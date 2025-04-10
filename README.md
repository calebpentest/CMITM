---

# CMITM - Covert Man-In-The-Middle Tool

CMITM is a Python-based man-in-the-middle (MITM) tool designed for intercepting and manipulating HTTP, DNS, and HTTPS traffic within a local network. It supports ARP and NDP spoofing, SSL stripping, and packet injection, providing a stealthy approach for penetration testing.

---

## Features

- ARP Spoofing (IPv4)
- NDP Spoofing (IPv6)
- HTTP packet inspection & injection
- DNS query logging
- SSL Stripping (downgrade HTTPS to HTTP)
- IPv6 support
- Packet statistics logging

---

## Requirements

- Python 3.6+
- `scapy` library
- Administrator/root privileges (for packet injection and network interface access)

Install dependencies:

```bash
pip install -r requirements.txt
```
---
## Usage

```
git clone https://github.com/calebpentest/CMITM.git
cd CMITM
```

### Windows (With `run.bat`)

If you're using Windows, you can easily run the tool using the `run.bat` file provided. This will automatically execute the necessary Python commands.

Simply double-click the `run.bat` file or run it from the command line:

```bash
run.bat
```

The batch file will prompt you for the required arguments (`-t`, `-g`, and `-i`). Make sure to provide your target IP, gateway IP, and network interface when prompted.

### Basic Command (for other OS):

If you're not using Windows, or if you prefer to run the tool manually, use the following command:

```bash
python cmitm.py -t <TARGET_IP> -g <GATEWAY_IP> -i <INTERFACE>
```

### Optional Arguments:

```
-h, --help                Show help message and exit
-t, --target-ip           Target IP address (required)
-g, --gateway-ip          Gateway IP address (required)
-i, --interface           Network interface to use (required)
--spoof-interval          Spoofing interval in seconds (default: 1)
--queue-size              Max size of the packet queue (default: 1000)
--ipv6                    Enable IPv6 spoofing
--ssl-strip               Enable HTTPS to HTTP downgrade
```

### Example:

```bash
sudo python cmitm.py -t 192.168.1.10 -g 192.168.1.1 -i wlan0 --ssl-strip --ipv6
```

---

## File Structure

```
CMITM/
├── cmitm.py              # Main script
├── requirements.txt      # Python dependencies
├── cmitm.log             # Runtime log file
├── README.md             # You're here!
├── run.bat               # Windows batch file for easier execution
```

---

## Legal Notice

**For educational purposes only**: This tool is intended for **authorized penetration testing** on devices you own or have explicit permission to test. Unauthorized use is illegal and unethical. The author assumes **no liability** for misuse.

---
