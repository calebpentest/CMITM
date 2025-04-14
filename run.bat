@echo off
setlocal EnableDelayedExpansion

echo [DEBUG] Starting run.bat...

REM === Check for admin privileges ===
echo [DEBUG] Checking admin privileges...
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] This script requires admin privileges. Please run as Administrator.
    echo [INFO] Right-click run.bat and select "Run as administrator".
    pause
    exit /b 1
)

REM === Check for Python 3 ===
echo [DEBUG] Checking Python installation...
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    where python3 >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Python is not installed or not in PATH.
        echo [INFO] Install Python from https://www.python.org/ and ensure it's added to PATH.
        pause
        exit /b 1
    )
    set PYTHON_CMD=python3
) else (
    set PYTHON_CMD=python
)
echo [DEBUG] Using Python command: %PYTHON_CMD%

REM === Check if cmitm.py exists ===
set SCRIPT=cmitm.py
echo [DEBUG] Checking for %SCRIPT%...
if not exist "%SCRIPT%" (
    echo [ERROR] %SCRIPT% not found in current directory: %CD%
    pause
    exit /b 1
)

echo.
echo [INFO] Detecting available interfaces...
echo Available interfaces:
%PYTHON_CMD% -c "import sys; from scapy.all import get_if_list; print('\n'.join(get_if_list()))" 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to list interfaces. Ensure Scapy is installed: %PYTHON_CMD% -m pip install scapy
    pause
    exit /b 1
)
echo.

REM === Get user input with retry option ===
:INPUT_TARGET
set "TARGET="
set /p TARGET="Enter Target IP Address: " || (
    echo [ERROR] Target IP cannot be empty.
    set /p RETRY="Try again? (y/n): "
    if /i "!RETRY!"=="y" goto :INPUT_TARGET
    pause
    exit /b 1
)
echo !TARGET!| findstr /R "^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$" >nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Invalid Target IP format. Use: x.x.x.x
    set /p RETRY="Try again? (y/n): "
    if /i "!RETRY!"=="y" goto :INPUT_TARGET
    pause
    exit /b 1
)

:INPUT_GATEWAY
set "GATEWAY="
set /p GATEWAY="Enter Gateway IP Address: " || (
    echo [ERROR] Gateway IP cannot be empty.
    set /p RETRY="Try again? (y/n): "
    if /i "!RETRY!"=="y" goto :INPUT_GATEWAY
    pause
    exit /b 1
)
echo !GATEWAY!| findstr /R "^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$" >nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Invalid Gateway IP format. Use: x.x.x.x
    set /p RETRY="Try again? (y/n): "
    if /i "!RETRY!"=="y" goto :INPUT_GATEWAY
    pause
    exit /b 1
)

:INPUT_INTERFACE
set "INTERFACE="
set /p INTERFACE="Enter EXACT Interface Name from above: " || (
    echo [ERROR] Interface Name cannot be empty.
    set /p RETRY="Try again? (y/n): "
    if /i "!RETRY!"=="y" goto :INPUT_INTERFACE
    pause
    exit /b 1
)

REM === Validate the selected interface ===
%PYTHON_CMD% -c "from scapy.all import get_if_list; print('\n'.join(get_if_list()))" > interfaces.txt 2>nul
echo [DEBUG] Validating interface: "!INTERFACE!"
findstr /X /C:"!INTERFACE!" interfaces.txt >nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Interface "!INTERFACE!" not found in available interfaces.
    echo [INFO] Available interfaces were:
    type interfaces.txt
    del interfaces.txt
    pause
    exit /b 1
)
del interfaces.txt

echo.
echo [INFO] Launching Stealth MITM...
echo [DEBUG] Command: %PYTHON_CMD% "%SCRIPT%" -t "!TARGET!" -g "!GATEWAY!" -i "!INTERFACE!"
echo.

REM === Execute MITM script ===
%PYTHON_CMD% "%SCRIPT%" -t "!TARGET!" -g "!GATEWAY!" -i "!INTERFACE!"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Script execution failed. Check cmitm.log for details.
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Script finished or stopped gracefully.
pause
