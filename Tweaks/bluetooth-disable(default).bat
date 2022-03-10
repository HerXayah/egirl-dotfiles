:: DISABLE BLUETOOTH ON GGOS (DEFAULT)
:: https://gitlab.com/ggos/support

@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
dism >nul 2>&1 || ( echo This script must be Run as Administrator. && pause && exit /b 1 )
devcon /? >nul 2>&1 || ( echo This script requires devcon in the system path. && pause && exit /b 1 )

:: DISABLE BLUETOOTH DEVICES
devcon disable BTH* >nul 2>&1

:: DISABLE BLUETOOTH SERVICES
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
sc config BluetoothUserService start=disabled >nul 2>&1
sc config BTAGService start=disabled >nul 2>&1
sc config BthAvctpSvc start=disabled >nul 2>&1
sc config bthserv start=disabled >nul 2>&1

:: DISABLE REMAINING BLUETOOTH DEVICES
devcon disable =Bluetooth >nul 2>&1

echo Bluetooth services have been disabled. Please restart your computer.
pause

exit /b 0
