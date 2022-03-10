:: DISABLE LANMAN WORKSTATION ON GGOS
:: https://gitlab.com/ggos/support

@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
dism >nul 2>&1 || ( echo This script must be Run as Administrator. && pause && exit /b 1 )

:: DISABLE LANMAN WORKSTATION AND DEPENDENCIES
sc config rdbss start=disabled >nul 2>&1
sc config KSecPkg start=disabled >nul 2>&1
sc config LanmanWorkstation start=disabled >nul 2>&1

echo Lanman Workstation has been disabled. Please restart your computer.
pause

exit /b 0
