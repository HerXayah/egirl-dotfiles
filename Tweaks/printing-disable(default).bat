:: DISABLE PRINTING ON GGOS (DEFAULT)
:: https://gitlab.com/ggos/support

@echo off
setlocal ENABLEDELAYEDEXPANSION

:: CHECK FOR ADMIN PRIVILEGES
dism >nul 2>&1 || ( echo This script must be Run as Administrator. && pause && exit /b 1 )

:: DISABLE PRINTING SERVICES
sc config Spooler start=disabled >nul 2>&1

echo Printing services have been disabled.
pause

exit /b 0
