@echo off

:Menu
cls
color 05
MODE CON COLS=55 LINES=14
echo.
echo               Redwan's Tscyncpolicy Bat
echo  ---------------------------------------------------
echo  1 = Default Tscyncpolicy
echo  2 = Tscyncpolicy Legacy (Better Input, worse FPS)
echo  3 = Tscyncpolicy Enhanced (Worse Input, better FPS)
echo  ---------------------------------------------------
set /p input=Option: 
if /i %input% == 1 goto Default
if /i %input% == 2 goto InputGood
if /i %input% == 3 goto FPSGood
) ELSE (
goto Menu

:Default
cls
bcdedit /deletevalue tscsyncpolicy
cls
echo Default Tscsyncpolicy Applied!
timeout 2 > nul
goto Menu

:InputGood
cls
bcdedit /set tscsyncpolicy legacy
cls
echo Tscsyncpolicy set to legacy!
timeout 2 > nul
goto Menu

:FPSGood
cls
bcdedit /set tscsyncpolicy enhanced
cls
echo Tscsyncpolicy set to enhanced!
timeout 2 > nul
goto Menu