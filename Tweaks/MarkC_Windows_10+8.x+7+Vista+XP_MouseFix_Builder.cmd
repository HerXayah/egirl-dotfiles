: Run MarkC_Windows_8+7+Vista+XP_MouseFix_Builder.vbs when .VBS is not a runnable filetype
: Allow Run as administrator by Right-click this CMD, click 'Run as administrator' on menu.
@echo off
if not exist "%~dpn0.vbs" goto usage
start WScript.exe "%~dpn0.vbs"
goto :eof

:usage
echo To run this program:
echo.
echo  - Unzip both of %~n0.cmd and %~n0.vbs to the same folder,
echo.
echo  - Run %~n0.vbs or %~n0.cmd from that folder.
echo.
echo Note: You can usually run the VBS directly, but if that does not work, try running the CMD file instead.
echo.
pause