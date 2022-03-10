@echo off

:: CSRSS Realtime Priority, lower input latency.
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v CpuPriorityClass /t Reg_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v IoPriority /t Reg_DWORD /d "3" /f

:: Disables Mouse, sticky & toggle keys.
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f

:: Disable Mouse acceleration.
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_DWORD /d "0" /f

:: Lower keyboard delay, increasing keyboard response time.
reg add "HKEY_CURRENT_USER\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_DWORD /d "0" /f

:: Data queue Size
reg add "HKLM\SYSTEM\CurrentControlSet\services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "20" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "20" /f

cls
echo Press any key to exit.
pause > nul