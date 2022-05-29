@echo off
del C:\Logs\UpdateDefender.older.log
ren C:\Logs\UpdateDefender.log UpdateDefender.older.log
cls
echo -------------------------------------------------------- >> C:\Logs\UpdateDefender.log 
date /t >> C:\Logs\UpdateDefender.log
"C:\Program Files\Windows Defender\MpCmdRun.exe" -signatureUpdate >> C:\Logs\UpdateDefender.log
echo -------------------------------------------------------- >> C:\Logs\UpdateDefender.log 
cls
exit