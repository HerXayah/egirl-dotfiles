#Requires -RunAsAdministrator

Write-Host "Starting Installation..."
Write-Host "Waiting three seconds to see if you cancel"
Start-Sleep -s 3

$windowsFolder = "C:\Windows"
$currentFolder = Get-Location
$User= "NT AUTHORITY\SYSTEM"

powershell.exe -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -Command "pip install liquidctl"

Write-Host "Installing Complete"
Start-Sleep -s 2
Clear-Host

Write-Host "Installing Liquidctl for Kraken Watercoolers"

#if files already exist, skip them
if(!(Test-Path $windowsFolder\AutoLiquidctl.cmd)){
    copy $currentFolder\AutoLiquidctl.cmd $windowsFolder\AutoLiquidctl.cmd
}

#if task exists, skip
if (Get-ScheduledTask -TaskName "Liquidctl" -ErrorAction SilentlyContinue) {
    Write-Host "Task already exists"
    } else {
    Write-Host "Creating Task"
Register-ScheduledTask -Xml (Get-Content 'Liquidctl.xml' | out-string) -TaskName "Liquidctl" -User $User
Enable-ScheduledTask -TaskName 'Liquidctl'
}

Write-Host "Installation Complete"