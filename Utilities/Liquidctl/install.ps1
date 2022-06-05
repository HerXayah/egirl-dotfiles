#Requires -RunAsAdministrator

Write-Host "Starting Installation..."
Write-Host "Waiting three seconds to see if you cancel"
Start-Sleep -s 3

$windowsFolder = "C:\Windows"
$currentFolder = Get-Location

powershell.exe -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -Command "pip install liquidctl"

Write-Host "Installing Complete"
Start-Sleep -s 2
Clear-Host

Write-Host "Installing Liquidctl for Kraken Watercoolers"

#if files already exist, skip them
if(!(Test-Path $windowsFolder\AutoLiquidctl.cmd)){
    copy $currentFolder\AutoLiquidctl.cmd $windowsFolder\AutoLiquidctl.cmd
}

# run task on login
$trigger = New-ScheduledTaskTrigger -AtStartup
# Run task as user
$User= [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal = New-ScheduledTaskPrincipal -User $User -RunLevel Highest
$action = New-ScheduledTaskAction -Execute 'C:\Windows\AutoLiquidctl.cmd' 
$settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -WakeToRun -Hidden -ExecutionTimeLimit (New-TimeSpan -Seconds 20) -MultipleInstances IgnoreNew
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings


#if task exists, skip
if (Get-ScheduledTask -TaskName "Liquidctl" -ErrorAction SilentlyContinue) {
    Write-Host "Task already exists"
    } else {
    Write-Host "Creating Task"
Register-ScheduledTask Liquidctl -InputObject $task
Enable-ScheduledTask -TaskName 'Liquidctl'
}

Write-Host "Installation Complete"