#Requires -RunAsAdministrator

Write-Host "Starting Installation..."

Start-Sleep -s 5

$folder = "C:\Logs"
$windowsFolder = "C:\Windows"
$currentFolder = Get-Location

copy $currentFolder\UpdateDefender.cmd $windowsFolder\UpdateDefender.cmd

Write-Host "Creating Task"

$DurationTimeSpanIndefinite = ([TimeSpan]::MaxValue) 

# every 5 hours for Indefinitely
$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Hours 5) `
    -RepetitionDuration (New-TimeSpan -Days (365 * 68)) `
    -ThrottleLimit 1 `
# Run task as system
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -RunLevel Highest
$action = New-ScheduledTaskAction -Execute 'C:\Windows\UpdateDefender.cmd' 
$settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -WakeToRun -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
Register-ScheduledTask UpdateDefender -InputObject $task



Enable-ScheduledTask -TaskName 'UpdateDefender'

Write-Host "Creating Folder"

New-Item -Path $folder -ItemType Directory

Write-Host "Installation Complete"