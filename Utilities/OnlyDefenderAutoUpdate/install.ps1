#Requires -RunAsAdministrator

Write-Host "Starting Installation..."
Write-Host "Waiting three seconds to see if you cancel"
Start-Sleep -s 3

$folder = "C:\Logs"
$windowsFolder = "C:\Windows"
$currentFolder = Get-Location

#if files already exist, skip them
if(!(Test-Path $windowsFolder\UpdateDefender.cmd)){
    copy $currentFolder\UpdateDefender.cmd $windowsFolder\UpdateDefender.cmd
}

#$DurationTimeSpanIndefinite = ([TimeSpan]::MaxValue) 

# every 5 hours for Indefinitely
$trigger = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Hours 6) `
    -RepetitionDuration (New-TimeSpan -Days (365 * 68)) `
    -ThrottleLimit 1 `
# Run task as system
$User= "NT AUTHORITY\SYSTEM"
$principal = New-ScheduledTaskPrincipal -User $User -RunLevel Highest
$action = New-ScheduledTaskAction -Execute 'C:\Windows\UpdateDefender.cmd' 
$settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -WakeToRun -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings


#if task exists, skip
if (Get-ScheduledTask -TaskName "UpdateDefender" -ErrorAction SilentlyContinue) {
    Write-Host "Task already exists"
    } else {
    Write-Host "Creating Task"
Register-ScheduledTask UpdateDefender -InputObject $task
Enable-ScheduledTask -TaskName 'UpdateDefender'
}

Write-Host "Creating Folder"

# if folder already exist then skip
if (Test-Path $folder) {
    Write-Host "Folder already exist. Skippping..."
} else {
    New-Item $folder -ItemType Directory
}

Write-Host "Installation Complete"
Start-Sleep -s 2
Write-Host "You can change the Windows Version and set it to indefinite via TaskSchedule.msc"