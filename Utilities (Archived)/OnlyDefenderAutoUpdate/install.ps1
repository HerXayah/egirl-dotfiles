#Requires -RunAsAdministrator

Write-Host "Starting Installation..."
Write-Host "Waiting three seconds to see if you cancel"
Start-Sleep -s 3

$folder = "C:\Logs"
$windowsFolder = "C:\Windows"
$currentFolder = Get-Location
$User= "NT AUTHORITY\SYSTEM"

#if files already exist, skip them
if(!(Test-Path $windowsFolder\UpdateDefender.cmd)){
    copy $currentFolder\UpdateDefender.cmd $windowsFolder\UpdateDefender.cmd
}
else {

    Write-Host "Update Defender already exists, skipping..."

}


#if task exists, skip
if (Get-ScheduledTask -TaskName "UpdateDefender" -ErrorAction SilentlyContinue) {
    Write-Host "Task already exists"
    } else {
    Write-Host "Creating Task"
Register-ScheduledTask -Xml (Get-Content 'UpdateDefender.xml' | out-string) -TaskName "UpdateDefender" -User $User
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
exit