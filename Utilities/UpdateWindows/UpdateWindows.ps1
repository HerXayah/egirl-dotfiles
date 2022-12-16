# check if log file exists
# if it does not exist, create a new log file
if (!(Test-Path "C:\Logs\UpdateWindows.log")) {
    New-Item -ItemType File -Path "C:\Logs\UpdateWindows.log"
    Write-Output "Initializing Logfile..." | Out-File -FilePath "C:\Logs\UpdateWindows.log" -Append
}

# if logfile exists add a space line
if (Test-Path "C:\Logs\UpdateWindows.log") {
    Write-Output "------------------------" | Out-File -FilePath "C:\Logs\UpdateWindows.log" -Append
    Write-Output "Running..." | Out-File -FilePath "C:\Logs\UpdateWindows.log" -Append
}

Add-WUServiceManager -MicrosoftUpdate -Confirm:$false

# for each update in Get-WindowsUpdate create a toast notification and write output to log file
Get-WindowsUpdate -MicrosoftUpdate | ForEach-Object {
    New-BurntToastNotification -Text "Installing Update: $($_.Title)" -AppLogo "C:\Windows\BurntToast\logo.png"
    # add date and time to log
    Get-Date | Out-File -FilePath "C:\Logs\UpdateWindows.log" -Append
    Write-Output "Installing Update: $($_.Title)" | Out-File -FilePath "C:\Logs\UpdateWindows.log" -Append
    # unfortunatly we cant do this
    # Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Update $_.Identity.UpdateID
}

Write-Output "User: $env:UserName" | Out-File -FilePath "C:\Logs\UpdateWindows.log" -Append

# sucks that we have to do this
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll
New-BurntToastNotification -Text "Finished Installing Updates! Gomenasai ☆*: .｡. o(≧▽≦)o .｡.:*☆" -AppLogo "C:\Windows\BurntToast\logo.png"

    