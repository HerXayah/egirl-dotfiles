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

# check if BurntToast and PSWindowsUpdate are installed
# if not, install them
if (!(Get-Module -ListAvailable -Name BurntToast)) {
    Install-Module -Name BurntToast -Confirm:$false
    Write-Output "Installed BurntToast" | Out-File -FilePath "C:\Logs\UpdateWindows.log" -Append
}
if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Install-Module PSWindowsUpdate -Confirm:$false
    Write-Output "Installed PowershellUpdate" | Out-File -FilePath "C:\Logs\UpdateWindows.log" -Append
}

# add Microsoft Update Service
Add-WUServiceManager -MicrosoftUpdate -Confirm:$false

# for each update in Get-WindowsUpdate get the kb create a toast notification and write output to log file
foreach ($update in Get-WindowsUpdate -MicrosoftUpdate) {
    # if no updates are found, exit
    if ($update -eq $null) {
        Write-Output "No updates found." | Out-File -FilePath "C:\Logs\UpdateWindows.log" -Append\
        New-BurntToastNotification -Text "No updates found." -AppLogo "C:\Windows\BurntToast\logo.png"
        exit
    }
    else {
    New-BurntToastNotification -Text "Installing $update.KB" -AppLogo "C:\Windows\BurntToast\logo.png"
    Write-Output "Installing $update.KB" | Out-File -FilePath "C:\Logs\UpdateWindows.log" -Append
    Get-WindowsUpdate -Install -KBArticleID '$update.KB'
    }
}

Write-Output "User: $env:UserName" | Out-File -FilePath "C:\Logs\UpdateWindows.log" -Append

New-BurntToastNotification -Text "Finished Installing Updates! Gomenasai ☆*: .｡. o(≧▽≦)o .｡.:*☆" -AppLogo "C:\Windows\BurntToast\logo.png"
Write-Output "Done." | Out-File -FilePath "C:\Logs\UpdateWindows.log" -Append

    # powershell -noprofile -command "&{ start-process powershell -noprofile -windowstyle hidden -ArgumentList '-file C:\Windows\UpdateWindows.ps1 -windowstyle hidden' -verb RunAs}" -windowstyle hidden
