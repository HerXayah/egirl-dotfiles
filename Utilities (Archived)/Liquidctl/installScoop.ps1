Write-Host "Installing..."
powershell.exe -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -Command "irm get.scoop.sh | iex" -Wait
powershell.exe -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -Command "scoop install sudo aria2 curl grep sed less touch python" -Wait
powershell.exe -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -Command "sudo scoop install 7zip git openssh --global" -Wait
Write-Host "Installed!"