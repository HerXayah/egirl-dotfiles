$Env:KOMOREBI_CONFIG_HOME = 'C:\Users\Sarah\.config\komorebi'
$Env:WHKD_CONFIG_HOME = 'C:\Users\Sarah\.config'
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete
Set-PSReadlineKeyHandler -Key UpArrow -Function HistorySearchBackward
Set-PSReadlineKeyHandler -Key DownArrow -Function HistorySearchForward
Import-Module "$($(Get-Item $(Get-Command scoop.ps1).Path).Directory.Parent.FullName)\modules\scoop-completion"
Import-Module -Name Terminal-Icons
New-Alias open ii
clear
Invoke-Expression (&starship init powershell)
Enable-PowerType
Set-PSReadLineOption -PredictionSource HistoryAndPlugin -PredictionViewStyle ListView
winfetch
