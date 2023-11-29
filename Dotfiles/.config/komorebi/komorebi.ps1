if (!(Get-Process whkd -ErrorAction SilentlyContinue))
{
    Start-Process whkd -WindowStyle hidden
}

. $PSScriptRootkomorebi.generated.ps1

# Send the ALT key whenever changing focus to force focus changes
komorebic alt-focus-hack enable
# Default to cloaking windows when switching workspaces
komorebic window-hiding-behaviour cloak
# Set cross-monitor move behaviour to insert instead of swap
komorebic cross-monitor-move-behaviour insert
# Enable hot reloading of changes to this file
komorebic watch-configuration enable

# Create named workspaces I-V on monitor 0
komorebic ensure-named-workspaces 0 I
komorebic ensure-named-workspaces 1 II
# You can do the same thing for secondary monitors too
# komorebic ensure-named-workspaces 1 A B C D E F

# Assign layouts to workspaces, possibits a pain in the ass to setuple values bsp, columns, rows, vertical-stack, horizontal-stack, ultrawide-vertical-stack
komorebic named-workspace-layout I Main
komorebic named-workspace-layout II Secondary

# Set the gaps around the edge of the screen for a workspace
komorebic named-workspace-padding I 6
# Set the gaps between the containers for a workspace
komorebic named-workspace-container-padding I 5

# You can assign specific apps to named workspaces
# komorebic named-workspace-rule exe Firefox.exe III

# Configure the invisible border dimensions
komorebic invisible-borders 7 0 14 7

# Uncomment the next lines if you want a visual border around the active window
komorebic active-window-border-colour 66 165 245 --window-kind single
# komorebic active-window-border-colour 256 165 66 --window-kind stack
# komorebic active-window-border-colour 255 51 153 --window-kind monocle
komorebic active-window-border enable

# Sarah Stuff
komorebic identify-tray-application exe CompactGUI.exe
komorebic 
komorebic named-workspace-rule exe Discord.exe II


komorebic complete-configuration