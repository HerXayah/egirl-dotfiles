# ===== WINFETCH CONFIGURATION =====

 $image = "C:\Users\Sarah\.config\winfetch\winfetch.png"
 $noimage = $false

# Set the version of Windows to derive the logo from.
# $logo = "Windows 10"

# Make the logo blink
# $blink = $true

# Display all built-in info segments.
# $all = $true

# Add a custom info line
# function info_custom_time {
#     return @{
#         title = "Time"
#         content = (Get-Date)
#     }
# }

# Configure which disks are shown
# $ShowDisks = @("C:", "D:")
# Show all available disks
 $ShowDisks = @("*")

# Configure which package managers are shown
# disabling unused ones will improve speed
 #$ShowPkgs = @("winget", "scoop", "choco")
 $ShowPkgs = @("scoop")

# Use the following option to specify custom package managers.
# Create a function with that name as suffix, and which returns
# the number of packages. Two examples are shown here:
# $CustomPkgs = @("cargo", "just-install")
# function info_pkg_cargo {
#     return (cargo install --list | Where-Object {$_ -like "*:" }).Length
# }
# function info_pkg_just-install {
#     return (just-install list).Length
# }

# Configure how to show info for levels
# Default is for text only.
# 'bar' is for bar only.
# 'textbar' is for text + bar.
# 'bartext' is for bar + text.
 $cpustyle = 'textbar'
 $memorystyle = 'textbar'
 $diskstyle = 'bartext'
 $batterystyle = 'bartext'


# Remove the '#' from any of the lines in
# the following to **enable** their output.

@(
    "title"
    "dashes"
    "os"
    "computer"
    "kernel"
    "motherboard"
    # "custom_time"  # use custom info line
    "uptime"
     #"ps_pkgs"  # takes some time
    "pkgs"
    #"pwsh"
    "resolution"
    "terminal"
    # "theme"
    "cpu"
    "gpu"
    # "cpu_usage"  # takes some time
    "memory"
    "disk"
    # "battery"
    # "locale"
     #"weather"
    # "local_ip"
    # "public_ip"
    "blank"
    #"colorbar"
)
