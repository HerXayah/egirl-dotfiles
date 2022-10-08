:: from https://github.com/yesdopepe/Yesos/releases
:: cleaned up version.

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /v "SchUseStrongCrypto" /t REG_DWORD /d "1" /f >nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NetFramework\v4.0.30319" /v "SchUseStrongCrypto" /t REG_DWORD /d "1" /f >nul
cls
echo applying network tweaks
PowerShell Disable-NetAdapterQos -Name "*"
PowerShell Disable-NetAdapterRsc -Name "*"
PowerShell Disable-NetAdapterChecksumOffload -Name "*"
PowerShell Disable-NetAdapterPowerManagement -Name "*"
PowerShell Disable-NetAdapterIPsecOffload -Name "*"
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NoNetCrawling" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "5840" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "5840" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DeadGWDetectDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "5840" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "5840" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "DeadGWDetectDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TcpAckFrequency /t REG_DWORD /d 0000001 /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TcpDelAckTicks /t REG_DWORD /d 0000000 /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v TCPNoDelay /t REG_DWORD /d 0000001 /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v InterfaceMetric /t REG_DWORD /d 0000055 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NetBT\Parameters" /v "NameSrvQueryTimeout" /t REG_DWORD /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "UseDelayedAcceptance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "maxcachettl" /t REG_DWORD /d "13824" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "maxnegativecachettl" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "86400" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxSOACacheEntryTtlLimit" /t REG_DWORD /d "300" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d "384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "Class" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7081E8E0-307B-48AB-8DB1-A9F1FC59D021}Machine\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "100" /f
netsh int isatap set state disable
netsh int ip set global taskoffload=disabled
netsh int tcp set global timestamps=disabled
netsh int tcp set heuristics disabled
netsh int tcp set global chimney=disabled
netsh int tcp set global ecncapability=disabled
netsh int tcp set global rss=enabled
netsh int tcp set global rsc=disabled
netsh int tcp set global dca=enabled
netsh int tcp set global netdma=enabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set security mpp=disabled
netsh int tcp set security profiles=disabled
netsh int ip set global icmpredirects=disabled
netsh int tcp set security mpp=disabled profiles=disabled
netsh int ip set global multicastforwarding=disabled
PowerShell Disable-NetAdapterLso -Name "*"
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue}"
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterLso -Name $adapter.Name -ErrorAction SilentlyContinue}"

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "AdditionalCriticalWorkerThreads" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "AdditionalDelayedWorkerThreads" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "SecondLevelDataCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "134217728" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
cls
echo applying file system tweaks
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DisableDeleteNotification" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsAllowExtendedCharacter8dot3Rename" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsBugcheckOnCorrupt" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableCompression" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableEncryption" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsEncryptPagingFile" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMemoryUsage" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "RefsDisableLastAccessUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "UdfsSoftwareDefectManagement" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "Win31FileSystem" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "FileNameCache" /t REG_DWORD /d "1024" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "PathCache" /t REG_DWORD /d "128" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "ContigFileAllocSize" /t REG_DWORD /d "1536" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "DisableDeleteNotification" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "NtfsAllowExtendedCharacter8dot3Rename" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "NtfsBugcheckOnCorrupt" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "NtfsDisableCompression" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "NtfsDisableEncryption" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "NtfsEncryptPagingFile" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "NtfsMemoryUsage" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "RefsDisableLastAccessUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "UdfsSoftwareDefectManagement" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "Win31FileSystem" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "FileNameCache" /t REG_DWORD /d "1024" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "PathCache" /t REG_DWORD /d "128" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "ContigFileAllocSize" /t REG_DWORD /d "1536" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /

cls
echo optimizing system task parameters
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Priority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "BackgroundPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "BackgroundPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Priority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Latency Sensitive" /t REG_SZ /d "True" /f
cls

Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Accessibility\Keyboard Response" /v "DelayBeforeAcceptance" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Accessibility\Keyboard Response" /v "AutoRepeatRate" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Accessibility\Keyboard Response" /v "AutoRepeatDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKU\.DEFAULT\Control Panel\Accessibility\Keyboard Response" /v "KeyboardDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseDelay" /t REG_SZ /d "0" /f

Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "1" /f

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ13Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f

cls
echo disabling coalescing timer interval
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
cls
echo disabling power throttling and hiber boot
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
cls
echo disabling fso
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowSharedUserAppData" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
cls
echo disabling accessibility
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f
cls
echo disabling superfetch
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
cls
echo disabling settings sync
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
cls
echo setting IRQ priority
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ13Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
cls
echo Take Ownership Dialoge
Reg.exe add "HKCR\*\shell\TakeOwnership" /ve /t REG_SZ /d "Take Ownership" /f
Reg.exe delete "HKCR\*\shell\TakeOwnership" /v "Extended" /f
Reg.exe add "HKCR\*\shell\TakeOwnership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\*\shell\TakeOwnership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\*\shell\TakeOwnership" /v "NeverDefault" /t REG_SZ /d "" /f
Reg.exe add "HKCR\*\shell\TakeOwnership\command" /ve /t REG_SZ /d "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%%1\\\" && icacls \\\"%%1\\\" /grant *S-1-3-4:F /t /c /l' -Verb runAs\"" /f
Reg.exe add "HKCR\Directory\shell\TakeOwnership" /ve /t REG_SZ /d "Take Ownership" /f
Reg.exe add "HKCR\Directory\shell\TakeOwnership" /v "AppliesTo" /t REG_SZ /d "NOT (System.ItemPathDisplay:=\"C:\Users\" OR System.ItemPathDisplay:=\"C:\ProgramData\" OR System.ItemPathDisplay:=\"C:\Windows\" OR System.ItemPathDisplay:=\"C:\Windows\System32\" OR System.ItemPathDisplay:=\"C:\Program Files\" OR System.ItemPathDisplay:=\"C:\Program Files (x86)\")" /f
Reg.exe delete "HKCR\Directory\shell\TakeOwnership" /v "Extended" /f
Reg.exe add "HKCR\Directory\shell\TakeOwnership" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\shell\TakeOwnership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Directory\shell\TakeOwnership" /v "Position" /t REG_SZ /d "middle" /f
Reg.exe add "HKCR\Directory\shell\TakeOwnership\command" /ve /t REG_SZ /d "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%%1\\\" /r /d y && icacls \\\"%%1\\\" /grant *S-1-3-4:F /t /c /l /q' -Verb runAs\"" /f
Reg.exe add "HKCR\Directory\shell\TakeOwnership\command" /v "IsolatedCommand" /t REG_SZ /d "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%%1\\\" /r /d y && icacls \\\"%%1\\\" /grant *S-1-3-4:F /t /c /l /q' -Verb runAs\"" /f
Reg.exe add "HKCR\Drive\shell\runas" /ve /t REG_SZ /d "Take Ownership" /f
Reg.exe delete "HKCR\Drive\shell\runas" /v "Extended" /f
Reg.exe add "HKCR\Drive\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Drive\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Reg.exe add "HKCR\Drive\shell\runas" /v "Position" /t REG_SZ /d "middle" /f
Reg.exe add "HKCR\Drive\shell\runas" /v "AppliesTo" /t REG_SZ /d "NOT (System.ItemPathDisplay:=\"C:\\\")" /f
Reg.exe add "HKCR\Drive\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\\\" /r /d y && icacls \"%%1\\\" /grant *S-1-3-4:F /t /c" /f
Reg.exe add "HKCR\Drive\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\\\" /r /d y && icacls \"%%1\\\" /grant *S-1-3-4:F /t /c" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "MMTaskbarMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "MMTaskbarGlomLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSizeMove" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisablePreviewDesktop" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSmallIcons" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarGlomLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontUsePowerShellOnWinX" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi" /v "DisableTLCorner" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell\EdgeUi" /v "DisableTRCorner" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d "1" /f
echo Privacy
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "RunStartupScriptSync" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisableThumbnailCache" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "CompositionPolicy" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowCrossDeviceClipboard" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" /v "EnableEventTranscript" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
Reg.exe delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightWindowsWelcomeExperience" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnActionCenter" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
Reg.exe delete "HKCU\System\GameConfigStore\Children" /f
Reg.exe delete "HKCU\System\GameConfigStore\Parents" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableAutocorrection" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableSpellchecking" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableTextPrediction" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnablePredictionSpaceInsertion" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableDoubleTapSpace" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableInkingWithTouch" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceAppSuggestionsEnabled" /t REG_DWORD /d "0" /f
cls
echo Windows Update
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
cls
echo Misc
Reg.exe add "HKLM\SOFTWARE\Microsoft\OneDrive" /v "PreventNetworkTrafficPreUserSignIn" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "ActiveWndTrkTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "PaintDesktopVersion" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "2000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "forceguest" /t REG_DWORD /d "0" /f
Reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
Reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f
cls
echo Search
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HidePeopleBar" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoPinningStoreToTaskbar" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f
cls
echo "If you wannanot frick ur system maybe *for me it works atleast*, continue AFTER this long block of text"
timeout /t 10 


echo disabling diagnostics and telemetry
sc stop dmwappushservice
net stop dmwappushservice 
sc config dmwappushservice start= disabled
net stop diagnosticshub.standardcollector.service > NUL 2>&1
sc config diagnosticshub.standardcollector.service start= disabled
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "DiagnosticErrorText" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticErrorText" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticLinkText" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NtfsLog" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NtfsLog" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\FaceRecoTel" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\FaceRecoTel" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CShellCircular" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CShellCircular" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\HolographicDevice" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\HolographicDevice" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsClient" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsClient" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Setup" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Setup" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NetCore" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NetCore" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WFP-IPsec Trace" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WFP-IPsec Trace" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-AssignedAccess-Trace" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-AssignedAccess-Trace" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatformTel" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatformTel" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WinPhoneCritical" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WinPhoneCritical" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsProxy" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsProxy" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TCPIPLOGGER" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TCPIPLOGGER" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NBSMBLOGGER" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NBSMBLOGGER" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Cellcore" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Cellcore" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Mellanox-Kernel" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Mellanox-Kernel" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\MellanoxSoftware\Microsoft\Windows NT\CurrentVersion\SPP\Clients-Kernel" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\PEAuthLog" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\PEAuthLog" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RdrLog" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RdrLog" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SocketHeciServer" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SocketHeciServer" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TileStore" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TileStore" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DataMarket" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DataMarket" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSessionRepro" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSessionRepro" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TPMProvisioningService" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TPMProvisioningService" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RadioMgr" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RadioMgr" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\FaceUnlock" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\FaceUnlock" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" /v "Status" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "DwmInputUsesIoCompletionPort" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "AnimationAttributionEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "AnimationAttributionHashingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "EnableDesktopOverlays" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "DisableProjectedShadows" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "DisableHologramCompositor" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "OneCoreNoBootDWM" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm\ExtendedComposition" /v "ExclusiveModeFramerateAveragingPeriodMs" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm\ExtendedComposition" /v "ExclusiveModeFramerateThresholdPercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DWMWA_TRANSITIONS_FORCEDISABLED" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowFlip3d" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowColorizationColorChanges" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowFlip3d" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowColorizationColorChanges" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "Composition" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "EnableWindowColorization" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "ColorPrevalence" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\DirectShowFilterGraph" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\DirectShowPluginControl" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Els_Hyphenation/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\EndpointMapper" /v "OwningPublisher" /t REG_SZ /d "{d8975f88-7ddb-4ed0-91bf-3adf48c48e0c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\EndpointMapper" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\EndpointMapper" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\EndpointMapper" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\EndpointMapper" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\FirstUXPerf-Analytic" /v "OwningPublisher" /t REG_SZ /d "{fbef8096-2ca3-4082-acde-dcfb47e96b72}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\FirstUXPerf-Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\FirstUXPerf-Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\FirstUXPerf-Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\FirstUXPerf-Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\ForwardedEvents" /v "OwningPublisher" /t REG_SZ /d "{b977cf02-76f6-df84-cc1a-6a4b232322b6}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\ForwardedEvents" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\ForwardedEvents" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\ForwardedEvents" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\ForwardedEvents" /v "MaxSize" /t REG_DWORD /d "20971520" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\ForwardedEvents" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\ForwardedEvents" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\IHM_DebugChannel" /v "OwningPublisher" /t REG_SZ /d "{e978f84e-582d-4167-977e-32af52706888}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\IHM_DebugChannel" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\IHM_DebugChannel" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\IHM_DebugChannel" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\IHM_DebugChannel" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS-GPIO/Analytic" /v "OwningPublisher" /t REG_SZ /d "{d386cc7a-620a-41c1-abf5-55018c6c699a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS-GPIO/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS-GPIO/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS-GPIO/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS-GPIO/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS-I2C/Analytic" /v "OwningPublisher" /t REG_SZ /d "{D4AEAC44-AD44-456E-9C90-33F8CDCED6AF}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS-I2C/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS-I2C/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS-I2C/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS-I2C/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-GPIO2/Debug" /v "OwningPublisher" /t REG_SZ /d "{63848cff-3ec7-4ddf-8072-5f95e8c8eb98}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-GPIO2/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-GPIO2/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-GPIO2/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-GPIO2/Debug" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-GPIO2/Performance" /v "OwningPublisher" /t REG_SZ /d "{63848cff-3ec7-4ddf-8072-5f95e8c8eb98}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-GPIO2/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-GPIO2/Performance" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-GPIO2/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-GPIO2/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-I2C/Debug" /v "OwningPublisher" /t REG_SZ /d "{C2F86198-03CA-4771-8D4C-CE6E15CBCA56}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-I2C/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-I2C/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-I2C/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-I2C/Debug" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-I2C/Performance" /v "OwningPublisher" /t REG_SZ /d "{C2F86198-03CA-4771-8D4C-CE6E15CBCA56}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-I2C/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-I2C/Performance" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-I2C/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Intel-iaLPSS2-I2C/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MedaFoundationVideoProc" /v "OwningPublisher" /t REG_SZ /d "{a4112d1a-6dfa-476e-bb75-e350d24934e1}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MedaFoundationVideoProc" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MedaFoundationVideoProc" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MedaFoundationVideoProc" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MedaFoundationVideoProc" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MedaFoundationVideoProcD3D" /v "OwningPublisher" /t REG_SZ /d "{a4112d1a-6dfa-476e-bb75-e350d24934e1}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MedaFoundationVideoProcD3D" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MedaFoundationVideoProcD3D" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MedaFoundationVideoProcD3D" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MedaFoundationVideoProcD3D" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationAsyncWrapper" /v "OwningPublisher" /t REG_SZ /d "{a7364e1a-894f-4b3d-a930-2ed9c8c4c811}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationAsyncWrapper" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationAsyncWrapper" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationAsyncWrapper" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationAsyncWrapper" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationContentProtection" /v "OwningPublisher" /t REG_SZ /d "{a7364e1a-894f-4b3d-a930-2ed9c8c4c811}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationContentProtection" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationContentProtection" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationContentProtection" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationContentProtection" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationDeviceProxy" /v "OwningPublisher" /t REG_SZ /d "{bc97b970-d001-482f-8745-b8d7d5759f99}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationDeviceProxy" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationDeviceProxy" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationDeviceProxy" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationDeviceProxy" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationDS" /v "OwningPublisher" /t REG_SZ /d "{a7364e1a-894f-4b3d-a930-2ed9c8c4c811}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationDS" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationDS" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationDS" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationDS" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationMediaEngine" /v "OwningPublisher" /t REG_SZ /d "{8f2048e0-f260-4f57-a8d1-932376291682}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationMediaEngine" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationMediaEngine" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationMediaEngine" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationMediaEngine" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationMP4" /v "OwningPublisher" /t REG_SZ /d "{a7364e1a-894f-4b3d-a930-2ed9c8c4c811}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationMP4" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationMP4" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationMP4" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationMP4" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPerformance" /v "OwningPublisher" /t REG_SZ /d "{f404b94e-27e0-4384-bfe8-1d8d390b0aa3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPerformance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPerformance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPerformance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPerformance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPerformanceCore" /v "OwningPublisher" /t REG_SZ /d "{b20e65ac-c905-4014-8f78-1b6a508142eb}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPerformanceCore" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPerformanceCore" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPerformanceCore" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPerformanceCore" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPipeline" /v "OwningPublisher" /t REG_SZ /d "{a7364e1a-894f-4b3d-a930-2ed9c8c4c811}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPipeline" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPipeline" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPipeline" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPipeline" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPlatform" /v "OwningPublisher" /t REG_SZ /d "{bc97b970-d001-482f-8745-b8d7d5759f99}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPlatform" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPlatform" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPlatform" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationPlatform" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationSrcPrefetch" /v "OwningPublisher" /t REG_SZ /d "{a7364e1a-894f-4b3d-a930-2ed9c8c4c811}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationSrcPrefetch" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationSrcPrefetch" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationSrcPrefetch" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MediaFoundationSrcPrefetch" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MF_MediaFoundationDeviceMFT" /v "OwningPublisher" /t REG_SZ /d "{a7364e1a-894f-4b3d-a930-2ed9c8c4c811}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MF_MediaFoundationDeviceMFT" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MF_MediaFoundationDeviceMFT" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MF_MediaFoundationDeviceMFT" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MF_MediaFoundationDeviceMFT" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MF_MediaFoundationDeviceProxy" /v "OwningPublisher" /t REG_SZ /d "{a7364e1a-894f-4b3d-a930-2ed9c8c4c811}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MF_MediaFoundationDeviceProxy" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MF_MediaFoundationDeviceProxy" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MF_MediaFoundationDeviceProxy" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MF_MediaFoundationDeviceProxy" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MF_MediaFoundationFrameServer" /v "OwningPublisher" /t REG_SZ /d "{9e22a3ed-7b32-4b99-b6c2-21dd6ace01e1}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MF_MediaFoundationFrameServer" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MF_MediaFoundationFrameServer" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MF_MediaFoundationFrameServer" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\MF_MediaFoundationFrameServer" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client-Streamingux/Debug" /v "OwningPublisher" /t REG_SZ /d "{28cb46c7-4003-4e50-8bd9-442086762d12}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client-Streamingux/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client-Streamingux/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client-Streamingux/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client-Streamingux/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client/Admin" /v "OwningPublisher" /t REG_SZ /d "{e4f68870-5ae8-4e5b-9ce7-ca9ed75b0245}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client/Admin" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client/Admin" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client/Admin" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client/Admin" /v "MaxSize" /t REG_DWORD /d "10485760" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client/Admin" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client/Admin" /v "Retention" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client/Admin" /v "Type" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client/Debug" /v "OwningPublisher" /t REG_SZ /d "{9cc69d1c-7917-4acd-8066-6bf8b63e551b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-Client/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-SharedPerformance/Analytic" /v "OwningPublisher" /t REG_SZ /d "{fb4a19ee-eb5a-47a4-bc52-e71aac6d0859}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-SharedPerformance/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-SharedPerformance/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-SharedPerformance/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-AppV-SharedPerformance/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Admin" /v "OwningPublisher" /t REG_SZ /d "{b6cc0d55-9ecc-49a8-b929-2b9022426f2a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Admin" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Admin" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Admin" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Admin" /v "Type" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Debug" /v "OwningPublisher" /t REG_SZ /d "{b6cc0d55-9ecc-49a8-b929-2b9022426f2a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{b6cc0d55-9ecc-49a8-b929-2b9022426f2a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Client-Licensing-Platform/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-IE/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{9e3b3947-ca5d-4614-91a2-7b624e0e7244}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-IE/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-IE/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-IE/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-IE/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-IEFRAME/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{5c8bb950-959e-4309-8908-67961a1205d5}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-IEFRAME/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-IEFRAME/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-IEFRAME/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-IEFRAME/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-JSDumpHeap/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{7f8e35ca-68e8-41b9-86fe-d6adc5b327e7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-JSDumpHeap/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-JSDumpHeap/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-JSDumpHeap/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-JSDumpHeap/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-OneCore-Setup/Analytic" /v "OwningPublisher" /t REG_SZ /d "{41862974-da3b-4f0b-97d5-bb29fbb9b71e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-OneCore-Setup/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-OneCore-Setup/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-OneCore-Setup/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-OneCore-Setup/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-PerfTrack-IEFRAME/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{b2a40f1f-a05a-4dfd-886a-4c4f18c4334c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-PerfTrack-IEFRAME/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-PerfTrack-IEFRAME/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-PerfTrack-IEFRAME/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-PerfTrack-IEFRAME/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-PerfTrack-MSHTML/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{ffdb9886-80f3-4540-aa8b-b85192217ddf}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-PerfTrack-MSHTML/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-PerfTrack-MSHTML/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-PerfTrack-MSHTML/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-PerfTrack-MSHTML/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-Admin/Debug" /v "OwningPublisher" /t REG_SZ /d "{61bc445e-7a8d-420e-ab36-9c7143881b98}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-Admin/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-Admin/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-Admin/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-Admin/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-Agent Driver/Debug" /v "OwningPublisher" /t REG_SZ /d "{de29cf61-5ee6-43ff-9aac-959c4e13cc6c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-Agent Driver/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-Agent Driver/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-Agent Driver/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-Agent Driver/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-App Agent/Analytic" /v "OwningPublisher" /t REG_SZ /d "{1ed6976a-4171-4764-b415-7ea08bc46c51}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-App Agent/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-App Agent/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-App Agent/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-App Agent/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-App Agent/Debug" /v "OwningPublisher" /t REG_SZ /d "{1ed6976a-4171-4764-b415-7ea08bc46c51}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-App Agent/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-App Agent/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-App Agent/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-App Agent/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-SQM Uploader/Analytic" /v "OwningPublisher" /t REG_SZ /d "{57003e21-269b-4bdc-8434-b3bf8d57d2d5}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-SQM Uploader/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-SQM Uploader/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-SQM Uploader/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-SQM Uploader/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-SQM Uploader/Debug" /v "OwningPublisher" /t REG_SZ /d "{57003e21-269b-4bdc-8434-b3bf8d57d2d5}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-SQM Uploader/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-SQM Uploader/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-SQM Uploader/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-SQM Uploader/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-SQM Uploader/Operational" /v "OwningPublisher" /t REG_SZ /d "{57003e21-269b-4bdc-8434-b3bf8d57d2d5}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-SQM Uploader/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-SQM Uploader/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-SQM Uploader/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-User Experience Virtualization-SQM Uploader/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AAD/Analytic" /v "OwningPublisher" /t REG_SZ /d "{4de9bc9c-b27a-43c9-8994-0915f1a5e24f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AAD/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AAD/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AAD/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AAD/Analytic" /v "Retention" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AAD/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ActionQueue/Analytic" /v "OwningPublisher" /t REG_SZ /d "{0dd4d48e-2bbf-452f-a7ec-ba3dba8407ae}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ActionQueue/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ActionQueue/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ActionQueue/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ActionQueue/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ADSI/Debug" /v "OwningPublisher" /t REG_SZ /d "{7288c9f8-d63c-4932-a345-89d6b060174d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ADSI/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ADSI/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ADSI/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ADSI/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AllJoyn/Debug" /v "OwningPublisher" /t REG_SZ /d "{2ed299d2-2f6b-411d-8d15-f4cc6fde0c70}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AllJoyn/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AllJoyn/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AllJoyn/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AllJoyn/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/ApplicationTracing" /v "OwningPublisher" /t REG_SZ /d "{98e0765d-8c42-44a3-a57b-760d7f93225a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/ApplicationTracing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/ApplicationTracing" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/ApplicationTracing" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/ApplicationTracing" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{98e0765d-8c42-44a3-a57b-760d7f93225a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/Internal" /v "OwningPublisher" /t REG_SZ /d "{98e0765d-8c42-44a3-a57b-760d7f93225a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/Internal" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/Internal" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/Internal" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppHost/Internal" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ApplicabilityEngine/Analytic" /v "OwningPublisher" /t REG_SZ /d "{10a208dd-a372-421c-9d99-4fad6db68b62}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ApplicabilityEngine/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ApplicabilityEngine/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ApplicabilityEngine/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ApplicabilityEngine/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application Server-Applications/Analytic" /v "OwningPublisher" /t REG_SZ /d "{c651f5f6-1c0d-492e-8ae1-b4efd7c9d503}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application Server-Applications/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application Server-Applications/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application Server-Applications/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application Server-Applications/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application Server-Applications/Analytic" /v "BufferSize" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application Server-Applications/Debug" /v "OwningPublisher" /t REG_SZ /d "{c651f5f6-1c0d-492e-8ae1-b4efd7c9d503}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application Server-Applications/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application Server-Applications/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application Server-Applications/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application Server-Applications/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Compatibility-Infrastructure-Debug" /v "OwningPublisher" /t REG_SZ /d "{eef54e71-0661-422d-9a98-82fd4940b820}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Compatibility-Infrastructure-Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Compatibility-Infrastructure-Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Compatibility-Infrastructure-Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Compatibility-Infrastructure-Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Analytic" /v "OwningPublisher" /t REG_SZ /d "{eef54e71-0661-422d-9a98-82fd4940b820}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Trace" /v "OwningPublisher" /t REG_SZ /d "{eef54e71-0661-422d-9a98-82fd4940b820}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Trace" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Trace" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Trace" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Trace" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-Runtime/Analytic" /v "OwningPublisher" /t REG_SZ /d "{f1ef270a-0d32-4352-ba52-dbab41e1d859}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-Runtime/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-Runtime/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-Runtime/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-Runtime/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-Runtime/Debug" /v "OwningPublisher" /t REG_SZ /d "{f1ef270a-0d32-4352-ba52-dbab41e1d859}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-Runtime/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-Runtime/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-Runtime/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-Runtime/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-Runtime/Diagnostics" /v "OwningPublisher" /t REG_SZ /d "{f1ef270a-0d32-4352-ba52-dbab41e1d859}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-Runtime/Diagnostics" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-Runtime/Diagnostics" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-Runtime/Diagnostics" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-Runtime/Diagnostics" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-State/Debug" /v "OwningPublisher" /t REG_SZ /d "{bff15e13-81bf-45ee-8b16-7cfead00da86}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-State/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-State/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-State/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-State/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-State/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{bff15e13-81bf-45ee-8b16-7cfead00da86}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-State/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-State/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-State/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppModel-State/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppReadiness/Debug" /v "OwningPublisher" /t REG_SZ /d "{f0be35f8-237b-4814-86b5-ade51192e503}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppReadiness/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppReadiness/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppReadiness/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppReadiness/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppXDeployment/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{8127f6d4-59f9-4abf-8952-3e3a02073d5f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppXDeployment/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppXDeployment/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppXDeployment/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppXDeployment/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppXDeploymentServer/Debug" /v "OwningPublisher" /t REG_SZ /d "{3f471139-acb7-4a01-b7a7-ff5da4ba2d43}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppXDeploymentServer/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppXDeploymentServer/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppXDeploymentServer/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppXDeploymentServer/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppXDeploymentServer/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{3f471139-acb7-4a01-b7a7-ff5da4ba2d43}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppXDeploymentServer/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppXDeploymentServer/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppXDeploymentServer/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppXDeploymentServer/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppxPackaging/Debug" /v "OwningPublisher" /t REG_SZ /d "{ba723d81-0d0c-4f1e-80c8-54740f508ddf}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppxPackaging/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppxPackaging/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppxPackaging/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppxPackaging/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppxPackaging/Performance" /v "OwningPublisher" /t REG_SZ /d "{ba723d81-0d0c-4f1e-80c8-54740f508ddf}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppxPackaging/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppxPackaging/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppxPackaging/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AppxPackaging/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ASN1/Operational" /v "OwningPublisher" /t REG_SZ /d "{d92ef8ac-99dd-4ab8-b91d-c6eba85f3755}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ASN1/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ASN1/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ASN1/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x7BA)(A0x2AU)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ASN1/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AssignedAccess/Operational" /v "OwningPublisher" /t REG_SZ /d "{8530db6e-51c0-43d6-9d02-a8c2088526cd}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AssignedAccess/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AssignedAccess/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AssignedAccess/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AssignedAccess/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AssignedAccessBroker/Operational" /v "OwningPublisher" /t REG_SZ /d "{f2311b48-32be-4902-a22a-7240371dbb2c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AssignedAccessBroker/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AssignedAccessBroker/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AssignedAccessBroker/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AssignedAccessBroker/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AsynchronousCausality/Causality" /v "OwningPublisher" /t REG_SZ /d "{19a4c69a-28eb-4d4b-8d94-5f19055a1b5c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AsynchronousCausality/Causality" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AsynchronousCausality/Causality" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AsynchronousCausality/Causality" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AsynchronousCausality/Causality" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ATAPort/General" /v "OwningPublisher" /t REG_SZ /d "{cb587ad1-cc35-4ef1-ad93-36cc82a2d319}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ATAPort/General" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ATAPort/General" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ATAPort/General" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ATAPort/General" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ATAPort/SATA-LPM" /v "OwningPublisher" /t REG_SZ /d "{cb587ad1-cc35-4ef1-ad93-36cc82a2d319}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ATAPort/SATA-LPM" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ATAPort/SATA-LPM" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ATAPort/SATA-LPM" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ATAPort/SATA-LPM" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/GlitchDetection" /v "OwningPublisher" /t REG_SZ /d "{ae4bd3be-f36f-45b6-8d21-bdd6fb832853}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/GlitchDetection" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/GlitchDetection" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/GlitchDetection" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/GlitchDetection" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/Informational" /v "OwningPublisher" /t REG_SZ /d "{ae4bd3be-f36f-45b6-8d21-bdd6fb832853}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/Informational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/Informational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/Informational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/Informational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/Performance" /v "OwningPublisher" /t REG_SZ /d "{ae4bd3be-f36f-45b6-8d21-bdd6fb832853}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/Performance" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audio/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audit/Analytic" /v "OwningPublisher" /t REG_SZ /d "{75ebc33e-0936-4a55-9d26-5f298f3180bf}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audit/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audit/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audit/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Audit/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" /v "OwningPublisher" /t REG_SZ /d "{dddc1d91-51a1-4a8d-95b5-350c4ee3d809}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/ProtectedUser-Client" /v "OwningPublisher" /t REG_SZ /d "{dddc1d91-51a1-4a8d-95b5-350c4ee3d809}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/ProtectedUser-Client" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/ProtectedUser-Client" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/ProtectedUser-Client" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/ProtectedUser-Client" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" /v "OwningPublisher" /t REG_SZ /d "{dddc1d91-51a1-4a8d-95b5-350c4ee3d809}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" /v "OwningPublisher" /t REG_SZ /d "{dddc1d91-51a1-4a8d-95b5-350c4ee3d809}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AxInstallService/Log" /v "OwningPublisher" /t REG_SZ /d "{dab3b18c-3c0f-43e8-80b1-e44bc0dad901}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AxInstallService/Log" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AxInstallService/Log" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AxInstallService/Log" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-AxInstallService/Log" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BackgroundTaskInfrastructure/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{e6835967-e0d2-41fb-bcec-58387404e25a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BackgroundTaskInfrastructure/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BackgroundTaskInfrastructure/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BackgroundTaskInfrastructure/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BackgroundTaskInfrastructure/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Base-Filtering-Engine-Connections/Operational" /v "OwningPublisher" /t REG_SZ /d "{121d3da8-baf1-4dcb-929f-2d4c9a47f7ab}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Base-Filtering-Engine-Connections/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Base-Filtering-Engine-Connections/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Base-Filtering-Engine-Connections/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Base-Filtering-Engine-Connections/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Base-Filtering-Engine-Resource-Flows/Operational" /v "OwningPublisher" /t REG_SZ /d "{92765247-03a9-4ae3-a575-b42264616e78}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Base-Filtering-Engine-Resource-Flows/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Base-Filtering-Engine-Resource-Flows/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Base-Filtering-Engine-Resource-Flows/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Base-Filtering-Engine-Resource-Flows/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Battery/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{59819d0a-adaf-46b2-8d7c-990bc39c7c15}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Battery/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Battery/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Battery/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Battery/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker-Driver-Performance/Operational" /v "OwningPublisher" /t REG_SZ /d "{1de130e1-c026-4cbf-ba0f-ab608e40aeea}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker-Driver-Performance/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker-Driver-Performance/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker-Driver-Performance/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker-Driver-Performance/Operational" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker/BitLocker Operational" /v "OwningPublisher" /t REG_SZ /d "{5d674230-ca9f-11da-a94d-0800200c9a66}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker/BitLocker Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker/BitLocker Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker/BitLocker Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker/BitLocker Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker/Tracing" /v "OwningPublisher" /t REG_SZ /d "{5d674230-ca9f-11da-a94d-0800200c9a66}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker/Tracing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker/Tracing" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker/Tracing" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker/Tracing" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BitLocker/Tracing" /v "ClockType" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bits-Client/Analytic" /v "OwningPublisher" /t REG_SZ /d "{ef1cc15b-46c1-414e-bb95-e76b077bd51e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bits-Client/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bits-Client/Analytic" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bits-Client/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bits-Client/Analytic" /v "Retention" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bits-Client/Analytic" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-BthLEPrepairing/Operational" /v "OwningPublisher" /t REG_SZ /d "{4af188ac-e9c4-4c11-b07b-1fabc07dfeb2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-BthLEPrepairing/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-BthLEPrepairing/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-BthLEPrepairing/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-BthLEPrepairing/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-Bthmini/Operational" /v "OwningPublisher" /t REG_SZ /d "{db25b328-a6f6-444f-9d97-a50e20217d16}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-Bthmini/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-Bthmini/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-Bthmini/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-Bthmini/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-MTPEnum/Operational" /v "OwningPublisher" /t REG_SZ /d "{04268430-d489-424d-b914-0cff741d6684}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-MTPEnum/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-MTPEnum/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-MTPEnum/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-MTPEnum/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-Policy/Operational" /v "OwningPublisher" /t REG_SZ /d "{0602ECEF-6381-4BC0-AEDA-EB9BB919B276}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-Policy/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-Policy/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-Policy/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Bluetooth-Policy/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BranchCacheClientEventProvider/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{e837619c-a2a8-4689-833f-47b48ebd2442}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BranchCacheClientEventProvider/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BranchCacheClientEventProvider/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BranchCacheClientEventProvider/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BranchCacheClientEventProvider/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BranchCacheEventProvider/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{dd85457f-4e2d-44a5-a7a7-6253362e34dc}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BranchCacheEventProvider/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BranchCacheEventProvider/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BranchCacheEventProvider/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BranchCacheEventProvider/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BranchCacheMonitoring/Analytic" /v "OwningPublisher" /t REG_SZ /d "{a2f55524-8ebc-45fd-88e4-a1b39f169e08}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BranchCacheMonitoring/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BranchCacheMonitoring/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BranchCacheMonitoring/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BranchCacheMonitoring/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHPORT/HCI" /v "OwningPublisher" /t REG_SZ /d "{8a1f9517-3a8c-4a9e-a018-4f17a200f277}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHPORT/HCI" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHPORT/HCI" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHPORT/HCI" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHPORT/HCI" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHPORT/L2CAP" /v "OwningPublisher" /t REG_SZ /d "{8a1f9517-3a8c-4a9e-a018-4f17a200f277}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHPORT/L2CAP" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHPORT/L2CAP" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHPORT/L2CAP" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHPORT/L2CAP" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHUSB/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{33693e1d-246a-471b-83be-3e75f47a832d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHUSB/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHUSB/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHUSB/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHUSB/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHUSB/Performance" /v "OwningPublisher" /t REG_SZ /d "{33693e1d-246a-471b-83be-3e75f47a832d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHUSB/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHUSB/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHUSB/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-BTH-BTHUSB/Performance" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Catalog Database Debug" /v "OwningPublisher" /t REG_SZ /d "{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Catalog Database Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Catalog Database Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Catalog Database Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Catalog Database Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational" /v "OwningPublisher" /t REG_SZ /d "{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x7BA)(A0x2AU)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CAPI2/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CDROM/Operational" /v "OwningPublisher" /t REG_SZ /d "{9b6123dc-9af6-4430-80d7-7d36f054fb9f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CDROM/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CDROM/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CDROM/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CDROM/Operational" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CertificateServicesClient-CredentialRoaming/Operational" /v "OwningPublisher" /t REG_SZ /d "{89a2278b-c662-4aff-a06c-46ad3f220bca}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CertificateServicesClient-CredentialRoaming/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CertificateServicesClient-CredentialRoaming/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CertificateServicesClient-CredentialRoaming/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CertificateServicesClient-CredentialRoaming/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CertPoleEng/Operational" /v "OwningPublisher" /t REG_SZ /d "{af9cc194-e9a8-42bd-b0d1-834e9cfab799}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CertPoleEng/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CertPoleEng/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CertPoleEng/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CertPoleEng/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ClearTypeTextTuner/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{0a88862d-20a3-4c1f-b76f-162c55adbf93}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ClearTypeTextTuner/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ClearTypeTextTuner/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ClearTypeTextTuner/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ClearTypeTextTuner/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CloudStore/Debug" /v "OwningPublisher" /t REG_SZ /d "{741bb90c-a7a3-49d6-bd82-1e6b858403f7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CloudStore/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CloudStore/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CloudStore/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CloudStore/Debug" /v "MaxSize" /t REG_DWORD /d "10485760" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CloudStore/Debug" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CloudStore/Debug" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CmiSetup/Analytic" /v "OwningPublisher" /t REG_SZ /d "{75ebc33e-0cc6-49da-8cd9-8903a5222aa0}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CmiSetup/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CmiSetup/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CmiSetup/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CmiSetup/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CodeIntegrity/Verbose" /v "OwningPublisher" /t REG_SZ /d "{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CodeIntegrity/Verbose" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CodeIntegrity/Verbose" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CodeIntegrity/Verbose" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CodeIntegrity/Verbose" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/Analytic" /v "OwningPublisher" /t REG_SZ /d "{d4263c98-310c-4d97-ba39-b55354f08584}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/ApartmentInitialize" /v "OwningPublisher" /t REG_SZ /d "{b8d6861b-d20f-4eec-bbae-87e0dd80602b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/ApartmentInitialize" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/ApartmentInitialize" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/ApartmentInitialize" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/ApartmentInitialize" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/ApartmentUninitialize" /v "OwningPublisher" /t REG_SZ /d "{b8d6861b-d20f-4eec-bbae-87e0dd80602b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/ApartmentUninitialize" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/ApartmentUninitialize" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/ApartmentUninitialize" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/ApartmentUninitialize" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/Call" /v "OwningPublisher" /t REG_SZ /d "{b8d6861b-d20f-4eec-bbae-87e0dd80602b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/Call" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/Call" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/Call" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/Call" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/CreateInstance" /v "OwningPublisher" /t REG_SZ /d "{b8d6861b-d20f-4eec-bbae-87e0dd80602b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/CreateInstance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/CreateInstance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/CreateInstance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/CreateInstance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/ExtensionCatalog" /v "OwningPublisher" /t REG_SZ /d "{b8d6861b-d20f-4eec-bbae-87e0dd80602b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/ExtensionCatalog" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/ExtensionCatalog" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/ExtensionCatalog" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/ExtensionCatalog" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/FreeUnusedLibrary" /v "OwningPublisher" /t REG_SZ /d "{b8d6861b-d20f-4eec-bbae-87e0dd80602b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/FreeUnusedLibrary" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/FreeUnusedLibrary" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/FreeUnusedLibrary" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/FreeUnusedLibrary" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/RundownInstrumentation" /v "OwningPublisher" /t REG_SZ /d "{2957313d-fcaa-5d4a-2f69-32ce5f0ac44e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/RundownInstrumentation" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/RundownInstrumentation" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/RundownInstrumentation" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COM/RundownInstrumentation" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ComDlg32/Analytic" /v "OwningPublisher" /t REG_SZ /d "{7f912b92-21ad-496e-b97a-88622a72bc42}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ComDlg32/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ComDlg32/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ComDlg32/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ComDlg32/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ComDlg32/Debug" /v "OwningPublisher" /t REG_SZ /d "{7f912b92-21ad-496e-b97a-88622a72bc42}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ComDlg32/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ComDlg32/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ComDlg32/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ComDlg32/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COMRuntime/Activations" /v "OwningPublisher" /t REG_SZ /d "{bf406804-6afa-46e7-8a48-6c357e1d6d61}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COMRuntime/Activations" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COMRuntime/Activations" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COMRuntime/Activations" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COMRuntime/Activations" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COMRuntime/MessageProcessing" /v "OwningPublisher" /t REG_SZ /d "{bf406804-6afa-46e7-8a48-6c357e1d6d61}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COMRuntime/MessageProcessing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COMRuntime/MessageProcessing" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COMRuntime/MessageProcessing" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COMRuntime/MessageProcessing" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COMRuntime/Tracing" /v "OwningPublisher" /t REG_SZ /d "{bf406804-6afa-46e7-8a48-6c357e1d6d61}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COMRuntime/Tracing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COMRuntime/Tracing" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COMRuntime/Tracing" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-COMRuntime/Tracing" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Containers-BindFlt/Debug" /v "OwningPublisher" /t REG_SZ /d "{fc4e8f51-7a04-4bab-8b91-6321416f72ab}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Containers-BindFlt/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Containers-BindFlt/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Containers-BindFlt/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Containers-BindFlt/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Containers-Wcifs/Debug" /v "OwningPublisher" /t REG_SZ /d "{aec5c129-7c10-407d-be97-91a042c61aaa}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Containers-Wcifs/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Containers-Wcifs/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Containers-Wcifs/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Containers-Wcifs/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Containers-Wcnfs/Debug" /v "OwningPublisher" /t REG_SZ /d "{b99317e5-89b7-4c0d-abd1-6e705f7912dc}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Containers-Wcnfs/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Containers-Wcnfs/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Containers-Wcnfs/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Containers-Wcnfs/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreApplication/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{5f0e257f-c224-43e5-9555-2adcb8540a58}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreApplication/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreApplication/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreApplication/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreApplication/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreApplication/Tracing" /v "OwningPublisher" /t REG_SZ /d "{5f0e257f-c224-43e5-9555-2adcb8540a58}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreApplication/Tracing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreApplication/Tracing" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreApplication/Tracing" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreApplication/Tracing" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreSystem-SmsRouter-Events/Debug" /v "OwningPublisher" /t REG_SZ /d "{a9c11050-9e93-4fa4-8fe0-7c4750a345b2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreSystem-SmsRouter-Events/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreSystem-SmsRouter-Events/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreSystem-SmsRouter-Events/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreSystem-SmsRouter-Events/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreWindow/Analytic" /v "OwningPublisher" /t REG_SZ /d "{a3d95055-34cc-4e4a-b99f-ec88f5370495}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreWindow/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreWindow/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreWindow/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreWindow/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreWindow/Debug" /v "OwningPublisher" /t REG_SZ /d "{a3d95055-34cc-4e4a-b99f-ec88f5370495}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreWindow/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreWindow/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreWindow/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CoreWindow/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crashdump/Operational" /v "OwningPublisher" /t REG_SZ /d "{ecdaacfa-6fe9-477c-b5f0-85b76f8f50aa}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crashdump/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crashdump/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crashdump/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crashdump/Operational" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CredUI/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{5a24fcdb-1cf3-477b-b422-ef4909d51223}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CredUI/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CredUI/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CredUI/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-CredUI/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-BCRYPT/Analytic" /v "OwningPublisher" /t REG_SZ /d "{c7e089ac-ba2a-11e0-9af7-68384824019b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-BCRYPT/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-BCRYPT/Analytic" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-BCRYPT/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x7BA)(A0x2AU)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-BCRYPT/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-CNG/Analytic" /v "OwningPublisher" /t REG_SZ /d "{e3e0e2f0-c9c5-11e0-8ab9-9ebc4824019b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-CNG/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-CNG/Analytic" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-CNG/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x7BA)(A0x2AU)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-CNG/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-DPAPI/Debug" /v "OwningPublisher" /t REG_SZ /d "{89fe8f40-cdce-464e-8217-15ef97d4c7c3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-DPAPI/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-DPAPI/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-DPAPI/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-DPAPI/Debug" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-DSSEnh/Analytic" /v "OwningPublisher" /t REG_SZ /d "{43dad447-735f-4829-a6ff-9829a87419ff}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-DSSEnh/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-DSSEnh/Analytic" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-DSSEnh/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x7BA)(A0x2AU)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-DSSEnh/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-RNG/Analytic" /v "OwningPublisher" /t REG_SZ /d "{54d5ac20-e14f-4fda-92da-ebf7556ff176}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-RNG/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-RNG/Analytic" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-RNG/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x7BA)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-RNG/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-RSAEnh/Analytic" /v "OwningPublisher" /t REG_SZ /d "{152fdb2b-6e9d-4b60-b317-815d5f174c4a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-RSAEnh/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-RSAEnh/Analytic" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-RSAEnh/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x7BA)(A0x2AU)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Crypto-RSAEnh/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-D3D10Level9/Analytic" /v "OwningPublisher" /t REG_SZ /d "{7e7d3382-023c-43cb-95d2-6f0ca6d70381}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-D3D10Level9/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-D3D10Level9/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-D3D10Level9/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-D3D10Level9/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-D3D10Level9/PerfTiming" /v "OwningPublisher" /t REG_SZ /d "{7e7d3382-023c-43cb-95d2-6f0ca6d70381}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-D3D10Level9/PerfTiming" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-D3D10Level9/PerfTiming" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-D3D10Level9/PerfTiming" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-D3D10Level9/PerfTiming" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DAL-Provider/Analytic" /v "OwningPublisher" /t REG_SZ /d "{7e87506f-bace-4bf1-bc09-3a1f37045c71}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DAL-Provider/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DAL-Provider/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DAL-Provider/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DAL-Provider/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DAMM/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{dd2fe441-6c12-41fd-8232-3709c6045f63}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DAMM/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DAMM/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DAMM/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DAMM/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DateTimeControlPanel/Analytic" /v "OwningPublisher" /t REG_SZ /d "{741fc222-44ed-4ba7-98e3-f405b2d2c4b4}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DateTimeControlPanel/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DateTimeControlPanel/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DateTimeControlPanel/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DateTimeControlPanel/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DateTimeControlPanel/Debug" /v "OwningPublisher" /t REG_SZ /d "{741fc222-44ed-4ba7-98e3-f405b2d2c4b4}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DateTimeControlPanel/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DateTimeControlPanel/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DateTimeControlPanel/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DateTimeControlPanel/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DCLocator/Debug" /v "OwningPublisher" /t REG_SZ /d "{cfaa5446-c6c4-4f5c-866f-31c9b55b962d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DCLocator/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DCLocator/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DCLocator/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DCLocator/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DDisplay/Analytic" /v "OwningPublisher" /t REG_SZ /d "{75051c9d-2833-4a29-8923-046db7a432ca}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DDisplay/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DDisplay/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DDisplay/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DDisplay/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DDisplay/Logging" /v "OwningPublisher" /t REG_SZ /d "{75051c9d-2833-4a29-8923-046db7a432ca}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DDisplay/Logging" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DDisplay/Logging" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DDisplay/Logging" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DDisplay/Logging" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Deduplication/Performance" /v "OwningPublisher" /t REG_SZ /d "{f9fe3908-44b8-48d9-9a32-5a763ff5ed79}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Deduplication/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Deduplication/Performance" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Deduplication/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(D0xf0007AN)(D0xf0007BG)(A0x7SY)(A0x7BA)(A0x2WD)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Deduplication/Performance" /v "MaxSize" /t REG_DWORD /d "10485760" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Deduplication/Performance" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Deduplication/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Deduplication/Performance" /v "BufferSize" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Deplorch/Analytic" /v "OwningPublisher" /t REG_SZ /d "{b9da9fe6-ae5f-4f3e-b2fa-8e623c11dc75}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Deplorch/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Deplorch/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Deplorch/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Deplorch/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DesktopActivityModerator/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{32dd13df-9c0b-4c3b-b854-ee76c050f5f4}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DesktopActivityModerator/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DesktopActivityModerator/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DesktopActivityModerator/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DesktopActivityModerator/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DesktopWindowManager-Diag/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{31f60101-3703-48ea-8143-451f8de779d2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DesktopWindowManager-Diag/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DesktopWindowManager-Diag/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DesktopWindowManager-Diag/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DesktopWindowManager-Diag/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceAssociationService/Performance" /v "OwningPublisher" /t REG_SZ /d "{56c71c31-cfbd-4cdd-8559-505e042bbbe1}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceAssociationService/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceAssociationService/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceAssociationService/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceAssociationService/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceGuard/Verbose" /v "OwningPublisher" /t REG_SZ /d "{f717d024-f5b4-4f03-9ab9-331b2dc38ffb}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceGuard/Verbose" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceGuard/Verbose" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceGuard/Verbose" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceGuard/Verbose" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Debug" /v "OwningPublisher" /t REG_SZ /d "{3da494e4-0fe2-415c-b895-fb5265c5c83b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSetupManager/Analytic" /v "OwningPublisher" /t REG_SZ /d "{fcbb06bb-6a2a-46e3-abaa-246cb4e508b2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSetupManager/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSetupManager/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSetupManager/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSetupManager/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSetupManager/Debug" /v "OwningPublisher" /t REG_SZ /d "{fcbb06bb-6a2a-46e3-abaa-246cb4e508b2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSetupManager/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSetupManager/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSetupManager/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSetupManager/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSync/Analytic" /v "OwningPublisher" /t REG_SZ /d "{09ec9687-d7ad-40ca-9c5e-78a04a5ae993}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSync/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSync/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSync/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceSync/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceUx/Informational" /v "OwningPublisher" /t REG_SZ /d "{ded165cf-485d-4770-a3e7-9c5f0320e80c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceUx/Informational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceUx/Informational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceUx/Informational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceUx/Informational" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceUx/Performance" /v "OwningPublisher" /t REG_SZ /d "{ded165cf-485d-4770-a3e7-9c5f0320e80c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceUx/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceUx/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceUx/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceUx/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcp-Client/Operational" /v "OwningPublisher" /t REG_SZ /d "{15a7a4f8-0072-4eab-abad-f98a4d666aed}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcp-Client/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcp-Client/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcp-Client/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcp-Client/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcpv6-Client/Operational" /v "OwningPublisher" /t REG_SZ /d "{6a1f2b00-6a90-4c38-95a5-5cab3b056778}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcpv6-Client/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcpv6-Client/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcpv6-Client/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dhcpv6-Client/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PCW/Analytic" /v "OwningPublisher" /t REG_SZ /d "{aabf8b86-7936-4fa2-acb0-63127f879dbf}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PCW/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PCW/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PCW/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PCW/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PCW/Debug" /v "OwningPublisher" /t REG_SZ /d "{aabf8b86-7936-4fa2-acb0-63127f879dbf}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PCW/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PCW/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PCW/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PCW/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-Perfhost/Analytic" /v "OwningPublisher" /t REG_SZ /d "{f27b948b-0a7c-4eb6-92ec-8a2c1b353ecd}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-Perfhost/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-Perfhost/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-Perfhost/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-Perfhost/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PLA/Debug" /v "OwningPublisher" /t REG_SZ /d "{e4d53f84-7de3-11d8-9435-505054503030}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PLA/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PLA/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PLA/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PLA/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D10/Analytic" /v "OwningPublisher" /t REG_SZ /d "{9b7e4c0f-342c-4106-a19f-4f2704f689f0}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D10/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D10/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D10/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D10/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D10_1/Analytic" /v "OwningPublisher" /t REG_SZ /d "{9b7e4c8f-342c-4106-a19f-4f2704f689f0}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D10_1/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D10_1/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D10_1/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D10_1/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D11/Analytic" /v "OwningPublisher" /t REG_SZ /d "{db6f6ddb-ac77-4e88-8253-819df9bbf140}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D11/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D11/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D11/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D11/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D11/Logging" /v "OwningPublisher" /t REG_SZ /d "{db6f6ddb-ac77-4e88-8253-819df9bbf140}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D11/Logging" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D11/Logging" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D11/Logging" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D11/Logging" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D11/PerfTiming" /v "OwningPublisher" /t REG_SZ /d "{db6f6ddb-ac77-4e88-8253-819df9bbf140}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D11/PerfTiming" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D11/PerfTiming" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D11/PerfTiming" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D11/PerfTiming" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D12/Analytic" /v "OwningPublisher" /t REG_SZ /d "{5d8087dd-3a9b-4f56-90df-49196cdc4f11}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D12/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D12/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D12/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D12/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D12/Logging" /v "OwningPublisher" /t REG_SZ /d "{5d8087dd-3a9b-4f56-90df-49196cdc4f11}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D12/Logging" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D12/Logging" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D12/Logging" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D12/Logging" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D12/PerfTiming" /v "OwningPublisher" /t REG_SZ /d "{5d8087dd-3a9b-4f56-90df-49196cdc4f11}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D12/PerfTiming" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D12/PerfTiming" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D12/PerfTiming" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D12/PerfTiming" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D9/Analytic" /v "OwningPublisher" /t REG_SZ /d "{783aca0a-790e-4d7f-8451-aa850511c6b9}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D9/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D9/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D9/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3D9/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3DShaderCache/Default" /v "OwningPublisher" /t REG_SZ /d "{2d4ebca6-ea64-453f-a292-ae2ea0ee513b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3DShaderCache/Default" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3DShaderCache/Default" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3DShaderCache/Default" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Direct3DShaderCache/Default" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectComposition/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{c44219d0-f344-11df-a5e2-b307dfd72085}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectComposition/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectComposition/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectComposition/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectComposition/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectManipulation/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{5786e035-ef2d-4178-84f2-5a6bbedbb947}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectManipulation/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectManipulation/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectManipulation/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectManipulation/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectShow-KernelSupport/Performance" /v "OwningPublisher" /t REG_SZ /d "{3cc2d4af-da5e-4ed4-bcbe-3cf995940483}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectShow-KernelSupport/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectShow-KernelSupport/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectShow-KernelSupport/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectShow-KernelSupport/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectSound/Debug" /v "OwningPublisher" /t REG_SZ /d "{8a93b54b-c75a-49b5-a5be-9060715b1a33}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectSound/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectSound/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectSound/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DirectSound/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Disk/Operational" /v "OwningPublisher" /t REG_SZ /d "{6b4db0bc-9a3d-467d-81b9-a84c6f2f3d40}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Disk/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Disk/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Disk/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Disk/Operational" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Api/Analytic" /v "OwningPublisher" /t REG_SZ /d "{75b0da21-8b50-42eb-9448-ec48b1729b57}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Api/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Api/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Api/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Api/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Api/ExternalAnalytic" /v "OwningPublisher" /t REG_SZ /d "{75b0da21-8b50-42eb-9448-ec48b1729b57}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Api/ExternalAnalytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Api/ExternalAnalytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Api/ExternalAnalytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Api/ExternalAnalytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Api/InternalAnalytic" /v "OwningPublisher" /t REG_SZ /d "{75b0da21-8b50-42eb-9448-ec48b1729b57}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Api/InternalAnalytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Api/InternalAnalytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Api/InternalAnalytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Api/InternalAnalytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Cli/Analytic" /v "OwningPublisher" /t REG_SZ /d "{2f959466-24d4-4972-8729-0d5e3539ebc3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Cli/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Cli/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Cli/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dism-Cli/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DisplayColorCalibration/Debug" /v "OwningPublisher" /t REG_SZ /d "{3239eb6f-c7fc-4953-aa15-646829a4ca4c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DisplayColorCalibration/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DisplayColorCalibration/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DisplayColorCalibration/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DisplayColorCalibration/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DisplayColorCalibration/Operational" /v "OwningPublisher" /t REG_SZ /d "{3239eb6f-c7fc-4953-aa15-646829a4ca4c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DisplayColorCalibration/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DisplayColorCalibration/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DisplayColorCalibration/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DisplayColorCalibration/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DisplaySwitch/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{192ede41-9175-4c86-ac02-9d003c9d43ab}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DisplaySwitch/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DisplaySwitch/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DisplaySwitch/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DisplaySwitch/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DLNA-Namespace/Analytic" /v "OwningPublisher" /t REG_SZ /d "{d38fb874-33e4-4dcf-911e-1b53bb106d53}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DLNA-Namespace/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DLNA-Namespace/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DLNA-Namespace/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DLNA-Namespace/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DNS-Client/Operational" /v "OwningPublisher" /t REG_SZ /d "{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DNS-Client/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DNS-Client/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DNS-Client/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DNS-Client/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Documents/Performance" /v "OwningPublisher" /t REG_SZ /d "{c89b991e-3b48-49b2-80d3-ac000dfc9749}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Documents/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Documents/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Documents/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Documents/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dot3MM/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{f3419a17-e994-4c40-b593-79b8edec54e9}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dot3MM/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dot3MM/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dot3MM/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dot3MM/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DriverFrameworks-UserMode/Operational" /v "OwningPublisher" /t REG_SZ /d "{2e35aaeb-857f-4beb-a418-2e6c0e54d988}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DriverFrameworks-UserMode/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DriverFrameworks-UserMode/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DriverFrameworks-UserMode/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DriverFrameworks-UserMode/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DSC/Analytic" /v "OwningPublisher" /t REG_SZ /d "{50df9e12-a8c4-4939-b281-47e1325ba63e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DSC/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DSC/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DSC/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DSC/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DSC/Debug" /v "OwningPublisher" /t REG_SZ /d "{50df9e12-a8c4-4939-b281-47e1325ba63e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DSC/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DSC/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DSC/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DSC/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DUI/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{8360bd0f-a7dc-4391-91a7-a457c5c381e4}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DUI/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DUI/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DUI/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DUI/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DUSER/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{8429e243-345b-47c1-8a91-2c94caf0daab}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DUSER/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DUSER/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DUSER/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DUSER/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-API/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{292a52c4-fa27-4461-b526-54a46430bd54}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-API/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-API/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-API/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-API/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Core/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{9e9bba3c-2e38-40cb-99f4-9e8281425164}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Core/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Core/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Core/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Core/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Dwm/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{d29d56ea-4867-4221-b02e-cfd998834075}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Dwm/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Dwm/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Dwm/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Dwm/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Redir/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{7d99f6a4-1bec-4c09-9703-3aaa8148347f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Redir/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Redir/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Redir/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Redir/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Udwm/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{a2d1c713-093b-43a7-b445-d09370ec9f47}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Udwm/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Udwm/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Udwm/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Dwm-Udwm/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DXGI/Analytic" /v "OwningPublisher" /t REG_SZ /d "{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DXGI/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DXGI/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DXGI/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DXGI/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DXGI/Logging" /v "OwningPublisher" /t REG_SZ /d "{ca11c036-0102-4a2d-a6ad-f03cfed5d3c9}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DXGI/Logging" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DXGI/Logging" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DXGI/Logging" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DXGI/Logging" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Contention" /v "OwningPublisher" /t REG_SZ /d "{802ec45a-1e99-4b83-9920-87c98277ba9d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Contention" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Contention" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Contention" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Contention" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{802ec45a-1e99-4b83-9920-87c98277ba9d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Performance" /v "OwningPublisher" /t REG_SZ /d "{802ec45a-1e99-4b83-9920-87c98277ba9d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Power" /v "OwningPublisher" /t REG_SZ /d "{802ec45a-1e99-4b83-9920-87c98277ba9d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Power" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Power" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Power" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxgKrnl/Power" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DXP/Analytic" /v "OwningPublisher" /t REG_SZ /d "{728b8c72-0f0f-4071-9bcc-27cb3b6dacbe}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DXP/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DXP/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DXP/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DXP/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxpTaskSyncProvider/Analytic" /v "OwningPublisher" /t REG_SZ /d "{271c5228-c3fe-4e47-831f-48c3652ce5ac}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxpTaskSyncProvider/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxpTaskSyncProvider/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxpTaskSyncProvider/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DxpTaskSyncProvider/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EapHost/Analytic" /v "OwningPublisher" /t REG_SZ /d "{6eb8db94-fe96-443f-a366-5fe0cee7fb1c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EapHost/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EapHost/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EapHost/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EapHost/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EapHost/Debug" /v "OwningPublisher" /t REG_SZ /d "{6eb8db94-fe96-443f-a366-5fe0cee7fb1c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EapHost/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EapHost/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EapHost/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EapHost/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EaseOfAccess/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{74b4a4b1-2302-4768-ac5b-9773dd456b08}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EaseOfAccess/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EaseOfAccess/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EaseOfAccess/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EaseOfAccess/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EFS/Debug" /v "OwningPublisher" /t REG_SZ /d "{3663a992-84be-40ea-bba9-90c7ed544222}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EFS/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EFS/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EFS/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EFS/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ESE/IODiagnose" /v "OwningPublisher" /t REG_SZ /d "{478ea8a8-00be-4ba6-8e75-8b9dc7db9f78}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ESE/IODiagnose" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ESE/IODiagnose" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ESE/IODiagnose" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ESE/IODiagnose" /v "MaxSize" /t REG_DWORD /d "20971520" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ESE/IODiagnose" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ESE/IODiagnose" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ESE/Operational" /v "OwningPublisher" /t REG_SZ /d "{478ea8a8-00be-4ba6-8e75-8b9dc7db9f78}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ESE/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ESE/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ESE/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ESE/Operational" /v "MaxSize" /t REG_DWORD /d "655360" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ESE/Operational" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ESE/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventCollector/Debug" /v "OwningPublisher" /t REG_SZ /d "{b977cf02-76f6-df84-cc1a-6a4b232322b6}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventCollector/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventCollector/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventCollector/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventCollector/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventCollector/Debug" /v "Level" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventCollector/Debug" /v "KeywordsLower" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventCollector/Debug" /v "KeywordsUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventCollector/Debug" /v "ControlGuid" /t REG_SZ /d "{cddc4496-d9e2-4530-8fb5-9e4448aaf60d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog-WMIProvider/Debug" /v "OwningPublisher" /t REG_SZ /d "{35ac6ce8-6104-411d-976c-877f183d2d32}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog-WMIProvider/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog-WMIProvider/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog-WMIProvider/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog-WMIProvider/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog-WMIProvider/Debug" /v "Level" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog-WMIProvider/Debug" /v "KeywordsLower" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog-WMIProvider/Debug" /v "KeywordsUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog-WMIProvider/Debug" /v "ControlGuid" /t REG_SZ /d "{224db5a0-be14-4bc2-8a6a-cbec1e24e0be}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog/Analytic" /v "OwningPublisher" /t REG_SZ /d "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog/Debug" /v "OwningPublisher" /t REG_SZ /d "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog/Debug" /v "Level" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog/Debug" /v "KeywordsLower" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog/Debug" /v "KeywordsUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-EventLog/Debug" /v "ControlGuid" /t REG_SZ /d "{b0ca1d82-539d-4fb0-944b-1620c6e86231}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FailoverClustering-Client/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{a82fda5d-745f-409c-b0fe-18ae0678a0e0}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FailoverClustering-Client/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FailoverClustering-Client/Diagnostic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FailoverClustering-Client/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FailoverClustering-Client/Diagnostic" /v "MaxSize" /t REG_DWORD /d "104857600" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FailoverClustering-Client/Diagnostic" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FailoverClustering-Client/Diagnostic" /v "Retention" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FailoverClustering-Client/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FailoverClustering-Client/Diagnostic" /v "ClockType" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Catalog/Analytic" /v "OwningPublisher" /t REG_SZ /d "{b447b4dc-7780-11e0-ada3-18a90531a85a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Catalog/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Catalog/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Catalog/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Catalog/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Catalog/Debug" /v "OwningPublisher" /t REG_SZ /d "{b447b4dc-7780-11e0-ada3-18a90531a85a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Catalog/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Catalog/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Catalog/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Catalog/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-ConfigManager/Analytic" /v "OwningPublisher" /t REG_SZ /d "{b447b4dd-7780-11e0-ada3-18a90531a85a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-ConfigManager/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-ConfigManager/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-ConfigManager/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-ConfigManager/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-ConfigManager/Debug" /v "OwningPublisher" /t REG_SZ /d "{b447b4dd-7780-11e0-ada3-18a90531a85a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-ConfigManager/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-ConfigManager/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-ConfigManager/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-ConfigManager/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Core/Analytic" /v "OwningPublisher" /t REG_SZ /d "{b447b4db-7780-11e0-ada3-18a90531a85a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Core/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Core/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Core/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Core/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Core/Debug" /v "OwningPublisher" /t REG_SZ /d "{b447b4db-7780-11e0-ada3-18a90531a85a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Core/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Core/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Core/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Core/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Engine/Analytic" /v "OwningPublisher" /t REG_SZ /d "{b447b4de-7780-11e0-ada3-18a90531a85a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Engine/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Engine/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Engine/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Engine/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Engine/Debug" /v "OwningPublisher" /t REG_SZ /d "{b447b4de-7780-11e0-ada3-18a90531a85a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Engine/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Engine/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Engine/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Engine/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-EventListener/Analytic" /v "OwningPublisher" /t REG_SZ /d "{b447b4df-7780-11e0-ada3-18a90531a85a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-EventListener/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-EventListener/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-EventListener/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-EventListener/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-EventListener/Debug" /v "OwningPublisher" /t REG_SZ /d "{b447b4df-7780-11e0-ada3-18a90531a85a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-EventListener/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-EventListener/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-EventListener/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-EventListener/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Service/Analytic" /v "OwningPublisher" /t REG_SZ /d "{b447b4e0-7780-11e0-ada3-18a90531a85a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Service/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Service/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Service/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Service/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Service/Debug" /v "OwningPublisher" /t REG_SZ /d "{b447b4e0-7780-11e0-ada3-18a90531a85a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Service/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Service/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Service/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-Service/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-UI-Events/Analytic" /v "OwningPublisher" /t REG_SZ /d "{b447b4e1-7780-11e0-ada3-18a90531a85a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-UI-Events/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-UI-Events/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-UI-Events/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-UI-Events/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-UI-Events/Debug" /v "OwningPublisher" /t REG_SZ /d "{b447b4e1-7780-11e0-ada3-18a90531a85a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-UI-Events/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-UI-Events/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-UI-Events/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileHistory-UI-Events/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileInfoMinifilter/Operational" /v "OwningPublisher" /t REG_SZ /d "{a319d300-015c-48be-acdb-47746e154751}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileInfoMinifilter/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileInfoMinifilter/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileInfoMinifilter/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FileInfoMinifilter/Operational" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Firewall-CPL/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{546549be-9d63-46aa-9154-4f6eb9526378}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Firewall-CPL/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Firewall-CPL/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Firewall-CPL/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Firewall-CPL/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FMS/Analytic" /v "OwningPublisher" /t REG_SZ /d "{dea07764-0790-44de-b9c4-49677b17174f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FMS/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FMS/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FMS/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FMS/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FMS/Debug" /v "OwningPublisher" /t REG_SZ /d "{dea07764-0790-44de-b9c4-49677b17174f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FMS/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FMS/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FMS/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-FMS/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Forwarding/Debug" /v "OwningPublisher" /t REG_SZ /d "{699e309c-e782-4400-98c8-e21d162d7b7b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Forwarding/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Forwarding/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Forwarding/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Forwarding/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Forwarding/Debug" /v "Level" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Forwarding/Debug" /v "KeywordsLower" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Forwarding/Debug" /v "KeywordsUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Forwarding/Debug" /v "ControlGuid" /t REG_SZ /d "{6fcdf39a-ef67-483d-a661-76d715c6b008}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-GPIO-ClassExtension/Analytic" /v "OwningPublisher" /t REG_SZ /d "{55ab77f6-fa04-43ef-af45-688fbf500482}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-GPIO-ClassExtension/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-GPIO-ClassExtension/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-GPIO-ClassExtension/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-GPIO-ClassExtension/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HAL/Debug" /v "OwningPublisher" /t REG_SZ /d "{63d1e632-95cc-4443-9312-af927761d52a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HAL/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HAL/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HAL/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HAL/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HelloForBusiness/Operational" /v "OwningPublisher" /t REG_SZ /d "{906b8a99-63ce-58d7-86ab-10989bbd5567}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HelloForBusiness/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HelloForBusiness/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HelloForBusiness/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HelloForBusiness/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HomeGroup Control Panel Performance/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{134ea407-755d-4a93-b8a6-f290cd155023}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HomeGroup Control Panel Performance/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HomeGroup Control Panel Performance/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HomeGroup Control Panel Performance/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HomeGroup Control Panel Performance/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HomeGroup Provider Service Performance/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{c9bdb4eb-9287-4c8e-8378-6896f0d1c5ef}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HomeGroup Provider Service Performance/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HomeGroup Provider Service Performance/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HomeGroup Provider Service Performance/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HomeGroup Provider Service Performance/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HomeGroup-ListenerService" /v "OwningPublisher" /t REG_SZ /d "{af0a5a6d-e009-46d4-8867-42f2240f8a72}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HomeGroup-ListenerService" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HomeGroup-ListenerService" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HomeGroup-ListenerService" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HomeGroup-ListenerService" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HotspotAuth/Analytic" /v "OwningPublisher" /t REG_SZ /d "{de095dbe-8667-4168-94c2-48ca61665aca}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HotspotAuth/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HotspotAuth/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HotspotAuth/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HotspotAuth/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HotspotAuth/Operational" /v "OwningPublisher" /t REG_SZ /d "{de095dbe-8667-4168-94c2-48ca61665aca}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HotspotAuth/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HotspotAuth/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HotspotAuth/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HotspotAuth/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HttpService/Log" /v "OwningPublisher" /t REG_SZ /d "{c42a2738-2333-40a5-a32f-6acc36449dcc}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HttpService/Log" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HttpService/Log" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HttpService/Log" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HttpService/Log" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HttpService/Trace" /v "OwningPublisher" /t REG_SZ /d "{dd5ef90a-6398-47a4-ad34-4dcecdef795f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HttpService/Trace" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HttpService/Trace" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HttpService/Trace" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-HttpService/Trace" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Admin" /v "OwningPublisher" /t REG_SZ /d "{ba2ffb5c-e20a-4fb9-91b4-45f61b4b66a0}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Admin" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Admin" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Admin" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Admin" /v "Type" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Analytic" /v "OwningPublisher" /t REG_SZ /d "{ba2ffb5c-e20a-4fb9-91b4-45f61b4b66a0}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Debug" /v "OwningPublisher" /t REG_SZ /d "{ba2ffb5c-e20a-4fb9-91b4-45f61b4b66a0}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Diagnose" /v "OwningPublisher" /t REG_SZ /d "{ba2ffb5c-e20a-4fb9-91b4-45f61b4b66a0}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Diagnose" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Diagnose" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Diagnose" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Diagnose" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Operational" /v "OwningPublisher" /t REG_SZ /d "{ba2ffb5c-e20a-4fb9-91b4-45f61b4b66a0}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Guest-Drivers/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Hypervisor-Admin" /v "OwningPublisher" /t REG_SZ /d "{52fc89f8-995e-434c-a91e-199986449890}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Hypervisor-Admin" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Hypervisor-Admin" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Hypervisor-Admin" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)(A0x1S-1-5-32-578)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Hypervisor-Admin" /v "Type" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Hypervisor-Analytic" /v "OwningPublisher" /t REG_SZ /d "{52fc89f8-995e-434c-a91e-199986449890}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Hypervisor-Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Hypervisor-Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Hypervisor-Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)(A0x1S-1-5-32-578)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Hypervisor-Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Hypervisor-Operational" /v "OwningPublisher" /t REG_SZ /d "{52fc89f8-995e-434c-a91e-199986449890}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Hypervisor-Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Hypervisor-Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Hypervisor-Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)(A0x1S-1-5-32-578)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-Hypervisor-Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-NETVSC/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{152fbe4b-c7ad-4f68-bada-a4fcc1464f6c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-NETVSC/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-NETVSC/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-NETVSC/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-NETVSC/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-VID-Admin" /v "OwningPublisher" /t REG_SZ /d "{5931d877-4860-4ee7-a95c-610a5f0d1407}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-VID-Admin" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-VID-Admin" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-VID-Admin" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)(A0x1S-1-5-32-578)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-VID-Admin" /v "Type" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-VID-Analytic" /v "OwningPublisher" /t REG_SZ /d "{5931d877-4860-4ee7-a95c-610a5f0d1407}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-VID-Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-VID-Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-VID-Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)(A0x1S-1-5-32-578)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Hyper-V-VID-Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IdCtrls/Analytic" /v "OwningPublisher" /t REG_SZ /d "{6d7662a9-034e-4b1f-a167-67819c401632}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IdCtrls/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IdCtrls/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IdCtrls/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IdCtrls/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IE-SmartScreen" /v "OwningPublisher" /t REG_SZ /d "{52f82079-1974-4c67-81da-807b892778bb}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IE-SmartScreen" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IE-SmartScreen" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IE-SmartScreen" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IE-SmartScreen" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IKEDBG/Debug" /v "OwningPublisher" /t REG_SZ /d "{0c478c5b-0351-41b1-8c58-4a6737da32e3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IKEDBG/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IKEDBG/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IKEDBG/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IKEDBG/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-Broker/Analytic" /v "OwningPublisher" /t REG_SZ /d "{e2c15fd7-8924-4c8c-8cfe-da0be539ce27}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-Broker/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-Broker/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-Broker/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-Broker/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-CandidateUI/Analytic" /v "OwningPublisher" /t REG_SZ /d "{7c4117b1-ed82-4f47-b2ca-29e4e25719c7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-CandidateUI/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-CandidateUI/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-CandidateUI/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-CandidateUI/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-CustomerFeedbackManager/Debug" /v "OwningPublisher" /t REG_SZ /d "{e2242b38-9453-42fd-b446-00746e76eb82}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-CustomerFeedbackManager/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-CustomerFeedbackManager/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-CustomerFeedbackManager/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-CustomerFeedbackManager/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-CustomerFeedbackManagerUI/Analytic" /v "OwningPublisher" /t REG_SZ /d "{1b734b40-a458-4b81-954f-ad7c9461bed8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-CustomerFeedbackManagerUI/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-CustomerFeedbackManagerUI/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-CustomerFeedbackManagerUI/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-CustomerFeedbackManagerUI/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPAPI/Analytic" /v "OwningPublisher" /t REG_SZ /d "{31bcac7f-4ab8-47a1-b73a-a161ee68d585}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPAPI/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPAPI/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPAPI/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPAPI/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPLMP/Analytic" /v "OwningPublisher" /t REG_SZ /d "{dbc388bc-89c2-4fe0-b71f-6e4881fb575c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPLMP/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPLMP/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPLMP/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPLMP/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPPRED/Analytic" /v "OwningPublisher" /t REG_SZ /d "{3ad571f3-bdae-4942-8733-4d1b85870a1e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPPRED/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPPRED/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPPRED/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPPRED/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPSetting/Analytic" /v "OwningPublisher" /t REG_SZ /d "{14371053-1813-471a-9510-1cf1d0a055a8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPSetting/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPSetting/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPSetting/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPSetting/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPTIP/Analytic" /v "OwningPublisher" /t REG_SZ /d "{8c8a69ad-cc89-481f-bbad-fd95b5006256}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPTIP/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPTIP/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPTIP/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-JPTIP/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-KRAPI/Analytic" /v "OwningPublisher" /t REG_SZ /d "{7562948e-2671-4dda-8f8f-bf945ef984a1}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-KRAPI/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-KRAPI/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-KRAPI/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-KRAPI/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-KRTIP/Analytic" /v "OwningPublisher" /t REG_SZ /d "{e013e74b-97f4-4e1c-a120-596e5629ecfe}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-KRTIP/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-KRTIP/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-KRTIP/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-KRTIP/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-OEDCompiler/Analytic" /v "OwningPublisher" /t REG_SZ /d "{fd44a6e7-580f-4a9c-83d9-d820b7d3a033}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-OEDCompiler/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-OEDCompiler/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-OEDCompiler/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-OEDCompiler/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-TCCORE/Analytic" /v "OwningPublisher" /t REG_SZ /d "{f67b2345-47fa-4721-a6fb-fe08110eecf7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-TCCORE/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-TCCORE/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-TCCORE/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-TCCORE/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-TCTIP/Analytic" /v "OwningPublisher" /t REG_SZ /d "{d5268c02-6f51-436f-983b-74f2efbfaf3a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-TCTIP/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-TCTIP/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-TCTIP/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-TCTIP/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-TIP/Analytic" /v "OwningPublisher" /t REG_SZ /d "{bdd4b92e-19ef-4497-9c4a-e10e7fd2e227}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-TIP/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-TIP/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-TIP/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IME-TIP/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IndirectDisplays-ClassExtension-Events/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{966cd1c0-3f69-42ad-9877-517dce8462b4}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IndirectDisplays-ClassExtension-Events/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IndirectDisplays-ClassExtension-Events/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IndirectDisplays-ClassExtension-Events/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IndirectDisplays-ClassExtension-Events/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Input-HIDCLASS-Analytic" /v "OwningPublisher" /t REG_SZ /d "{6465da78-e7a0-4f39-b084-8f53c7c30dc6}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Input-HIDCLASS-Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Input-HIDCLASS-Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Input-HIDCLASS-Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Input-HIDCLASS-Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-InputSwitch/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{bb8e7234-bbf4-48a7-8741-339206ed1dfb}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-InputSwitch/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-InputSwitch/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-InputSwitch/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-InputSwitch/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Iphlpsvc/Debug" /v "OwningPublisher" /t REG_SZ /d "{6600e712-c3b6-44a2-8a48-935c511f28c8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Iphlpsvc/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Iphlpsvc/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Iphlpsvc/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Iphlpsvc/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Iphlpsvc/Debug" /v "Level" /t REG_DWORD /d "255" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Iphlpsvc/Trace" /v "OwningPublisher" /t REG_SZ /d "{6600e712-c3b6-44a2-8a48-935c511f28c8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Iphlpsvc/Trace" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Iphlpsvc/Trace" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Iphlpsvc/Trace" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Iphlpsvc/Trace" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Iphlpsvc/Trace" /v "Level" /t REG_DWORD /d "255" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IPNAT/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{a67075c2-3e39-4109-b6cd-6d750058a732}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IPNAT/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IPNAT/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IPNAT/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IPNAT/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IPSEC-SRV/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{c91ef675-842f-4fcf-a5c9-6ea93f2e4f8b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IPSEC-SRV/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IPSEC-SRV/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IPSEC-SRV/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IPSEC-SRV/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IPxlatCfg/Debug" /v "OwningPublisher" /t REG_SZ /d "{3e5ac668-af52-4c15-b99b-a3e7a6616ebd}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IPxlatCfg/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IPxlatCfg/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IPxlatCfg/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-IPxlatCfg/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kerberos/Operational" /v "OwningPublisher" /t REG_SZ /d "{98e6cfcb-ee0a-41e0-a57b-622d4e1b30b1}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kerberos/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kerberos/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kerberos/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kerberos/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Acpi/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{c514638f-7723-485b-bcfc-96565d735d4a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Acpi/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Acpi/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Acpi/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Acpi/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-AppCompat/General" /v "OwningPublisher" /t REG_SZ /d "{16a1adc1-9b7f-4cd9-94b3-d8296ab1b130}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-AppCompat/General" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-AppCompat/General" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-AppCompat/General" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-AppCompat/General" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-AppCompat/Performance" /v "OwningPublisher" /t REG_SZ /d "{16a1adc1-9b7f-4cd9-94b3-d8296ab1b130}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-AppCompat/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-AppCompat/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-AppCompat/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-AppCompat/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ApphelpCache/Analytic" /v "OwningPublisher" /t REG_SZ /d "{6d8a3a60-40af-445a-98ca-99359e500146}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ApphelpCache/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ApphelpCache/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ApphelpCache/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ApphelpCache/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ApphelpCache/Debug" /v "OwningPublisher" /t REG_SZ /d "{6d8a3a60-40af-445a-98ca-99359e500146}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ApphelpCache/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ApphelpCache/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ApphelpCache/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ApphelpCache/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Boot/Analytic" /v "OwningPublisher" /t REG_SZ /d "{15ca44ff-4d7a-4baa-bba5-0998955e531e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Boot/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Boot/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Boot/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Boot/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-BootDiagnostics/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{96ac7637-5950-4a30-b8f7-e07e8e5734c1}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-BootDiagnostics/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-BootDiagnostics/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-BootDiagnostics/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-BootDiagnostics/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Disk/Analytic" /v "OwningPublisher" /t REG_SZ /d "{c7bde69a-e1e0-4177-b6ef-283ad1525271}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Disk/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Disk/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Disk/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Disk/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-EventTracing/Analytic" /v "OwningPublisher" /t REG_SZ /d "{b675ec37-bdb6-4648-bc92-f3fdc74d3ca2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-EventTracing/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-EventTracing/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-EventTracing/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-EventTracing/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-File/Analytic" /v "OwningPublisher" /t REG_SZ /d "{edd08927-9cc4-4e65-b970-c2560fb5c289}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-File/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-File/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-File/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-File/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Interrupt-Steering/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{951b41ea-c830-44dc-a671-e2c9958809b8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Interrupt-Steering/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Interrupt-Steering/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Interrupt-Steering/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Interrupt-Steering/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-IoTrace/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{a103cabd-8242-4a93-8df5-1cdf3b3f26a6}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-IoTrace/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-IoTrace/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-IoTrace/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-IoTrace/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-LiveDump/Analytic" /v "OwningPublisher" /t REG_SZ /d "{bef2aa8e-81cd-11e2-a7bb-5eac6188709b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-LiveDump/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-LiveDump/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-LiveDump/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-LiveDump/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Memory/Analytic" /v "OwningPublisher" /t REG_SZ /d "{d1d93ef7-e1f2-4f45-9943-03d245fe6c00}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Memory/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Memory/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Memory/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Memory/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Network/Analytic" /v "OwningPublisher" /t REG_SZ /d "{7dd42a49-5329-4832-8dfd-43d979153a88}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Network/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Network/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Network/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Network/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Pdc/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{a6bf0deb-3659-40ad-9f81-e25af62ce3c7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Pdc/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Pdc/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Pdc/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Pdc/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Pep/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{5412704e-b2e1-4624-8ffd-55777b8f7373}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Pep/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Pep/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Pep/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Pep/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Boot Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{9c205a39-1250-487d-abd7-e831c6290539}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Boot Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Boot Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Boot Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Boot Diagnostic" /v "MaxSize" /t REG_DWORD /d "1048576" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Boot Diagnostic" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Boot Diagnostic" /v "Retention" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Boot Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Configuration Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{9c205a39-1250-487d-abd7-e831c6290539}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Configuration Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Configuration Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Configuration Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Configuration Diagnostic" /v "MaxSize" /t REG_DWORD /d "10485760" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Configuration Diagnostic" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Configuration Diagnostic" /v "Retention" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Configuration Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Device Enumeration Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{9c205a39-1250-487d-abd7-e831c6290539}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Device Enumeration Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Device Enumeration Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Device Enumeration Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Device Enumeration Diagnostic" /v "MaxSize" /t REG_DWORD /d "10485760" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Device Enumeration Diagnostic" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Device Enumeration Diagnostic" /v "Retention" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Device Enumeration Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Driver Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{9c205a39-1250-487d-abd7-e831c6290539}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Driver Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Driver Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Driver Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Driver Diagnostic" /v "MaxSize" /t REG_DWORD /d "10485760" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Driver Diagnostic" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Driver Diagnostic" /v "Retention" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-PnP/Driver Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Power/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{331c3b3a-2005-44c2-ac5e-77220c37d6b4}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Power/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Power/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Power/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Power/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Power/Thermal-Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{331c3b3a-2005-44c2-ac5e-77220c37d6b4}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Power/Thermal-Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Power/Thermal-Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Power/Thermal-Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Power/Thermal-Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Prefetch/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{5322d61a-9efa-4bc3-a3f9-14be95c144f8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Prefetch/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Prefetch/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Prefetch/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Prefetch/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Process/Analytic" /v "OwningPublisher" /t REG_SZ /d "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Process/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Process/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Process/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Process/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Processor-Power/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{0f67e49f-fe51-4e9f-b490-6f2948cc6027}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Processor-Power/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Processor-Power/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Processor-Power/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Processor-Power/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Registry/Analytic" /v "OwningPublisher" /t REG_SZ /d "{70eb4f03-c1de-4f73-a051-33d13d5413bd}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Registry/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Registry/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Registry/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Registry/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Registry/Performance" /v "OwningPublisher" /t REG_SZ /d "{70eb4f03-c1de-4f73-a051-33d13d5413bd}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Registry/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Registry/Performance" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Registry/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-Registry/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ShimEngine/Debug" /v "OwningPublisher" /t REG_SZ /d "{0bf2fb94-7b60-4b4d-9766-e82f658df540}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ShimEngine/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ShimEngine/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ShimEngine/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ShimEngine/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ShimEngine/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{0bf2fb94-7b60-4b4d-9766-e82f658df540}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ShimEngine/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ShimEngine/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ShimEngine/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-ShimEngine/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-StoreMgr/Analytic" /v "OwningPublisher" /t REG_SZ /d "{a6ad76e3-867a-4635-91b3-4904ba6374d7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-StoreMgr/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-StoreMgr/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-StoreMgr/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-StoreMgr/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-WDI/Analytic" /v "OwningPublisher" /t REG_SZ /d "{2ff3e6b7-cb90-4700-9621-443f389734ed}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-WDI/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-WDI/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-WDI/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-WDI/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-WDI/Debug" /v "OwningPublisher" /t REG_SZ /d "{2ff3e6b7-cb90-4700-9621-443f389734ed}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-WDI/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-WDI/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-WDI/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-WDI/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-XDV/Analytic" /v "OwningPublisher" /t REG_SZ /d "{f029ac39-38f0-4a40-b7de-404d244004cb}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-XDV/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-XDV/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-XDV/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Kernel-XDV/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-L2NA/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{85fe7609-ff4a-48e9-9d50-12918e43e1da}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-L2NA/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-L2NA/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-L2NA/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-L2NA/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LanguagePackSetup/Analytic" /v "OwningPublisher" /t REG_SZ /d "{7237fff9-a08a-4804-9c79-4a8704b70b87}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LanguagePackSetup/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LanguagePackSetup/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LanguagePackSetup/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LanguagePackSetup/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LanguagePackSetup/Debug" /v "OwningPublisher" /t REG_SZ /d "{7237fff9-a08a-4804-9c79-4a8704b70b87}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LanguagePackSetup/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LanguagePackSetup/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LanguagePackSetup/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LanguagePackSetup/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LDAP-Client/Debug" /v "OwningPublisher" /t REG_SZ /d "{099614a5-5dd7-4788-8bc9-e29f43db28fc}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LDAP-Client/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LDAP-Client/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LDAP-Client/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LDAP-Client/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LimitsManagement/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{73aa0094-facb-4aeb-bd1d-a7b98dd5c799}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LimitsManagement/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LimitsManagement/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LimitsManagement/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LimitsManagement/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LinkLayerDiscoveryProtocol/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{dcbfb8f0-cd19-4f1c-a27d-23ac706ded72}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LinkLayerDiscoveryProtocol/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LinkLayerDiscoveryProtocol/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LinkLayerDiscoveryProtocol/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LinkLayerDiscoveryProtocol/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LinkLayerDiscoveryProtocol/Operational" /v "OwningPublisher" /t REG_SZ /d "{dcbfb8f0-cd19-4f1c-a27d-23ac706ded72}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LinkLayerDiscoveryProtocol/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LinkLayerDiscoveryProtocol/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LinkLayerDiscoveryProtocol/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LinkLayerDiscoveryProtocol/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LiveId/Analytic" /v "OwningPublisher" /t REG_SZ /d "{05f02597-fe85-4e67-8542-69567ab8fd4f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LiveId/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LiveId/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LiveId/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x1SY)(A0x1BA)(A0x1LA)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LiveId/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LSA/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{199fe037-2b82-40a9-82ac-e1d46c792b99}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LSA/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LSA/Diagnostic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LSA/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LSA/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LSA/Operational" /v "OwningPublisher" /t REG_SZ /d "{199fe037-2b82-40a9-82ac-e1d46c792b99}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LSA/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LSA/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LSA/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LSA/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LSA/Performance" /v "OwningPublisher" /t REG_SZ /d "{199fe037-2b82-40a9-82ac-e1d46c792b99}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LSA/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LSA/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LSA/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-LSA/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Media-Streaming/DMC" /v "OwningPublisher" /t REG_SZ /d "{982824e5-e446-46ae-bc74-836401ffb7b6}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Media-Streaming/DMC" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Media-Streaming/DMC" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Media-Streaming/DMC" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Media-Streaming/DMC" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Media-Streaming/DMR" /v "OwningPublisher" /t REG_SZ /d "{982824e5-e446-46ae-bc74-836401ffb7b6}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Media-Streaming/DMR" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Media-Streaming/DMR" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Media-Streaming/DMR" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Media-Streaming/DMR" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Media-Streaming/MDE" /v "OwningPublisher" /t REG_SZ /d "{982824e5-e446-46ae-bc74-836401ffb7b6}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Media-Streaming/MDE" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Media-Streaming/MDE" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Media-Streaming/MDE" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Media-Streaming/MDE" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFCaptureEngine/MFCaptureEngine" /v "OwningPublisher" /t REG_SZ /d "{b8197c10-845f-40ca-82ab-9341e98cfc2b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFCaptureEngine/MFCaptureEngine" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFCaptureEngine/MFCaptureEngine" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFCaptureEngine/MFCaptureEngine" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFCaptureEngine/MFCaptureEngine" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFReadWrite/SinkWriter" /v "OwningPublisher" /t REG_SZ /d "{4b7eac67-fc53-448c-a49d-7cc6db524da7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFReadWrite/SinkWriter" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFReadWrite/SinkWriter" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFReadWrite/SinkWriter" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFReadWrite/SinkWriter" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFReadWrite/SourceReader" /v "OwningPublisher" /t REG_SZ /d "{4b7eac67-fc53-448c-a49d-7cc6db524da7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFReadWrite/SourceReader" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFReadWrite/SourceReader" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFReadWrite/SourceReader" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFReadWrite/SourceReader" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFReadWrite/Transform" /v "OwningPublisher" /t REG_SZ /d "{4b7eac67-fc53-448c-a49d-7cc6db524da7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFReadWrite/Transform" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFReadWrite/Transform" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFReadWrite/Transform" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-MFReadWrite/Transform" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-Performance/SARStreamResource" /v "OwningPublisher" /t REG_SZ /d "{f404b94e-27e0-4384-bfe8-1d8d390b0aa3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-Performance/SARStreamResource" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-Performance/SARStreamResource" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-Performance/SARStreamResource" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-Performance/SARStreamResource" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-PlayAPI/Analytic" /v "OwningPublisher" /t REG_SZ /d "{b65471e1-019d-436f-bc38-e15fa8e87f53}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-PlayAPI/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-PlayAPI/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-PlayAPI/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MediaFoundation-PlayAPI/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Minstore/Analytic" /v "OwningPublisher" /t REG_SZ /d "{55b24b1d-dd9c-44c0-ba77-4f749f1b6976}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Minstore/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Minstore/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Minstore/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Minstore/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Minstore/Debug" /v "OwningPublisher" /t REG_SZ /d "{55b24b1d-dd9c-44c0-ba77-4f749f1b6976}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Minstore/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Minstore/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Minstore/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Minstore/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-Api-Internal/Analytic" /v "OwningPublisher" /t REG_SZ /d "{2aabd03b-f48b-419a-b4ce-7a14403f4a46}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-Api-Internal/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-Api-Internal/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-Api-Internal/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-Api-Internal/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-Api/Analytic" /v "OwningPublisher" /t REG_SZ /d "{2e2bbb16-0c36-4b9b-a567-40924a199fd5}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-Api/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-Api/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-Api/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-Api/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-Parser-Task/Analytic" /v "OwningPublisher" /t REG_SZ /d "{28e25b07-c47f-473d-8b24-2e171cca808a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-Parser-Task/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-Parser-Task/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-Parser-Task/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-Parser-Task/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-SmsApi/Analytic" /v "OwningPublisher" /t REG_SZ /d "{0ff1c24b-7f05-45c0-abdc-3c8521be4f62}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-SmsApi/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-SmsApi/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-SmsApi/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Mobile-Broadband-Experience-SmsApi/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPEG2-Video-Encoder-MFT_Analytic" /v "OwningPublisher" /t REG_SZ /d "{d17b213a-c505-49c9-98cc-734253ef65d4}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPEG2-Video-Encoder-MFT_Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPEG2-Video-Encoder-MFT_Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPEG2-Video-Encoder-MFT_Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPEG2-Video-Encoder-MFT_Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPS-CLNT/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{37945dc2-899b-44d1-b79c-dd4a9e57ff98}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPS-CLNT/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPS-CLNT/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPS-CLNT/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPS-CLNT/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPS-DRV/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{50bd1bfd-936b-4db3-86be-e25b96c25898}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPS-DRV/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPS-DRV/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPS-DRV/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPS-DRV/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPS-SRV/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{5444519f-2484-45a2-991e-953e4b54c8e0}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPS-SRV/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPS-SRV/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPS-SRV/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MPS-SRV/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MSFTEDIT/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{9640427c-7d03-4331-b8ee-fb77625bf381}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MSFTEDIT/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MSFTEDIT/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MSFTEDIT/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MSFTEDIT/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MUI/Analytic" /v "OwningPublisher" /t REG_SZ /d "{a8a1f2f6-a13a-45e9-b1fe-3419569e5ef2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MUI/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MUI/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MUI/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MUI/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MUI/Debug" /v "OwningPublisher" /t REG_SZ /d "{a8a1f2f6-a13a-45e9-b1fe-3419569e5ef2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MUI/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MUI/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MUI/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-MUI/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Narrator/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{835b79e2-e76a-44c4-9885-26ad122d3b4d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Narrator/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Narrator/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Narrator/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Narrator/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Ncasvc/Operational" /v "OwningPublisher" /t REG_SZ /d "{126ded58-a28d-4113-8e7a-59d7444b2af1}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Ncasvc/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Ncasvc/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Ncasvc/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Ncasvc/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NcdAutoSetup/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{ec23f986-ae2d-4269-b52f-4e20765c1a94}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NcdAutoSetup/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NcdAutoSetup/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NcdAutoSetup/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NcdAutoSetup/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NCSI/Analytic" /v "OwningPublisher" /t REG_SZ /d "{314de49f-ce63-4779-ba2b-d616f6963a88}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NCSI/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NCSI/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NCSI/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NCSI/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS-PacketCapture/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{2ed6006e-4729-4609-b423-3ee7bcd678ef}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS-PacketCapture/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS-PacketCapture/Diagnostic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS-PacketCapture/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS-PacketCapture/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS-PacketCapture/Diagnostic" /v "Level" /t REG_DWORD /d "255" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{cdead503-17f5-4a3e-b7ae-df8cc2902eb9}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS/Operational" /v "OwningPublisher" /t REG_SZ /d "{cdead503-17f5-4a3e-b7ae-df8cc2902eb9}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NDIS/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetShell/Performance" /v "OwningPublisher" /t REG_SZ /d "{af2e340c-0743-4f5a-b2d3-2f7225d215de}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetShell/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetShell/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetShell/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetShell/Performance" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Network-and-Sharing-Center/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{6a502821-ab44-40c8-b32f-37315d9d52e0}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Network-and-Sharing-Center/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Network-and-Sharing-Center/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Network-and-Sharing-Center/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Network-and-Sharing-Center/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Network-DataUsage/Analytic" /v "OwningPublisher" /t REG_SZ /d "{5c1c9ab3-8689-4e41-90fa-85858306d7b7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Network-DataUsage/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Network-DataUsage/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Network-DataUsage/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Network-DataUsage/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Network-Setup/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{a111f1c2-5923-47c0-9a68-d0bafb577901}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Network-Setup/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Network-Setup/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Network-Setup/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Network-Setup/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkBridge/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{a67075c2-3e39-4109-b6cd-6d750058a731}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkBridge/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkBridge/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkBridge/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkBridge/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Networking-RealTimeCommunication/Tracing" /v "OwningPublisher" /t REG_SZ /d "{1e39b4ce-d1e6-46ce-b65b-5ab05d6cc266}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Networking-RealTimeCommunication/Tracing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Networking-RealTimeCommunication/Tracing" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Networking-RealTimeCommunication/Tracing" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Networking-RealTimeCommunication/Tracing" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Networking-RealTimeCommunication/Tracing" /v "ClockType" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Networking-RealTimeCommunication/Tracing" /v "Level" /t REG_DWORD /d "255" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkProfile/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{fbcfac3f-8459-419f-8e48-1f0b49cdb85e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkProfile/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkProfile/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkProfile/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkProfile/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkProvisioning/Analytic" /v "OwningPublisher" /t REG_SZ /d "{93a19ab3-fb2c-46eb-91ef-56b0a318b983}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkProvisioning/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkProvisioning/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkProvisioning/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkProvisioning/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkSecurity/Debug" /v "OwningPublisher" /t REG_SZ /d "{7b702970-90bc-4584-8b20-c0799086ee5a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkSecurity/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkSecurity/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkSecurity/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkSecurity/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkStatus/Analytic" /v "OwningPublisher" /t REG_SZ /d "{7868b0d4-1423-4681-afdf-27913575441e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkStatus/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkStatus/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkStatus/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NetworkStatus/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NlaSvc/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{63b530f8-29c9-4880-a5b4-b8179096e7b8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NlaSvc/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NlaSvc/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NlaSvc/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NlaSvc/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Ntfs/Performance" /v "OwningPublisher" /t REG_SZ /d "{3ff37a1c-a68d-4d6e-8c9b-f79e8b16c482}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Ntfs/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Ntfs/Performance" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Ntfs/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Ntfs/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ntshrui" /v "OwningPublisher" /t REG_SZ /d "{676f167f-f72c-446e-a498-eda43319a5e3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ntshrui" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ntshrui" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ntshrui" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ntshrui" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ntshrui-perf" /v "OwningPublisher" /t REG_SZ /d "{676f167f-f72c-446e-a498-eda43319a5e3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ntshrui-perf" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ntshrui-perf" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ntshrui-perf" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ntshrui-perf" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NWiFi/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{0bd3506a-9030-4f76-9b88-3e8fe1f7cfb6}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NWiFi/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NWiFi/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NWiFi/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-NWiFi/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OLE/Clipboard-Performance" /v "OwningPublisher" /t REG_SZ /d "{84958368-7da7-49a0-b33d-07fabb879626}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OLE/Clipboard-Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OLE/Clipboard-Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OLE/Clipboard-Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OLE/Clipboard-Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OLEACC/Debug" /v "OwningPublisher" /t REG_SZ /d "{19d2c934-ee9b-49e5-aaeb-9cce721d2c65}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OLEACC/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OLEACC/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OLEACC/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OLEACC/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OLEACC/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{19d2c934-ee9b-49e5-aaeb-9cce721d2c65}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OLEACC/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OLEACC/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OLEACC/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OLEACC/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OneX/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{ab0d8ef9-866d-4d39-b83f-453f3b8f6325}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OneX/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OneX/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OneX/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OneX/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OneX/Operational" /v "OwningPublisher" /t REG_SZ /d "{ab0d8ef9-866d-4d39-b83f-453f3b8f6325}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OneX/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OneX/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OneX/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OneX/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-FirstLogonAnim/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{2d4c0c5e-6704-493a-a44b-f5add4fc9283}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-FirstLogonAnim/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-FirstLogonAnim/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-FirstLogonAnim/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-FirstLogonAnim/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-Machine-Core/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{ec276cde-2a17-473c-a010-2ff78d5426d2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-Machine-Core/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-Machine-Core/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-Machine-Core/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-Machine-Core/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-Machine-DUI/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{f5dbaa02-15d6-4644-a784-7032d508bf64}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-Machine-DUI/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-Machine-DUI/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-Machine-DUI/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-Machine-DUI/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-Machine-Plugins-Wireless/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{0f352580-e9e2-46c2-8336-6ac66e986416}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-Machine-Plugins-Wireless/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-Machine-Plugins-Wireless/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-Machine-Plugins-Wireless/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OOBE-Machine-Plugins-Wireless/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OobeLdr/Analytic" /v "OwningPublisher" /t REG_SZ /d "{75ebc33e-8670-4eb6-b535-3b9d6bb222fd}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OobeLdr/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OobeLdr/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OobeLdr/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OobeLdr/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-osk/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{4f768be8-9c69-4bbc-87fc-95291d3f9d0c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-osk/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-osk/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-osk/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-osk/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational" /v "OwningPublisher" /t REG_SZ /d "{5cad485a-210f-4c16-80c5-f892de74e28d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-OtpCredentialProvider/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PackageStateRoaming/Analytic" /v "OwningPublisher" /t REG_SZ /d "{5b5ab841-7d2e-4a95-bb4f-095cdf66d8f0}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PackageStateRoaming/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PackageStateRoaming/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PackageStateRoaming/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PackageStateRoaming/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PackageStateRoaming/Debug" /v "OwningPublisher" /t REG_SZ /d "{5b5ab841-7d2e-4a95-bb4f-095cdf66d8f0}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PackageStateRoaming/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PackageStateRoaming/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PackageStateRoaming/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PackageStateRoaming/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Partition/Analytic" /v "OwningPublisher" /t REG_SZ /d "{412bdff2-a8c4-470d-8f33-63fe0d8c20e2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Partition/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Partition/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Partition/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Partition/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PCI/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{1a9443d4-b099-44d6-8eb1-829b9c2fe290}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PCI/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PCI/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PCI/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PCI/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PeerToPeerDrtEventProvider/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{40ae003c-6f3d-4590-ae1c-0e8be526b50f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PeerToPeerDrtEventProvider/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PeerToPeerDrtEventProvider/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PeerToPeerDrtEventProvider/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PeerToPeerDrtEventProvider/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-Nvdimm/Analytic" /v "OwningPublisher" /t REG_SZ /d "{a7f2235f-be51-51ed-decf-f4498812a9a2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-Nvdimm/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-Nvdimm/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-Nvdimm/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-Nvdimm/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-Nvdimm/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{a7f2235f-be51-51ed-decf-f4498812a9a2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-Nvdimm/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-Nvdimm/Diagnostic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-Nvdimm/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-Nvdimm/Diagnostic" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-PmemDisk/Analytic" /v "OwningPublisher" /t REG_SZ /d "{0fa2ee03-1feb-5057-3bb3-eb25521b8482}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-PmemDisk/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-PmemDisk/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-PmemDisk/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-PmemDisk/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-PmemDisk/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{0fa2ee03-1feb-5057-3bb3-eb25521b8482}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-PmemDisk/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-PmemDisk/Diagnostic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-PmemDisk/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-PmemDisk/Diagnostic" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-ScmBus/Analytic" /v "OwningPublisher" /t REG_SZ /d "{c03715ce-ea6f-5b67-4449-da1d1e1afeb8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-ScmBus/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-ScmBus/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-ScmBus/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-ScmBus/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-ScmBus/Diagnose" /v "OwningPublisher" /t REG_SZ /d "{c03715ce-ea6f-5b67-4449-da1d1e1afeb8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-ScmBus/Diagnose" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-ScmBus/Diagnose" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-ScmBus/Diagnose" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PersistentMemory-ScmBus/Diagnose" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PhotoAcq/Analytic" /v "OwningPublisher" /t REG_SZ /d "{76cfa528-b26e-b773-62d0-9588270442a6}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PhotoAcq/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PhotoAcq/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PhotoAcq/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PhotoAcq/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PlayToManager/Analytic" /v "OwningPublisher" /t REG_SZ /d "{bb311100-2d9f-4cd3-b2d6-f4ea3839c548}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PlayToManager/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PlayToManager/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PlayToManager/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PlayToManager/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Policy/Analytic" /v "OwningPublisher" /t REG_SZ /d "{54cb22ff-26b4-4393-a8c2-6b0715912c5f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Policy/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Policy/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Policy/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Policy/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Policy/Analytic" /v "Level" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PortableDeviceStatusProvider/Analytic" /v "OwningPublisher" /t REG_SZ /d "{8c63b5a5-b484-4381-892d-edd424582df7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PortableDeviceStatusProvider/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PortableDeviceStatusProvider/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PortableDeviceStatusProvider/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PortableDeviceStatusProvider/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PortableDeviceSyncProvider/Analytic" /v "OwningPublisher" /t REG_SZ /d "{a3e1697b-a12c-46b9-84d1-7ffe73c4b678}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PortableDeviceSyncProvider/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PortableDeviceSyncProvider/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PortableDeviceSyncProvider/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PortableDeviceSyncProvider/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Power-Meter-Polling/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{306c4e0b-e148-543d-315b-c618eb93157c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Power-Meter-Polling/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Power-Meter-Polling/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Power-Meter-Polling/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Power-Meter-Polling/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerCfg/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{9f0c4ea8-ec01-4200-a00d-b9701cbea5d8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerCfg/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerCfg/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerCfg/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerCfg/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerCpl/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{b1f90b27-4551-49d6-b2bd-dfc6453762a6}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerCpl/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerCpl/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerCpl/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerCpl/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Analytic" /v "OwningPublisher" /t REG_SZ /d "{aaf67066-0bf8-469f-ab76-275590c434ee}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Debug" /v "OwningPublisher" /t REG_SZ /d "{aaf67066-0bf8-469f-ab76-275590c434ee}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Analytic" /v "OwningPublisher" /t REG_SZ /d "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Analytic" /v "MaxSize" /t REG_DWORD /d "1048985600" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Analytic" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Analytic" /v "Retention" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Analytic" /v "BufferSize" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Debug" /v "OwningPublisher" /t REG_SZ /d "{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Debug" /v "MaxSize" /t REG_DWORD /d "1048985600" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Debug" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Debug" /v "Retention" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PowerShell/Debug" /v "BufferSize" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrimaryNetworkIcon/Performance" /v "OwningPublisher" /t REG_SZ /d "{8ce93926-bdae-4409-9155-2fe4799ef4d3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrimaryNetworkIcon/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrimaryNetworkIcon/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrimaryNetworkIcon/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrimaryNetworkIcon/Performance" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintBRM/Admin" /v "OwningPublisher" /t REG_SZ /d "{cf3f502e-b40d-4071-996f-00981edf938e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintBRM/Admin" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintBRM/Admin" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintBRM/Admin" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintBRM/Admin" /v "Type" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService-USBMon/Debug" /v "OwningPublisher" /t REG_SZ /d "{7f812073-b28d-4afc-9ced-b8010f914ef6}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService-USBMon/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService-USBMon/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService-USBMon/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService-USBMon/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Admin" /v "OwningPublisher" /t REG_SZ /d "{747ef6fd-e535-4d16-b510-42c90f6873a1}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Admin" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Admin" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Admin" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Admin" /v "Type" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Debug" /v "OwningPublisher" /t REG_SZ /d "{747ef6fd-e535-4d16-b510-42c90f6873a1}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Operational" /v "OwningPublisher" /t REG_SZ /d "{747ef6fd-e535-4d16-b510-42c90f6873a1}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-PrintService/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ProcessStateManager/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{d49918cf-9489-4bf1-9d7b-014d864cf71f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ProcessStateManager/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ProcessStateManager/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ProcessStateManager/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ProcessStateManager/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Program-Compatibility-Assistant/Analytic" /v "OwningPublisher" /t REG_SZ /d "{4cb314df-c11f-47d7-9c04-65fb0051561b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Program-Compatibility-Assistant/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Program-Compatibility-Assistant/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Program-Compatibility-Assistant/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Program-Compatibility-Assistant/Analytic" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Provisioning-Diagnostics-Provider/Debug" /v "OwningPublisher" /t REG_SZ /d "{ed8b9bd3-f66e-4ff2-b86b-75c7925f72a9}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Provisioning-Diagnostics-Provider/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Provisioning-Diagnostics-Provider/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Provisioning-Diagnostics-Provider/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Provisioning-Diagnostics-Provider/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Proximity-Common/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{28058203-d394-4afc-b2a6-2f9155a3bb95}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Proximity-Common/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Proximity-Common/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Proximity-Common/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Proximity-Common/Diagnostic" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Proximity-Common/Informational" /v "OwningPublisher" /t REG_SZ /d "{28058203-d394-4afc-b2a6-2f9155a3bb95}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Proximity-Common/Informational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Proximity-Common/Informational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Proximity-Common/Informational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Proximity-Common/Informational" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Proximity-Common/Performance" /v "OwningPublisher" /t REG_SZ /d "{28058203-d394-4afc-b2a6-2f9155a3bb95}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Proximity-Common/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Proximity-Common/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Proximity-Common/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Proximity-Common/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-QoS-Pacer/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{914ed502-b70d-4add-b758-95692854f8a3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-QoS-Pacer/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-QoS-Pacer/Diagnostic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-QoS-Pacer/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-QoS-Pacer/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-QoS-Pacer/Diagnostic" /v "Level" /t REG_DWORD /d "255" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-QoS-qWAVE/Debug" /v "OwningPublisher" /t REG_SZ /d "{6ba132c4-da49-415b-a7f4-31870dc9fe25}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-QoS-qWAVE/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-QoS-qWAVE/Debug" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-QoS-qWAVE/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-QoS-qWAVE/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RadioManager/Analytic" /v "OwningPublisher" /t REG_SZ /d "{92061e3d-21cd-45bc-a3df-0e8ae5e8580a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RadioManager/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RadioManager/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RadioManager/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RadioManager/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RasAgileVpn/Debug" /v "OwningPublisher" /t REG_SZ /d "{b5325cd6-438e-4ec1-aa46-14f46f2570e4}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RasAgileVpn/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RasAgileVpn/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RasAgileVpn/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RasAgileVpn/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RasAgileVpn/Debug" /v "Level" /t REG_DWORD /d "255" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RasAgileVpn/Operational" /v "OwningPublisher" /t REG_SZ /d "{b5325cd6-438e-4ec1-aa46-14f46f2570e4}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RasAgileVpn/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RasAgileVpn/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RasAgileVpn/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RasAgileVpn/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Remotefs-Rdbss/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{1a870028-f191-4699-8473-6fcd299eab77}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Remotefs-Rdbss/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Remotefs-Rdbss/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Remotefs-Rdbss/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Remotefs-Rdbss/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Remotefs-Rdbss/Operational" /v "OwningPublisher" /t REG_SZ /d "{1a870028-f191-4699-8473-6fcd299eab77}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Remotefs-Rdbss/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Remotefs-Rdbss/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Remotefs-Rdbss/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Remotefs-Rdbss/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ResetEng-Trace/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{7fa514b5-a023-4b62-a6ab-2946a483e065}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ResetEng-Trace/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ResetEng-Trace/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ResetEng-Trace/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ResetEng-Trace/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ResourcePublication/Tracing" /v "OwningPublisher" /t REG_SZ /d "{74c2135f-cc76-45c3-879a-ef3bb1eeaf86}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ResourcePublication/Tracing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ResourcePublication/Tracing" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ResourcePublication/Tracing" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ResourcePublication/Tracing" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RPC-Proxy/Debug" /v "OwningPublisher" /t REG_SZ /d "{272a979b-34b5-48ec-94f5-7225a59c85a0}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RPC-Proxy/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RPC-Proxy/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RPC-Proxy/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RPC-Proxy/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RPC/Debug" /v "OwningPublisher" /t REG_SZ /d "{6ad52b32-d609-4be9-ae07-ce8dae937e39}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RPC/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RPC/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RPC/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RPC/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RPC/EEInfo" /v "OwningPublisher" /t REG_SZ /d "{6ad52b32-d609-4be9-ae07-ce8dae937e39}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RPC/EEInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RPC/EEInfo" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RPC/EEInfo" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RPC/EEInfo" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RRAS/Debug" /v "OwningPublisher" /t REG_SZ /d "{24989972-0967-4e21-a926-93854033638e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RRAS/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RRAS/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RRAS/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RRAS/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RRAS/Debug" /v "Level" /t REG_DWORD /d "255" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RRAS/Operational" /v "OwningPublisher" /t REG_SZ /d "{24989972-0967-4e21-a926-93854033638e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RRAS/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RRAS/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RRAS/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-RRAS/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Graphics/Analytic" /v "OwningPublisher" /t REG_SZ /d "{fa5cf675-72eb-49e2-b447-de5552faff1c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Graphics/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Graphics/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Graphics/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Graphics/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Networking/Tracing" /v "OwningPublisher" /t REG_SZ /d "{6eb875eb-8f4a-4800-a00b-e484c97d7561}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Networking/Tracing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Networking/Tracing" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Networking/Tracing" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Networking/Tracing" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Networking/Tracing" /v "ClockType" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Web-Http/Tracing" /v "OwningPublisher" /t REG_SZ /d "{41877cb4-11fc-4188-b590-712c143c881d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Web-Http/Tracing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Web-Http/Tracing" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Web-Http/Tracing" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Web-Http/Tracing" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Web-Http/Tracing" /v "BufferSize" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-WebAPI/Tracing" /v "OwningPublisher" /t REG_SZ /d "{6bd96334-dc49-441a-b9c4-41425ba628d8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-WebAPI/Tracing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-WebAPI/Tracing" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-WebAPI/Tracing" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-WebAPI/Tracing" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-WebAPI/Tracing" /v "BufferSize" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTAdaptiveMediaSource" /v "OwningPublisher" /t REG_SZ /d "{8f0db3a8-299b-4d64-a4ed-907b409d4584}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTAdaptiveMediaSource" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTAdaptiveMediaSource" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTAdaptiveMediaSource" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTAdaptiveMediaSource" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTCaptureEngine" /v "OwningPublisher" /t REG_SZ /d "{8f0db3a8-299b-4d64-a4ed-907b409d4584}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTCaptureEngine" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTCaptureEngine" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTCaptureEngine" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTCaptureEngine" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTMediaStreamSource" /v "OwningPublisher" /t REG_SZ /d "{8f0db3a8-299b-4d64-a4ed-907b409d4584}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTMediaStreamSource" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTMediaStreamSource" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTMediaStreamSource" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTMediaStreamSource" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTTranscode" /v "OwningPublisher" /t REG_SZ /d "{8f0db3a8-299b-4d64-a4ed-907b409d4584}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTTranscode" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTTranscode" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTTranscode" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime-Windows-Media/WinRTTranscode" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime/CreateInstance" /v "OwningPublisher" /t REG_SZ /d "{b8d6861b-d20f-4eec-bbae-87e0dd80602b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime/CreateInstance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime/CreateInstance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime/CreateInstance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime/CreateInstance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime/Error" /v "OwningPublisher" /t REG_SZ /d "{a86f8471-c31d-4fbc-a035-665d06047b03}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime/Error" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime/Error" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime/Error" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Runtime/Error" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Schannel-Events/Perf" /v "OwningPublisher" /t REG_SZ /d "{91cc1150-71aa-47e2-ae18-c96e61736b6f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Schannel-Events/Perf" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Schannel-Events/Perf" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Schannel-Events/Perf" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Schannel-Events/Perf" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sdbus/Analytic" /v "OwningPublisher" /t REG_SZ /d "{fe28004e-b08f-4407-92b3-bad3a2c51708}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sdbus/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sdbus/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sdbus/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sdbus/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sdbus/Debug" /v "OwningPublisher" /t REG_SZ /d "{fe28004e-b08f-4407-92b3-bad3a2c51708}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sdbus/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sdbus/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sdbus/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sdbus/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sdstor/Analytic" /v "OwningPublisher" /t REG_SZ /d "{afe654eb-0a83-4eb4-948f-d4510ec39c30}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sdstor/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sdstor/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sdstor/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sdstor/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Search-Core/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{49c2c27c-fe2d-40bf-8c4e-c3fb518037e7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Search-Core/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Search-Core/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Search-Core/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Search-Core/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Search-ProtocolHandlers/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{dab065a9-620f-45ba-b5d6-d6bb8efedee9}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Search-ProtocolHandlers/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Search-ProtocolHandlers/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Search-ProtocolHandlers/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Search-ProtocolHandlers/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SearchUI/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{d8965fcf-7397-4e0e-b750-21a4580bd880}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SearchUI/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SearchUI/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SearchUI/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SearchUI/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-Adminless/Operational" /v "OwningPublisher" /t REG_SZ /d "{ea216962-877b-5b73-f7c5-8aef5375959e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-Adminless/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-Adminless/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-Adminless/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-Adminless/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-Audit-Configuration-Client/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{08466062-aed4-4834-8b04-cddb414504e5}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-Audit-Configuration-Client/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-Audit-Configuration-Client/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-Audit-Configuration-Client/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-Audit-Configuration-Client/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-EnterpriseData-FileRevocationManager/Operational" /v "OwningPublisher" /t REG_SZ /d "{2cd58181-0bb6-463e-828a-056ff837f966}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-EnterpriseData-FileRevocationManager/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-EnterpriseData-FileRevocationManager/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-EnterpriseData-FileRevocationManager/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-EnterpriseData-FileRevocationManager/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-ExchangeActiveSyncProvisioning/Operational" /v "OwningPublisher" /t REG_SZ /d "{9249d0d0-f034-402f-a29b-92fa8853d9f3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-ExchangeActiveSyncProvisioning/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-ExchangeActiveSyncProvisioning/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-ExchangeActiveSyncProvisioning/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-ExchangeActiveSyncProvisioning/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-ExchangeActiveSyncProvisioning/Performance" /v "OwningPublisher" /t REG_SZ /d "{9249d0d0-f034-402f-a29b-92fa8853d9f3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-ExchangeActiveSyncProvisioning/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-ExchangeActiveSyncProvisioning/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-ExchangeActiveSyncProvisioning/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-ExchangeActiveSyncProvisioning/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-IdentityListener/Operational" /v "OwningPublisher" /t REG_SZ /d "{3c6c422b-019b-4f48-b67b-f79a3fa8b4ed}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-IdentityListener/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-IdentityListener/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-IdentityListener/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-IdentityListener/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-IdentityStore/Performance" /v "OwningPublisher" /t REG_SZ /d "{00b7e1df-b469-4c69-9c41-53a6576e3dad}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-IdentityStore/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-IdentityStore/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-IdentityStore/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-IdentityStore/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-LessPrivilegedAppContainer/Operational" /v "OwningPublisher" /t REG_SZ /d "{45eec9e5-4a1b-5446-7ad8-a4ab1313c437}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-LessPrivilegedAppContainer/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-LessPrivilegedAppContainer/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-LessPrivilegedAppContainer/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-LessPrivilegedAppContainer/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX-GC/Analytic" /v "OwningPublisher" /t REG_SZ /d "{bbbdd6a3-f35e-449b-a471-4d830c8eda1f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX-GC/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX-GC/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX-GC/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX-GC/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX-GenuineCenter-Logging/Operational" /v "OwningPublisher" /t REG_SZ /d "{fb829150-cd7d-44c3-af5b-711a3c31cedc}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX-GenuineCenter-Logging/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX-GenuineCenter-Logging/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX-GenuineCenter-Logging/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX-GenuineCenter-Logging/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX-Notifications/ActionCenter" /v "OwningPublisher" /t REG_SZ /d "{c4efc9bb-2570-4821-8923-1bad317d2d4b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX-Notifications/ActionCenter" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX-Notifications/ActionCenter" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX-Notifications/ActionCenter" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX-Notifications/ActionCenter" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX/Analytic" /v "OwningPublisher" /t REG_SZ /d "{6bdadc96-673e-468c-9f5b-f382f95b2832}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP-UX/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP/Perf" /v "OwningPublisher" /t REG_SZ /d "{e23b33b0-c8c9-472c-a5f9-f2bdfea0f156}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP/Perf" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP/Perf" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP/Perf" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-SPP/Perf" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-UserConsentVerifier/Audit" /v "OwningPublisher" /t REG_SZ /d "{40783728-8921-45d0-b231-919037b4b4fd}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-UserConsentVerifier/Audit" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-UserConsentVerifier/Audit" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-UserConsentVerifier/Audit" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Security-UserConsentVerifier/Audit" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SecurityMitigationsBroker/Admin" /v "OwningPublisher" /t REG_SZ /d "{ea8cd8a5-78ff-4418-b292-aadc6a7181df}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SecurityMitigationsBroker/Admin" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SecurityMitigationsBroker/Admin" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SecurityMitigationsBroker/Admin" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SecurityMitigationsBroker/Admin" /v "Type" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SecurityMitigationsBroker/Perf" /v "OwningPublisher" /t REG_SZ /d "{ea8cd8a5-78ff-4418-b292-aadc6a7181df}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SecurityMitigationsBroker/Perf" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SecurityMitigationsBroker/Perf" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SecurityMitigationsBroker/Perf" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SecurityMitigationsBroker/Perf" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sens/Debug" /v "OwningPublisher" /t REG_SZ /d "{be69781c-b63b-41a1-8e24-a4fc7b3fc498}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sens/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sens/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sens/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sens/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sens/Debug" /v "Level" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sens/Debug" /v "KeywordsLower" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sens/Debug" /v "KeywordsUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sens/Debug" /v "ControlGuid" /t REG_SZ /d "{a0ca1d82-539d-4fb0-944b-1620c6e86231}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Serial-ClassExtension-V2/Analytic" /v "OwningPublisher" /t REG_SZ /d "{eee173ef-7ed2-45de-9877-01c70a852fbd}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Serial-ClassExtension-V2/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Serial-ClassExtension-V2/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Serial-ClassExtension-V2/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Serial-ClassExtension-V2/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Serial-ClassExtension/Analytic" /v "OwningPublisher" /t REG_SZ /d "{47bc9477-a8ba-452e-b951-4f2ed3593cf9}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Serial-ClassExtension/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Serial-ClassExtension/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Serial-ClassExtension/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Serial-ClassExtension/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ServiceReportingApi/Debug" /v "OwningPublisher" /t REG_SZ /d "{606a6a38-70ec-4309-b3a3-82ff86f73329}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ServiceReportingApi/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ServiceReportingApi/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ServiceReportingApi/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ServiceReportingApi/Debug" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Services-Svchost/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{06184c97-5201-480e-92af-3a3626c5b140}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Services-Svchost/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Services-Svchost/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Services-Svchost/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Services-Svchost/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Services/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{0063715b-eeda-4007-9429-ad526f62696e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Services/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Services/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Services/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Services/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Servicing/Debug" /v "OwningPublisher" /t REG_SZ /d "{bd12f3b8-fc40-4a61-a307-b7a013a069c1}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Servicing/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Servicing/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Servicing/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Servicing/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Setup/Analytic" /v "OwningPublisher" /t REG_SZ /d "{75ebc33e-997f-49cf-b49f-ecc50184b75d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Setup/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Setup/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Setup/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Setup/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupCl/Analytic" /v "OwningPublisher" /t REG_SZ /d "{75ebc33e-d017-4d0f-93ab-0b4f86579164}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupCl/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupCl/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupCl/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupCl/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupPlatform/Analytic" /v "OwningPublisher" /t REG_SZ /d "{530fb9b9-c515-4472-9313-fb346f9255e3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupPlatform/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupPlatform/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupPlatform/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupPlatform/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupQueue/Analytic" /v "OwningPublisher" /t REG_SZ /d "{a615acb9-d5a4-4738-b561-1df301d207f8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupQueue/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupQueue/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupQueue/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupQueue/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupUGC/Analytic" /v "OwningPublisher" /t REG_SZ /d "{75ebc33e-0870-49e5-bdce-9d7028279489}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupUGC/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupUGC/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupUGC/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SetupUGC/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ShareMedia-ControlPanel/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{02012a8a-adf5-4fab-92cb-ccb7bb3e689a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ShareMedia-ControlPanel/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ShareMedia-ControlPanel/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ShareMedia-ControlPanel/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ShareMedia-ControlPanel/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AppWizCpl/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{08d945eb-c8bd-44aa-994f-86079d8dce35}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AppWizCpl/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AppWizCpl/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AppWizCpl/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AppWizCpl/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-BootAnim/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{63d2bb1d-e39a-41b8-9a3d-52dd06677588}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-BootAnim/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-BootAnim/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-BootAnim/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-BootAnim/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-Common/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{63d2bb1d-e39a-41b8-9a3d-52dd06677588}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-Common/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-Common/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-Common/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-Common/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-CredentialProviderUser/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{63d2bb1d-e39a-41b8-9a3d-52dd06677588}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-CredentialProviderUser/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-CredentialProviderUser/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-CredentialProviderUser/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-CredentialProviderUser/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-CredUI/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{63d2bb1d-e39a-41b8-9a3d-52dd06677588}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-CredUI/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-CredUI/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-CredUI/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-CredUI/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-Logon/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{63d2bb1d-e39a-41b8-9a3d-52dd06677588}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-Logon/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-Logon/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-Logon/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-Logon/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-LogonUI/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{63d2bb1d-e39a-41b8-9a3d-52dd06677588}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-LogonUI/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-LogonUI/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-LogonUI/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-LogonUI/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-Shutdown/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{63d2bb1d-e39a-41b8-9a3d-52dd06677588}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-Shutdown/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-Shutdown/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-Shutdown/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-AuthUI-Shutdown/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-DefaultPrograms/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{65d99466-7a8e-489c-b8e1-962bc945031e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-DefaultPrograms/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-DefaultPrograms/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-DefaultPrograms/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-DefaultPrograms/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-LockScreenContent/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{a3c0d58a-9fe5-4f24-a2ce-e16de8baa0d2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-LockScreenContent/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-LockScreenContent/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-LockScreenContent/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-LockScreenContent/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-OpenWith/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{11bd2a68-77ff-4991-9658-f451f2eb6ce1}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-OpenWith/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-OpenWith/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-OpenWith/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-OpenWith/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-Shwebsvc" /v "OwningPublisher" /t REG_SZ /d "{f61cefc0-aa2e-11da-a746-0800200c9a66}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-Shwebsvc" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-Shwebsvc" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-Shwebsvc" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Shell-Shwebsvc" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ShellCommon-StartLayoutPopulation/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{97ca8142-10b1-4baa-9fbb-70a7d11231c3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ShellCommon-StartLayoutPopulation/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ShellCommon-StartLayoutPopulation/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ShellCommon-StartLayoutPopulation/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ShellCommon-StartLayoutPopulation/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ShellCommon-StartLayoutPopulation/Operational" /v "OwningPublisher" /t REG_SZ /d "{97ca8142-10b1-4baa-9fbb-70a7d11231c3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ShellCommon-StartLayoutPopulation/Operational" /v "Enabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ShellCommon-StartLayoutPopulation/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ShellCommon-StartLayoutPopulation/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ShellCommon-StartLayoutPopulation/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SleepStudy/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{d37687e7-8bf0-4d11-b589-a7abe080756a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SleepStudy/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SleepStudy/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SleepStudy/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SleepStudy/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-Audit/Authentication" /v "OwningPublisher" /t REG_SZ /d "{09ac07b9-6ac9-43bc-a50f-58419a797c69}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-Audit/Authentication" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-Audit/Authentication" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-Audit/Authentication" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-Audit/Authentication" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-DeviceEnum/Operational" /v "OwningPublisher" /t REG_SZ /d "{aaeac398-3028-487c-9586-44eacad03637}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-DeviceEnum/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-DeviceEnum/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-DeviceEnum/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-DeviceEnum/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-TPM-VCard-Module/Admin" /v "OwningPublisher" /t REG_SZ /d "{125f2cf1-2768-4d33-976e-527137d080f8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-TPM-VCard-Module/Admin" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-TPM-VCard-Module/Admin" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-TPM-VCard-Module/Admin" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-TPM-VCard-Module/Admin" /v "Type" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-TPM-VCard-Module/Operational" /v "OwningPublisher" /t REG_SZ /d "{125f2cf1-2768-4d33-976e-527137d080f8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-TPM-VCard-Module/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-TPM-VCard-Module/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-TPM-VCard-Module/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmartCard-TPM-VCard-Module/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/Analytic" /v "OwningPublisher" /t REG_SZ /d "{988c59c5-0a1c-45b6-a555-0c62276e327d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/Analytic" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(D0xf0007AN)(D0xf0007BG)(A0x7SY)(A0x7BA)(A0x2WD)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmbClient/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{988c59c5-0a1c-45b6-a555-0c62276e327d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmbClient/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmbClient/Diagnostic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmbClient/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SmbClient/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/HelperClassDiagnostic" /v "OwningPublisher" /t REG_SZ /d "{988c59c5-0a1c-45b6-a555-0c62276e327d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/HelperClassDiagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/HelperClassDiagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/HelperClassDiagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/HelperClassDiagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/ObjectStateDiagnostic" /v "OwningPublisher" /t REG_SZ /d "{988c59c5-0a1c-45b6-a555-0c62276e327d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/ObjectStateDiagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/ObjectStateDiagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/ObjectStateDiagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/ObjectStateDiagnostic" /v "MaxSize" /t REG_DWORD /d "536870912" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/ObjectStateDiagnostic" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/ObjectStateDiagnostic" /v "Retention" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/ObjectStateDiagnostic" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/ObjectStateDiagnostic" /v "BufferSize" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBClient/ObjectStateDiagnostic" /v "ClockType" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Debug" /v "OwningPublisher" /t REG_SZ /d "{db66ea65-b7bb-4ca9-8748-334cb5c32400}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Debug" /v "MaxSize" /t REG_DWORD /d "104857600" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Debug" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Debug" /v "Retention" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Debug" /v "BufferSize" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Debug" /v "ClockType" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Debug" /v "Level" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Netmon" /v "OwningPublisher" /t REG_SZ /d "{db66ea65-b7bb-4ca9-8748-334cb5c32400}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Netmon" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Netmon" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Netmon" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Netmon" /v "MaxSize" /t REG_DWORD /d "104857600" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Netmon" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Netmon" /v "Retention" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Netmon" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Netmon" /v "BufferSize" /t REG_DWORD /d "65536" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Netmon" /v "ClockType" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBDirect/Netmon" /v "Level" /t REG_DWORD /d "255" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBServer/Analytic" /v "OwningPublisher" /t REG_SZ /d "{d48ce617-33a2-4bc3-a5c7-11aa4f29619e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBServer/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBServer/Analytic" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBServer/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(D0xf0007AN)(D0xf0007BG)(A0x7SY)(A0x7BA)(A0x2WD)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBServer/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBServer/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{d48ce617-33a2-4bc3-a5c7-11aa4f29619e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBServer/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBServer/Diagnostic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBServer/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBServer/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBServer/Performance" /v "OwningPublisher" /t REG_SZ /d "{d48ce617-33a2-4bc3-a5c7-11aa4f29619e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBServer/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBServer/Performance" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBServer/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(D0xf0007AN)(D0xf0007BG)(A0x7SY)(A0x7BA)(A0x2WD)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SMBServer/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SPB-ClassExtension/Analytic" /v "OwningPublisher" /t REG_SZ /d "{72cd9ff7-4af8-4b89-aede-5f26fda13567}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SPB-ClassExtension/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SPB-ClassExtension/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SPB-ClassExtension/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SPB-ClassExtension/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SPB-HIDI2C/Analytic" /v "OwningPublisher" /t REG_SZ /d "{991f8fe6-249d-44d6-b93d-5a3060c1dedb}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SPB-HIDI2C/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SPB-HIDI2C/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SPB-HIDI2C/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SPB-HIDI2C/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Spell-Checking/Analytic" /v "OwningPublisher" /t REG_SZ /d "{d0e22efc-ac66-4b25-a72d-382736b5e940}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Spell-Checking/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Spell-Checking/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Spell-Checking/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Spell-Checking/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SpellChecker/Analytic" /v "OwningPublisher" /t REG_SZ /d "{b2fcd41f-9a40-4150-8c92-b224b7d8c8aa}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SpellChecker/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SpellChecker/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SpellChecker/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SpellChecker/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Spellchecking-Host/Analytic" /v "OwningPublisher" /t REG_SZ /d "{1bda2ab1-bbc1-4acb-a849-c0ef2b249672}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Spellchecking-Host/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Spellchecking-Host/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Spellchecking-Host/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Spellchecking-Host/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StateRepository/Debug" /v "OwningPublisher" /t REG_SZ /d "{89592015-d996-4636-8f61-066b5d4dd739}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StateRepository/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StateRepository/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StateRepository/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StateRepository/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StateRepository/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{89592015-d996-4636-8f61-066b5d4dd739}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StateRepository/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StateRepository/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StateRepository/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StateRepository/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-stobject/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{86133982-63d7-4741-928e-ef1349b80219}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-stobject/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-stobject/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-stobject/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-stobject/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Admin" /v "OwningPublisher" /t REG_SZ /d "{cb587ad1-cc35-4ef1-ad93-36cc82a2d319}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Admin" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Admin" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Admin" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Admin" /v "Type" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Analytic" /v "OwningPublisher" /t REG_SZ /d "{cb587ad1-cc35-4ef1-ad93-36cc82a2d319}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Debug" /v "OwningPublisher" /t REG_SZ /d "{cb587ad1-cc35-4ef1-ad93-36cc82a2d319}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Diagnose" /v "OwningPublisher" /t REG_SZ /d "{cb587ad1-cc35-4ef1-ad93-36cc82a2d319}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Diagnose" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Diagnose" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Diagnose" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Diagnose" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Operational" /v "OwningPublisher" /t REG_SZ /d "{cb587ad1-cc35-4ef1-ad93-36cc82a2d319}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ATAPort/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Admin" /v "OwningPublisher" /t REG_SZ /d "{f5d05b38-80a6-4653-825d-c414e4ab3c68}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Admin" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Admin" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Admin" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Admin" /v "Type" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Analytic" /v "OwningPublisher" /t REG_SZ /d "{f5d05b38-80a6-4653-825d-c414e4ab3c68}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Debug" /v "OwningPublisher" /t REG_SZ /d "{f5d05b38-80a6-4653-825d-c414e4ab3c68}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Diagnose" /v "OwningPublisher" /t REG_SZ /d "{f5d05b38-80a6-4653-825d-c414e4ab3c68}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Diagnose" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Diagnose" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Diagnose" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-ClassPnP/Diagnose" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Admin" /v "OwningPublisher" /t REG_SZ /d "{6b4db0bc-9a3d-467d-81b9-a84c6f2f3d40}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Admin" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Admin" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Admin" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Admin" /v "Type" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Analytic" /v "OwningPublisher" /t REG_SZ /d "{6b4db0bc-9a3d-467d-81b9-a84c6f2f3d40}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Debug" /v "OwningPublisher" /t REG_SZ /d "{6b4db0bc-9a3d-467d-81b9-a84c6f2f3d40}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Diagnose" /v "OwningPublisher" /t REG_SZ /d "{6b4db0bc-9a3d-467d-81b9-a84c6f2f3d40}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Diagnose" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Diagnose" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Diagnose" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Diagnose" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Operational" /v "OwningPublisher" /t REG_SZ /d "{6b4db0bc-9a3d-467d-81b9-a84c6f2f3d40}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Disk/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Admin" /v "OwningPublisher" /t REG_SZ /d "{c4636a1e-7986-4646-bf10-7bc3b4a76e8e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Admin" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Admin" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Admin" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Admin" /v "Type" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Analytic" /v "OwningPublisher" /t REG_SZ /d "{c4636a1e-7986-4646-bf10-7bc3b4a76e8e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Debug" /v "OwningPublisher" /t REG_SZ /d "{c4636a1e-7986-4646-bf10-7bc3b4a76e8e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Diagnose" /v "OwningPublisher" /t REG_SZ /d "{c4636a1e-7986-4646-bf10-7bc3b4a76e8e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Diagnose" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Diagnose" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Diagnose" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Storport/Diagnose" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Tiering-IoHeat/Heat" /v "OwningPublisher" /t REG_SZ /d "{990c55fc-2662-47f6-b7d7-eb3c027cb13f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Tiering-IoHeat/Heat" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Tiering-IoHeat/Heat" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Tiering-IoHeat/Heat" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Storage-Tiering-IoHeat/Heat" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StorDiag/Operational" /v "OwningPublisher" /t REG_SZ /d "{f5d05b38-80a6-4653-825d-c414e4ab3c68}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StorDiag/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StorDiag/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StorDiag/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StorDiag/Operational" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StorPort/Operational" /v "OwningPublisher" /t REG_SZ /d "{c4636a1e-7986-4646-bf10-7bc3b4a76e8e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StorPort/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StorPort/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StorPort/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-StorPort/Operational" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Subsys-Csr/Operational" /v "OwningPublisher" /t REG_SZ /d "{e8316a2d-0d94-4f52-85dd-1e15b66c5891}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Subsys-Csr/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Subsys-Csr/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Subsys-Csr/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Subsys-Csr/Operational" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Subsys-SMSS/Operational" /v "OwningPublisher" /t REG_SZ /d "{43e63da5-41d1-4fbf-aded-1bbed98fdd1d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Subsys-SMSS/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Subsys-SMSS/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Subsys-SMSS/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Subsys-SMSS/Operational" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysprep/Analytic" /v "OwningPublisher" /t REG_SZ /d "{75ebc33e-77b8-4ba8-9474-4f4a9db2f5c6}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysprep/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysprep/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysprep/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysprep/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-System-Profile-HardwareId/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{3419de6d-5d7f-4668-acc8-f80566814d96}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-System-Profile-HardwareId/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-System-Profile-HardwareId/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-System-Profile-HardwareId/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-System-Profile-HardwareId/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsHandlers/Debug" /v "OwningPublisher" /t REG_SZ /d "{fbbd52e1-df97-529d-4b67-53f67da99a98}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsHandlers/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsHandlers/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsHandlers/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsHandlers/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Debug" /v "OwningPublisher" /t REG_SZ /d "{8bcdf442-3070-4118-8c94-e8843be363b3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{8bcdf442-3070-4118-8c94-e8843be363b3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-SystemSettingsThreshold/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskbarCPL/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{05d7b0f0-2121-4eff-bf6b-ed3f69b894d7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskbarCPL/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskbarCPL/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskbarCPL/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskbarCPL/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Debug" /v "OwningPublisher" /t REG_SZ /d "{de7b24ea-73c8-4a09-985d-5bdadcfa9017}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Debug" /v "MaxSize" /t REG_DWORD /d "10485760" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Debug" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Debug" /v "Level" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Debug" /v "KeywordsLower" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Debug" /v "KeywordsUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Debug" /v "ControlGuid" /t REG_SZ /d "{047311a9-fa52-4a68-a1e4-4e289fbb8d17}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{de7b24ea-73c8-4a09-985d-5bdadcfa9017}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Diagnostic" /v "MaxSize" /t REG_DWORD /d "10485760" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Diagnostic" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Diagnostic" /v "Level" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Diagnostic" /v "KeywordsLower" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Diagnostic" /v "KeywordsUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" /v "OwningPublisher" /t REG_SZ /d "{de7b24ea-73c8-4a09-985d-5bdadcfa9017}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" /v "MaxSize" /t REG_DWORD /d "10485760" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TaskScheduler/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TCPIP/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{2f07e2ee-15db-40f1-90ef-9d7ba282188a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TCPIP/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TCPIP/Diagnostic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TCPIP/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TCPIP/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TCPIP/Diagnostic" /v "Level" /t REG_DWORD /d "255" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-ClientUSBDevices/Analytic" /v "OwningPublisher" /t REG_SZ /d "{6e400999-5b82-475f-b800-cef6fe361539}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-ClientUSBDevices/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-ClientUSBDevices/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-ClientUSBDevices/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-ClientUSBDevices/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-ClientUSBDevices/Debug" /v "OwningPublisher" /t REG_SZ /d "{6e400999-5b82-475f-b800-cef6fe361539}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-ClientUSBDevices/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-ClientUSBDevices/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-ClientUSBDevices/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-ClientUSBDevices/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-LocalSessionManager/Analytic" /v "OwningPublisher" /t REG_SZ /d "{5d896912-022d-40aa-a3a8-4fa5515c76d7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-LocalSessionManager/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-LocalSessionManager/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-LocalSessionManager/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-LocalSessionManager/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-LocalSessionManager/Debug" /v "OwningPublisher" /t REG_SZ /d "{5d896912-022d-40aa-a3a8-4fa5515c76d7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-LocalSessionManager/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-LocalSessionManager/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-LocalSessionManager/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TerminalServices-LocalSessionManager/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Tethering-Manager/Analytic" /v "OwningPublisher" /t REG_SZ /d "{cc311f1f-623c-4ca4-ba44-a458016555e8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Tethering-Manager/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Tethering-Manager/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Tethering-Manager/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Tethering-Manager/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Tethering-Station/Analytic" /v "OwningPublisher" /t REG_SZ /d "{585cab4f-9351-436e-9d99-dc4b41a20de0}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Tethering-Station/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Tethering-Station/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Tethering-Station/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Tethering-Station/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ThemeCPL/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{61f044af-9104-4ca5-81ee-cb6c51bb01ab}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ThemeCPL/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ThemeCPL/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ThemeCPL/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ThemeCPL/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ThemeUI/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{869fb599-80aa-485d-bca7-db18d72b7219}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ThemeUI/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ThemeUI/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ThemeUI/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-ThemeUI/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Threat-Intelligence/Analytic" /v "OwningPublisher" /t REG_SZ /d "{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Threat-Intelligence/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Threat-Intelligence/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Threat-Intelligence/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Threat-Intelligence/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Time-Service-PTP-Provider/PTP-Operational" /v "OwningPublisher" /t REG_SZ /d "{cffb980e-327c-5b87-19c6-62c4c3be2290}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Time-Service-PTP-Provider/PTP-Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Time-Service-PTP-Provider/PTP-Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Time-Service-PTP-Provider/PTP-Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Time-Service-PTP-Provider/PTP-Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Time-Service/Operational" /v "OwningPublisher" /t REG_SZ /d "{06edcfeb-0fd0-4e53-acca-a6f8bbf81bcb}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Time-Service/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Time-Service/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Time-Service/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Time-Service/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msctf/Debug" /v "OwningPublisher" /t REG_SZ /d "{4fba1227-f606-4e5f-b9e8-fab9ab5740f3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msctf/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msctf/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msctf/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msctf/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msctf/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{4fba1227-f606-4e5f-b9e8-fab9ab5740f3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msctf/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msctf/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msctf/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msctf/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msutb/Debug" /v "OwningPublisher" /t REG_SZ /d "{74b655a2-8958-410e-80e2-3457051b8dff}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msutb/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msutb/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msutb/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msutb/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msutb/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{74b655a2-8958-410e-80e2-3457051b8dff}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msutb/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msutb/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msutb/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TSF-msutb/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TunnelDriver" /v "OwningPublisher" /t REG_SZ /d "{4edbe902-9ed3-4cf0-93e8-b8b5fa920299}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TunnelDriver" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TunnelDriver" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TunnelDriver" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TunnelDriver" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TunnelDriver" /v "Level" /t REG_DWORD /d "255" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TWinAPI/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{5f0e257f-c224-43e5-9555-2adcb8540a58}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TWinAPI/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TWinAPI/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TWinAPI/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TWinAPI/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TWinUI/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{315a8872-923e-4ea2-9889-33cd4754bf64}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TWinUI/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TWinUI/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TWinUI/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TWinUI/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TZSync/Analytic" /v "OwningPublisher" /t REG_SZ /d "{3527cb55-1298-49d4-ab94-1243db0fcaff}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TZSync/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TZSync/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TZSync/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-TZSync/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UI-Shell/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{e3ee1525-8742-4e05-871b-dd2a60330c53}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UI-Shell/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UI-Shell/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UI-Shell/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UI-Shell/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAnimation/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{e0a40b26-30c4-4656-bc9a-74a5c3a0b2ec}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAnimation/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAnimation/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAnimation/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAnimation/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAutomationCore/Debug" /v "OwningPublisher" /t REG_SZ /d "{820a42d8-38c4-465d-b64e-d7d56ea1d612}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAutomationCore/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAutomationCore/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAutomationCore/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAutomationCore/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAutomationCore/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{820a42d8-38c4-465d-b64e-d7d56ea1d612}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAutomationCore/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAutomationCore/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAutomationCore/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAutomationCore/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAutomationCore/Perf" /v "OwningPublisher" /t REG_SZ /d "{820a42d8-38c4-465d-b64e-d7d56ea1d612}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAutomationCore/Perf" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAutomationCore/Perf" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAutomationCore/Perf" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UIAutomationCore/Perf" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-MAUSBHOST-Analytic" /v "OwningPublisher" /t REG_SZ /d "{7725b5f9-1f2e-4e21-baeb-b2af4690bc87}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-MAUSBHOST-Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-MAUSBHOST-Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-MAUSBHOST-Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-MAUSBHOST-Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-UCX-Analytic" /v "OwningPublisher" /t REG_SZ /d "{36da592d-e43a-4e28-af6f-4bc57c5a11e8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-UCX-Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-UCX-Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-UCX-Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-UCX-Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBHUB/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{7426a56b-e2d5-4b30-bdef-b31815c1a74a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBHUB/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBHUB/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBHUB/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBHUB/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBHUB3-Analytic" /v "OwningPublisher" /t REG_SZ /d "{ac52ad17-cc01-4f85-8df5-4dce4333c99b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBHUB3-Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBHUB3-Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBHUB3-Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBHUB3-Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBPORT/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{c88a4ef5-d048-4013-9408-e04b7db2814a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBPORT/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBPORT/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBPORT/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBPORT/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBXHCI-Analytic" /v "OwningPublisher" /t REG_SZ /d "{30e1d284-5d88-459c-83fd-6345b39b19ec}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBXHCI-Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBXHCI-Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBXHCI-Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBXHCI-Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBXHCI-Trustlet-Analytic" /v "OwningPublisher" /t REG_SZ /d "{30e1d284-5d88-459c-83fd-6345b39b19ec}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBXHCI-Trustlet-Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBXHCI-Trustlet-Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBXHCI-Trustlet-Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-USB-USBXHCI-Trustlet-Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Control Panel Performance/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{319122a9-1485-4e48-af35-7db2d93b8ad2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Control Panel Performance/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Control Panel Performance/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Control Panel Performance/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Control Panel Performance/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Control Panel Usage/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{319122a9-1485-4e48-af35-7db2d93b8ad2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Control Panel Usage/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Control Panel Usage/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Control Panel Usage/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Control Panel Usage/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Control Panel/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{319122a9-1485-4e48-af35-7db2d93b8ad2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Control Panel/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Control Panel/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Control Panel/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Control Panel/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Device Registration/Debug" /v "OwningPublisher" /t REG_SZ /d "{23b8d46b-67dd-40a3-b636-d43e50552c6d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Device Registration/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Device Registration/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Device Registration/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Device Registration/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Device Registration/Debug" /v "BufferSize" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Profile Service/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{89b1e9f0-5aff-44a6-9b44-0a07a7ce5845}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Profile Service/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Profile Service/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Profile Service/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User Profile Service/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User-Loader/Analytic" /v "OwningPublisher" /t REG_SZ /d "{b059b83f-d946-4b13-87ca-4292839dc2f2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User-Loader/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User-Loader/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User-Loader/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-User-Loader/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserModePowerService/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{ce8dee0b-d539-4000-b0f8-77bed049c590}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserModePowerService/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserModePowerService/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserModePowerService/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserModePowerService/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserPnp/DeviceMetadata/Debug" /v "OwningPublisher" /t REG_SZ /d "{96f4a050-7e31-453c-88be-9634f4e02139}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserPnp/DeviceMetadata/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserPnp/DeviceMetadata/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserPnp/DeviceMetadata/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserPnp/DeviceMetadata/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserPnp/Performance" /v "OwningPublisher" /t REG_SZ /d "{96f4a050-7e31-453c-88be-9634f4e02139}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserPnp/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserPnp/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserPnp/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserPnp/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserPnp/SchedulerOperations" /v "OwningPublisher" /t REG_SZ /d "{96f4a050-7e31-453c-88be-9634f4e02139}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserPnp/SchedulerOperations" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserPnp/SchedulerOperations" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserPnp/SchedulerOperations" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-UserPnp/SchedulerOperations" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VAN/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{01578f96-c270-4602-ade0-578d9c29fc0c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VAN/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VAN/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VAN/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VAN/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VerifyHardwareSecurity/Operational" /v "OwningPublisher" /t REG_SZ /d "{f3f53c76-b06d-4f15-b412-61164a0d2b73}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VerifyHardwareSecurity/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VerifyHardwareSecurity/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VerifyHardwareSecurity/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VerifyHardwareSecurity/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VHDMP-Analytic" /v "OwningPublisher" /t REG_SZ /d "{e2816346-87f4-4f85-95c3-0c79409aa89d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VHDMP-Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VHDMP-Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VHDMP-Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VHDMP-Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VIRTDISK-Analytic" /v "OwningPublisher" /t REG_SZ /d "{4d20df22-e177-4514-a369-f1759feedeb3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VIRTDISK-Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VIRTDISK-Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VIRTDISK-Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VIRTDISK-Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VolumeControl/Performance" /v "OwningPublisher" /t REG_SZ /d "{07de7879-1c96-41ce-afbd-c659a0e8e643}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VolumeControl/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VolumeControl/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VolumeControl/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VolumeControl/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VolumeSnapshot-Driver/Analytic" /v "OwningPublisher" /t REG_SZ /d "{67fe2216-727a-40cb-94b2-c02211edb34a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VolumeSnapshot-Driver/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VolumeSnapshot-Driver/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VolumeSnapshot-Driver/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VolumeSnapshot-Driver/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VPN-Client/Operational" /v "OwningPublisher" /t REG_SZ /d "{3c088e51-65be-40d1-9b90-62bfec076737}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VPN-Client/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VPN-Client/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VPN-Client/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VPN-Client/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VPN/Operational" /v "OwningPublisher" /t REG_SZ /d "{0c478c5b-0351-41b1-8c58-4a6737da32e3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VPN/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VPN/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VPN/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VPN/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VWiFi/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{314b2b0d-81ee-4474-b6e0-c2aaec0ddbde}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VWiFi/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VWiFi/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VWiFi/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-VWiFi/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WABSyncProvider/Analytic" /v "OwningPublisher" /t REG_SZ /d "{17f14a23-551d-40cc-a086-e4194d64ed4c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WABSyncProvider/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WABSyncProvider/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WABSyncProvider/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WABSyncProvider/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Wcmsvc/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{67d07935-283a-4791-8f8d-fa9117f3e6f2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Wcmsvc/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Wcmsvc/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Wcmsvc/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Wcmsvc/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WCN-Config-Registrar/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{c100becf-d33a-4a4b-bf23-bbef4663d017}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WCN-Config-Registrar/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WCN-Config-Registrar/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WCN-Config-Registrar/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WCN-Config-Registrar/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WCNWiz/Analytic" /v "OwningPublisher" /t REG_SZ /d "{e8aa5402-26a1-455e-a21b-f240ed62d155}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WCNWiz/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WCNWiz/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WCNWiz/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WCNWiz/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebAuth/Operational" /v "OwningPublisher" /t REG_SZ /d "{db6972b6-dddf-4820-84b1-2ed6ac0b96e5}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebAuth/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebAuth/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebAuth/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebAuth/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebIO-NDF/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{50b3e73c-9370-461d-bb9f-26f32d68887d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebIO-NDF/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebIO-NDF/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebIO-NDF/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebIO-NDF/Diagnostic" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebIO/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{50b3e73c-9370-461d-bb9f-26f32d68887d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebIO/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebIO/Diagnostic" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebIO/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebIO/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebIO/Diagnostic" /v "ClockType" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebPlatStorage-Server" /v "OwningPublisher" /t REG_SZ /d "{9e3b3947-ca5d-4614-91a2-7b624e0e7244}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebPlatStorage-Server" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebPlatStorage-Server" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebPlatStorage-Server" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebPlatStorage-Server" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebServices/Tracing" /v "OwningPublisher" /t REG_SZ /d "{e04fe2e0-c6cf-4273-b59d-5c97c9c374a4}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebServices/Tracing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebServices/Tracing" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebServices/Tracing" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebServices/Tracing" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebServices/Tracing" /v "BufferSize" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WebServices/Tracing" /v "ClockType" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Websocket-Protocol-Component/Tracing" /v "OwningPublisher" /t REG_SZ /d "{cba5f63c-e2cf-4b36-8305-bde1311924fc}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Websocket-Protocol-Component/Tracing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Websocket-Protocol-Component/Tracing" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Websocket-Protocol-Component/Tracing" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Websocket-Protocol-Component/Tracing" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Websocket-Protocol-Component/Tracing" /v "ClockType" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WEPHOSTSVC/Operational" /v "OwningPublisher" /t REG_SZ /d "{d5f7235b-48e2-4e9c-92fe-0e4950aba9e8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WEPHOSTSVC/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WEPHOSTSVC/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WEPHOSTSVC/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WEPHOSTSVC/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WFP/Analytic" /v "OwningPublisher" /t REG_SZ /d "{0c478c5b-0351-41b1-8c58-4a6737da32e3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WFP/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WFP/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WFP/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WFP/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WiFiDisplay/Analytic" /v "OwningPublisher" /t REG_SZ /d "{712880e9-7813-41a3-8e4c-e4e0c4f6580a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WiFiDisplay/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WiFiDisplay/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WiFiDisplay/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WiFiDisplay/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Concurrency" /v "OwningPublisher" /t REG_SZ /d "{8c416c79-d49b-4f01-a467-e56d3aa8234c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Concurrency" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Concurrency" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Concurrency" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Concurrency" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Contention" /v "OwningPublisher" /t REG_SZ /d "{8c416c79-d49b-4f01-a467-e56d3aa8234c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Contention" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Contention" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Contention" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Contention" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Messages" /v "OwningPublisher" /t REG_SZ /d "{8c416c79-d49b-4f01-a467-e56d3aa8234c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Messages" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Messages" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Messages" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Messages" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Power" /v "OwningPublisher" /t REG_SZ /d "{8c416c79-d49b-4f01-a467-e56d3aa8234c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Power" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Power" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Power" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Power" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Render" /v "OwningPublisher" /t REG_SZ /d "{8c416c79-d49b-4f01-a467-e56d3aa8234c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Render" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Render" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Render" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Render" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Tracing" /v "OwningPublisher" /t REG_SZ /d "{8c416c79-d49b-4f01-a467-e56d3aa8234c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Tracing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Tracing" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Tracing" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/Tracing" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/UIPI" /v "OwningPublisher" /t REG_SZ /d "{8c416c79-d49b-4f01-a467-e56d3aa8234c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/UIPI" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/UIPI" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/UIPI" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Win32k/UIPI" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windeploy/Analytic" /v "OwningPublisher" /t REG_SZ /d "{75ebc33e-c8ae-4f93-9ca1-683a53e20cb6}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windeploy/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windeploy/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windeploy/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windeploy/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity" /v "OwningPublisher" /t REG_SZ /d "{d1bc9aff-2abf-4d71-9146-ecb2a986eb85}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x7SY)(A0x7BA)(A0x7S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurityVerbose" /v "OwningPublisher" /t REG_SZ /d "{d1bc9aff-2abf-4d71-9146-ecb2a986eb85}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurityVerbose" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurityVerbose" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurityVerbose" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x7SY)(A0x7BA)(A0x7S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurityVerbose" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/FirewallDiagnostics" /v "OwningPublisher" /t REG_SZ /d "{d1bc9aff-2abf-4d71-9146-ecb2a986eb85}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/FirewallDiagnostics" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/FirewallDiagnostics" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/FirewallDiagnostics" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/FirewallDiagnostics" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/FirewallVerbose" /v "OwningPublisher" /t REG_SZ /d "{d1bc9aff-2abf-4d71-9146-ecb2a986eb85}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/FirewallVerbose" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/FirewallVerbose" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/FirewallVerbose" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Firewall With Advanced Security/FirewallVerbose" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsBackup/ActionCenter" /v "OwningPublisher" /t REG_SZ /d "{01979c6a-42fa-414c-b8aa-eee2c8202018}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsBackup/ActionCenter" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsBackup/ActionCenter" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsBackup/ActionCenter" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsBackup/ActionCenter" /v "Type" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsColorSystem/Debug" /v "OwningPublisher" /t REG_SZ /d "{d53270e3-c8cf-4707-958a-dad20c90073c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsColorSystem/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsColorSystem/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsColorSystem/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsColorSystem/Debug" /v "MaxSize" /t REG_DWORD /d "104857600" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsColorSystem/Debug" /v "MaxSizeUpper" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsColorSystem/Debug" /v "Retention" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsColorSystem/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsColorSystem/Debug" /v "ClockType" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsColorSystem/Operational" /v "OwningPublisher" /t REG_SZ /d "{d53270e3-c8cf-4707-958a-dad20c90073c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsColorSystem/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsColorSystem/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsColorSystem/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsColorSystem/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsSystemAssessmentTool/Operational" /v "OwningPublisher" /t REG_SZ /d "{11a75546-3234-465e-bec8-2d301cb501ac}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsSystemAssessmentTool/Operational" /v "Enabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsSystemAssessmentTool/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsSystemAssessmentTool/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsSystemAssessmentTool/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsSystemAssessmentTool/Tracing" /v "OwningPublisher" /t REG_SZ /d "{11a75546-3234-465e-bec8-2d301cb501ac}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsSystemAssessmentTool/Tracing" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsSystemAssessmentTool/Tracing" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsSystemAssessmentTool/Tracing" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsSystemAssessmentTool/Tracing" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUIImmersive/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{74827cbb-1e0f-45a2-8523-c605866d2f22}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUIImmersive/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUIImmersive/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUIImmersive/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUIImmersive/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUIImmersive/Operational" /v "OwningPublisher" /t REG_SZ /d "{74827cbb-1e0f-45a2-8523-c605866d2f22}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUIImmersive/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUIImmersive/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUIImmersive/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUIImmersive/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUpdateClient/Analytic" /v "OwningPublisher" /t REG_SZ /d "{945a8954-c147-4acd-923f-40c45405a658}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUpdateClient/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUpdateClient/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUpdateClient/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUpdateClient/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUpdateClient/Operational" /v "OwningPublisher" /t REG_SZ /d "{945a8954-c147-4acd-923f-40c45405a658}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUpdateClient/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUpdateClient/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUpdateClient/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WindowsUpdateClient/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinHTTP-NDF/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{7d44233d-3055-4b9c-ba64-0d47ca40a232}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinHTTP-NDF/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinHTTP-NDF/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinHTTP-NDF/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinHTTP-NDF/Diagnostic" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinHttp/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{7d44233d-3055-4b9c-ba64-0d47ca40a232}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinHttp/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinHttp/Diagnostic" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinHttp/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinHttp/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinHttp/Diagnostic" /v "ClockType" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet-Capture/Analytic" /v "OwningPublisher" /t REG_SZ /d "{a70ff94f-570b-4979-ba5c-e59c9feab61b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet-Capture/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet-Capture/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet-Capture/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet-Capture/Analytic" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/Analytic" /v "OwningPublisher" /t REG_SZ /d "{43d1a55c-76d6-4f7e-995c-64c711e5cafe}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/UsageLog" /v "OwningPublisher" /t REG_SZ /d "{43d1a55c-76d6-4f7e-995c-64c711e5cafe}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/UsageLog" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/UsageLog" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/UsageLog" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/UsageLog" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/WebSocket" /v "OwningPublisher" /t REG_SZ /d "{43d1a55c-76d6-4f7e-995c-64c711e5cafe}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/WebSocket" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/WebSocket" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/WebSocket" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinINet/WebSocket" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Wininit/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{206f6dea-d3c5-4d10-bc72-989f03c8b84b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Wininit/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Wininit/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Wininit/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Wininit/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winlogon/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winlogon/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winlogon/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winlogon/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winlogon/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinMDE/MDE" /v "OwningPublisher" /t REG_SZ /d "{77549803-7bb1-418b-a98e-f2e22f35a873}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinMDE/MDE" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinMDE/MDE" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinMDE/MDE" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinMDE/MDE" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinML/Analytic" /v "OwningPublisher" /t REG_SZ /d "{c8517e09-bea2-5bb6-bef3-50b4c91c431e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinML/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinML/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinML/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinML/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinNat/Oper" /v "OwningPublisher" /t REG_SZ /d "{66c07ecd-6667-43fc-93f8-05cf07f446ec}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinNat/Oper" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinNat/Oper" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinNat/Oper" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinNat/Oper" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinNat/Trace" /v "OwningPublisher" /t REG_SZ /d "{66c07ecd-6667-43fc-93f8-05cf07f446ec}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinNat/Trace" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinNat/Trace" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinNat/Trace" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinNat/Trace" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinNat/Trace" /v "Level" /t REG_DWORD /d "255" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winsock-AFD/Operational" /v "OwningPublisher" /t REG_SZ /d "{e53c6823-7bb8-44bb-90dc-3f86090d48a6}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winsock-AFD/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winsock-AFD/Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winsock-AFD/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winsock-AFD/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winsock-NameResolution/Operational" /v "OwningPublisher" /t REG_SZ /d "{55404e71-4db9-4deb-a5f5-8f86e46dde56}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winsock-NameResolution/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winsock-NameResolution/Operational" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winsock-NameResolution/Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winsock-NameResolution/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winsrv/Analytic" /v "OwningPublisher" /t REG_SZ /d "{9d55b53d-449b-4824-a637-24f9d69aa02f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winsrv/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winsrv/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winsrv/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Winsrv/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinURLMon/Analytic" /v "OwningPublisher" /t REG_SZ /d "{245f975d-909d-49ed-b8f9-9a75691d6b6b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinURLMon/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinURLMon/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinURLMon/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WinURLMon/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Wired-AutoConfig/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{b92cf7fd-dc10-4c6b-a72d-1613bf25e597}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Wired-AutoConfig/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Wired-AutoConfig/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Wired-AutoConfig/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Wired-AutoConfig/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-Autoconfig/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{9580d7dd-0379-4658-9870-d5be7d52d6de}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-Autoconfig/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-Autoconfig/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-Autoconfig/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-Autoconfig/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-Driver/Analytic" /v "OwningPublisher" /t REG_SZ /d "{daa6a96b-f3e7-4d4d-a0d6-31a350e6a445}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-Driver/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-Driver/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-Driver/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-Driver/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-MediaManager/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{323dad74-d3ec-44a8-8b9d-cafeb4999274}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-MediaManager/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-MediaManager/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-MediaManager/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLAN-MediaManager/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLANConnectionFlow/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{239cfb83-cbb7-4bbc-a02e-9bdb496aa7c2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLANConnectionFlow/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLANConnectionFlow/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLANConnectionFlow/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WLANConnectionFlow/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WlanDlg/Analytic" /v "OwningPublisher" /t REG_SZ /d "{d4afa0dc-4dd1-40af-afce-cb0d0e6736a7}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WlanDlg/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WlanDlg/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WlanDlg/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WlanDlg/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-wmbclass/Analytic" /v "OwningPublisher" /t REG_SZ /d "{12d25187-6c0d-4783-ad3a-84caa135acfd}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-wmbclass/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-wmbclass/Analytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-wmbclass/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-wmbclass/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-wmbclass/Trace" /v "OwningPublisher" /t REG_SZ /d "{12d25187-6c0d-4783-ad3a-84caa135acfd}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-wmbclass/Trace" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-wmbclass/Trace" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-wmbclass/Trace" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-wmbclass/Trace" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMI-Activity/Debug" /v "OwningPublisher" /t REG_SZ /d "{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMI-Activity/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMI-Activity/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMI-Activity/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMI-Activity/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMI-Activity/Trace" /v "OwningPublisher" /t REG_SZ /d "{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMI-Activity/Trace" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMI-Activity/Trace" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMI-Activity/Trace" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMI-Activity/Trace" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPDMCUI/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{3f9e07bd-0e26-4241-a5a5-28cafa150a75}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPDMCUI/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPDMCUI/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPDMCUI/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPDMCUI/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPNSS-PublicAPI/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{614696c9-85af-4e64-b389-d2c0db4ff87b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPNSS-PublicAPI/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPNSS-PublicAPI/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPNSS-PublicAPI/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPNSS-PublicAPI/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPNSS-Service/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{6a2dc7c1-930a-4fb5-bb44-80b30aebed6c}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPNSS-Service/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPNSS-Service/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPNSS-Service/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPNSS-Service/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPNSSUI/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{7c314e58-8246-47d1-8f7a-4049dc543e0b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPNSSUI/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPNSSUI/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPNSSUI/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WMPNSSUI/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WorkFolders/Analytic" /v "OwningPublisher" /t REG_SZ /d "{34a3697e-0f10-4e48-af3c-f869b5babebb}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WorkFolders/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WorkFolders/Analytic" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WorkFolders/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:LSD:(D0xf0007AN)(D0xf0007BG)(A0x7LS)(A0x7BA)(A0x2WD)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WorkFolders/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WorkFolders/Debug" /v "OwningPublisher" /t REG_SZ /d "{34a3697e-0f10-4e48-af3c-f869b5babebb}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WorkFolders/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WorkFolders/Debug" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WorkFolders/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:LSD:(D0xf0007AN)(D0xf0007BG)(A0x7LS)(A0x7BA)(A0x2WD)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WorkFolders/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-API/Analytic" /v "OwningPublisher" /t REG_SZ /d "{31569dcf-9c6f-4b8e-843a-b7c1cc7ffcba}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-API/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-API/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-API/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-API/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-ClassInstaller/Analytic" /v "OwningPublisher" /t REG_SZ /d "{ad5162d8-daf0-4a25-88a7-01cbeb33902e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-ClassInstaller/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-ClassInstaller/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-ClassInstaller/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-ClassInstaller/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-CompositeClassDriver/Analytic" /v "OwningPublisher" /t REG_SZ /d "{355c44fe-0c8e-4bf8-be28-8bc7b5a42720}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-CompositeClassDriver/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-CompositeClassDriver/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-CompositeClassDriver/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-CompositeClassDriver/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPBT/Analytic" /v "OwningPublisher" /t REG_SZ /d "{92ab58d3-f351-4af5-9c72-d52f36ee2c92}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPBT/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPBT/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPBT/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPBT/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPClassDriver/Analytic" /v "OwningPublisher" /t REG_SZ /d "{21b7c16e-c5af-4a69-a74a-7245481c1b97}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPClassDriver/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPClassDriver/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPClassDriver/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPClassDriver/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPIP/Analytic" /v "OwningPublisher" /t REG_SZ /d "{c374d21e-69b2-4cd7-9a25-62187c5a5619}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPIP/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPIP/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPIP/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPIP/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPUS/Analytic" /v "OwningPublisher" /t REG_SZ /d "{dcfc4489-9ce0-403c-99df-a05422c60898}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPUS/Analytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPUS/Analytic" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPUS/Analytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WPD-MTPUS/Analytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WUSA/Debug" /v "OwningPublisher" /t REG_SZ /d "{09608c12-c1da-4104-a6fe-b959cf57560a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WUSA/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WUSA/Debug" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WUSA/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WUSA/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-CFE/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{71c993b8-1e28-4543-9886-fb219b63fdb3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-CFE/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-CFE/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-CFE/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-CFE/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-MediaManager/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{f4c9be26-414f-42d7-b540-8bff965e6d32}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-MediaManager/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-MediaManager/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-MediaManager/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-MediaManager/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-MM-Events/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{7839bb2a-2ea3-4eca-a00f-b558ba678bec}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-MM-Events/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-MM-Events/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-MM-Events/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-MM-Events/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-NDISUIO-EVENTS/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{b3eee223-d0a9-40cd-adfc-50f1888138ab}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-NDISUIO-EVENTS/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-NDISUIO-EVENTS/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-NDISUIO-EVENTS/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-NDISUIO-EVENTS/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-SVC-Events/Diagnostic" /v "OwningPublisher" /t REG_SZ /d "{3cb40aaa-1145-4fb8-b27b-7e30f0454316}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-SVC-Events/Diagnostic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-SVC-Events/Diagnostic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-SVC-Events/Diagnostic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-WWAN-SVC-Events/Diagnostic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAML-Diagnostics/Default" /v "OwningPublisher" /t REG_SZ /d "{59e7a714-73a4-4147-b47e-0957048c75c4}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAML-Diagnostics/Default" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAML-Diagnostics/Default" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAML-Diagnostics/Default" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAML-Diagnostics/Default" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAML/Default" /v "OwningPublisher" /t REG_SZ /d "{531a35ab-63ce-4bcf-aa98-f88c7a89e455}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAML/Default" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAML/Default" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAML/Default" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAML/Default" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAudio2/Debug" /v "OwningPublisher" /t REG_SZ /d "{1ee3abdb-c1fc-4b43-9e56-11064abba866}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAudio2/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAudio2/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAudio2/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAudio2/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAudio2/Performance" /v "OwningPublisher" /t REG_SZ /d "{1ee3abdb-c1fc-4b43-9e56-11064abba866}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAudio2/Performance" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAudio2/Performance" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAudio2/Performance" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-XAudio2/Performance" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-WindowsPhone-Connectivity-WiFiConnSvc-Channel" /v "OwningPublisher" /t REG_SZ /d "{e5c16d49-2464-4382-bb20-97a4b5465db9}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-WindowsPhone-Connectivity-WiFiConnSvc-Channel" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-WindowsPhone-Connectivity-WiFiConnSvc-Channel" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-WindowsPhone-Connectivity-WiFiConnSvc-Channel" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-WindowsPhone-Connectivity-WiFiConnSvc-Channel" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-WindowsPhone-Net-Cellcore-CellManager/Debug" /v "OwningPublisher" /t REG_SZ /d "{9a6615a6-902a-4705-804b-57b8813089b8}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-WindowsPhone-Net-Cellcore-CellManager/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-WindowsPhone-Net-Cellcore-CellManager/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-WindowsPhone-Net-Cellcore-CellManager/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-WindowsPhone-Net-Cellcore-CellManager/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-WindowsPhone-Net-Cellcore-CellularAPI/Debug" /v "OwningPublisher" /t REG_SZ /d "{6b7b5e3a-f4de-42d9-9545-bae12852d778}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-WindowsPhone-Net-Cellcore-CellularAPI/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-WindowsPhone-Net-Cellcore-CellularAPI/Debug" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-WindowsPhone-Net-Cellcore-CellularAPI/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-WindowsPhone-Net-Cellcore-CellularAPI/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\muxencode" /v "OwningPublisher" /t REG_SZ /d "{86efff39-2bdd-4efd-bd0b-853d71b2a9dc}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\muxencode" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\muxencode" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\muxencode" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\muxencode" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Navigator" /v "OwningPublisher" /t REG_SZ /d "{e18d0fca-9515-4232-98e4-89e456d8551b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Navigator" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Navigator" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Navigator" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Navigator" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Network Isolation Operational" /v "OwningPublisher" /t REG_SZ /d "{d1bc9aff-2abf-4d71-9146-ecb2a986eb85}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Network Isolation Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Network Isolation Operational" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Network Isolation Operational" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x7SY)(A0x7BA)(A0x7S-1-5-80-3088073201-1464728630-1879813800-1107566885-823218052)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Network Isolation Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\OpenSSH/Debug" /v "OwningPublisher" /t REG_SZ /d "{c4b57d35-0636-4bc3-a262-370f249f9802}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\OpenSSH/Debug" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\OpenSSH/Debug" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\OpenSSH/Debug" /v "ChannelAccess" /t REG_SZ /d "O:BAG:BAD:(A0x2BU)(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\OpenSSH/Debug" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\OSK_SoftKeyboard_Channel" /v "OwningPublisher" /t REG_SZ /d "{e978f84e-582d-4167-977e-32af52706888}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\OSK_SoftKeyboard_Channel" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\OSK_SoftKeyboard_Channel" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\OSK_SoftKeyboard_Channel" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\OSK_SoftKeyboard_Channel" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Physical_Keyboard_Manager_Channel" /v "OwningPublisher" /t REG_SZ /d "{e978f84e-582d-4167-977e-32af52706888}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Physical_Keyboard_Manager_Channel" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Physical_Keyboard_Manager_Channel" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Physical_Keyboard_Manager_Channel" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Physical_Keyboard_Manager_Channel" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\PlayReadyPerformanceChannel" /v "OwningPublisher" /t REG_SZ /d "{d2402fde-7526-5a7b-501a-25dc7c9c282e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\PlayReadyPerformanceChannel" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\PlayReadyPerformanceChannel" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\PlayReadyPerformanceChannel" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\PlayReadyPerformanceChannel" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\RTWorkQueueExtended" /v "OwningPublisher" /t REG_SZ /d "{83faaa86-63c8-4dd8-a2da-fbadddfc0655}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\RTWorkQueueExtended" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\RTWorkQueueExtended" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\RTWorkQueueExtended" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\RTWorkQueueExtended" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\RTWorkQueueTheading" /v "OwningPublisher" /t REG_SZ /d "{e18d0fc9-9515-4232-98e4-89e456d8551b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\RTWorkQueueTheading" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\RTWorkQueueTheading" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\RTWorkQueueTheading" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\RTWorkQueueTheading" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\SmbWmiAnalytic" /v "OwningPublisher" /t REG_SZ /d "{50b9e206-9d55-4092-92e8-f157a8235799}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\SmbWmiAnalytic" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\SmbWmiAnalytic" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\SmbWmiAnalytic" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\SmbWmiAnalytic" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\SystemEventsBroker" /v "OwningPublisher" /t REG_SZ /d "{b6bfcc79-a3af-4089-8d4d-0eecb1b80779}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\SystemEventsBroker" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\SystemEventsBroker" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\SystemEventsBroker" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\SystemEventsBroker" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\TabletPC_InputPanel_Channel" /v "OwningPublisher" /t REG_SZ /d "{e978f84e-582d-4167-977e-32af52706888}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\TabletPC_InputPanel_Channel" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\TabletPC_InputPanel_Channel" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\TabletPC_InputPanel_Channel" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\TabletPC_InputPanel_Channel" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\TabletPC_InputPanel_Channel/IHM" /v "OwningPublisher" /t REG_SZ /d "{e978f84e-582d-4167-977e-32af52706888}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\TabletPC_InputPanel_Channel/IHM" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\TabletPC_InputPanel_Channel/IHM" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\TabletPC_InputPanel_Channel/IHM" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\TabletPC_InputPanel_Channel/IHM" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\TimeBroker" /v "OwningPublisher" /t REG_SZ /d "{0657adc1-9ae8-4e18-932d-e6079cda5ab3}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\TimeBroker" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\TimeBroker" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\TimeBroker" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\TimeBroker" /v "Type" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\UIManager_Channel" /v "OwningPublisher" /t REG_SZ /d "{4dd778b8-379c-4d8c-b659-517a43d6df7d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\UIManager_Channel" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\UIManager_Channel" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\UIManager_Channel" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\UIManager_Channel" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Windows Networking Vpn Plugin Platform/Operational" /v "OwningPublisher" /t REG_SZ /d "{e5fc4a0f-7198-492f-9b0f-88fdcbfded48}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Windows Networking Vpn Plugin Platform/Operational" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Windows Networking Vpn Plugin Platform/Operational" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Windows Networking Vpn Plugin Platform/Operational" /v "ChannelAccess" /t REG_SZ /d "O:SYG:SYD:(A0x7BA)(A0x7NO)(A0x7AU)(A0x7S-1-15-3-1024-2579400809-3867311217-3984994116-908665914-3508570097-1336497314-873935804-1444405236)(A0x7S-1-15-3-1024-1068037383-729401668-2768096886-125909118-1680096985-174794564-3112554050-3241210738)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Windows Networking Vpn Plugin Platform/Operational" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Windows Networking Vpn Plugin Platform/OperationalVerbose" /v "OwningPublisher" /t REG_SZ /d "{e5fc4a0f-7198-492f-9b0f-88fdcbfded48}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Windows Networking Vpn Plugin Platform/OperationalVerbose" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Windows Networking Vpn Plugin Platform/OperationalVerbose" /v "Isolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Windows Networking Vpn Plugin Platform/OperationalVerbose" /v "ChannelAccess" /t REG_SZ /d "O:SYG:SYD:(A0x7BA)(A0x7NO)(A0x7AU)(A0x7S-1-15-3-1024-2579400809-3867311217-3984994116-908665914-3508570097-1336497314-873935804-1444405236)(A0x7S-1-15-3-1024-1068037383-729401668-2768096886-125909118-1680096985-174794564-3112554050-3241210738)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Windows Networking Vpn Plugin Platform/OperationalVerbose" /v "Type" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_KS_CHANNEL" /v "OwningPublisher" /t REG_SZ /d "{548c4417-ce45-41ff-99dd-528f01ce0fe1}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_KS_CHANNEL" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_KS_CHANNEL" /v "Isolation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_KS_CHANNEL" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0xf0007SY)(A0x7BA)(A0x3BO)(A0x5SO)(A0x1IU)(A0x3SU)(A0x1S-1-5-3)(A0x2S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_KS_CHANNEL" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MFH264Enc_CHANNEL" /v "OwningPublisher" /t REG_SZ /d "{2a49de31-8a5b-4d3a-a904-7fc7409ae90d}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MFH264Enc_CHANNEL" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MFH264Enc_CHANNEL" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MFH264Enc_CHANNEL" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MFH264Enc_CHANNEL" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MP4SDECD_CHANNEL" /v "OwningPublisher" /t REG_SZ /d "{7f2bd991-ae93-454a-b219-0bc23f02262a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MP4SDECD_CHANNEL" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MP4SDECD_CHANNEL" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MP4SDECD_CHANNEL" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MP4SDECD_CHANNEL" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MSMPEG2ADEC_CHANNEL" /v "OwningPublisher" /t REG_SZ /d "{51311de3-d55e-454a-9c58-43dc7b4c01d2}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MSMPEG2ADEC_CHANNEL" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MSMPEG2ADEC_CHANNEL" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MSMPEG2ADEC_CHANNEL" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MSMPEG2ADEC_CHANNEL" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MSMPEG2VDEC_CHANNEL" /v "OwningPublisher" /t REG_SZ /d "{ae5cf422-786a-476a-ac96-753b05877c99}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MSMPEG2VDEC_CHANNEL" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MSMPEG2VDEC_CHANNEL" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MSMPEG2VDEC_CHANNEL" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_MSMPEG2VDEC_CHANNEL" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_VC1ENC_CHANNEL" /v "OwningPublisher" /t REG_SZ /d "{313b0545-bf9c-492e-9173-8de4863b8573}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_VC1ENC_CHANNEL" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_VC1ENC_CHANNEL" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_VC1ENC_CHANNEL" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_VC1ENC_CHANNEL" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_WMPHOTO_CHANNEL" /v "OwningPublisher" /t REG_SZ /d "{be3a31ea-aa6c-4196-9dcc-9ca13a49e09f}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_WMPHOTO_CHANNEL" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_WMPHOTO_CHANNEL" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_WMPHOTO_CHANNEL" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_WMPHOTO_CHANNEL" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_wmvdecod_CHANNEL" /v "OwningPublisher" /t REG_SZ /d "{55bacc9f-9ac0-46f5-968a-a5a5dd024f8a}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_wmvdecod_CHANNEL" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_wmvdecod_CHANNEL" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_wmvdecod_CHANNEL" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WINDOWS_wmvdecod_CHANNEL" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WMPSetup" /v "OwningPublisher" /t REG_SZ /d "{0d759f0f-cff9-4902-8867-eb9e29d7a98b}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WMPSetup" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WMPSetup" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WMPSetup" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WMPSetup" /v "Type" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WMPSyncEngine" /v "OwningPublisher" /t REG_SZ /d "{f3f14ff3-7b80-4868-91d0-d77e497b025e}" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WMPSyncEngine" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WMPSyncEngine" /v "Isolation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WMPSyncEngine" /v "ChannelAccess" /t REG_SZ /d "O:BAG:SYD:(A0x2S-1-15-2-1)(A0x2S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)(A0xf0007SY)(A0x7BA)(A0x7SO)(A0x3IU)(A0x3SU)(A0x3S-1-5-3)(A0x3S-1-5-33)(A0x1S-1-5-32-573)" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\WMPSyncEngine" /v "Type" /t REG_DWORD /d "2" /f
cls
  
echo "aight small one then"
sc stop dmwappushservice
net stop dmwappushservice 
sc config dmwappushservice start= disabled
net stop diagnosticshub.standardcollector.service > NUL 2>&1
sc config diagnosticshub.standardcollector.service start= disabled
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "DiagnosticErrorText" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticErrorText" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticLinkText" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f
cls
echo Extra Stuff

:: Credits https://github.com/tarekifla/X/blob/main/X.bat

echo Disabling Cortana
taskkill /f /im Cortana.exe
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f  >nul 2>&1
rd /s /q "%WinDir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d "0" /f >nul 2>&1
taskkill /f /im explorer.exe >nul 2>&1
start explorer.exe >nul 2>&1

echo Disabling Biometrics..
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "VsyncIdleTimeout" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKU\!USER_SID!\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1

echo Disabling Gamebar Presence Writer
chdir /d C:\Windows\System32 >nul 2>&1
ren GameBarPresenceWriter.exe GameBarPresenceWriter.old >nul 2>&1
taskkill /F /FI "IMAGENAME eq GameBarPresenceWriter.exe" >nul 2>&1

echo Removing mobsync and GameBarPresenceWriter
del /F /Q "%WinDir%\System32\GameBarPresenceWriter.exe" >nul 2>&1
del /F /Q "%WinDir%\System32\mobsync.exe" >nul 2>&1

:: Done finally.

echo Done
echo Please restart ur PC.
echo see in the file for more stuff
timeout /T 10
exit

:: these here break my windows 11 so be wary

:: echo Disabling drivers
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\3ware" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\ADP80XX" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\PEAUTH" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\rdyboost" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\KSecPkg" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\mrxsmb20" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\mrxsmb" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\srv2" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\sfloppy" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SiSRaid2" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SiSRaid4" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\tcpipreg" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Telemetry" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1

:: echo Removing dependencies
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Dhcp" /v "DependOnService" /t REG_MULTI_SZ /d "NSI\0Afd" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Dnscache" /v "DependOnService" /t REG_MULTI_SZ /d "nsi" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\rdyboost" /v "DependOnService" /t REG_MULTI_SZ /d "" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "LowerFilters" /t REG_SZ /d "" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "UpperFilters" /t REG_SZ /d "" /f >nul 2>&1
:: reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\fvevol" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1