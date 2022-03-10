' Create and apply a registry mouse acceleration fix for Windows 7 or Vista or XP.
' Copyright 2010-2018 Mark Cranness - http://donewmouseaccel.blogspot.com
'
' Create a registry .REG file that removes Windows' mouse acceleration,
'  or emulates Windows 2000 or Windows 98 or Windows 95 acceleration.
'
' The registry fix created works like the CPL and Cheese and MarkC fixes,
'  but is customized for your specific desktop display text size (DPI),
'  your specific mouse pointer speed slider setting, your specific refresh rate
'  and has any pointer speed scaling/sensitivity factor you want.
'
' Other Registry fixes need the pointer speed slider set to 6/11 (middle) to get
'  exactly 1-to-1 mouse to pointer response, but this script can create a registry
'  fix that gives exact 1-to-1 response for non-6/11 settings.
' Other registry fixes only provide files for some pre-defined display DPI 
'  values: 100%, 125%..., but this script can create a fix for any DPI setting.
' This script can create a fix with any mouse-to-pointer speed scaling factor you want.

' The current system is queried, and the user can change the values and tune the
'  registry fix file created.
' The result is saved to a file and can optionally be imported into the registry.
'
' This script asks for:
' - Operating system that the fix will be used for.
' - The desktop Control Panel, Display, text size (DPI) that will be used.
' - The in-game monitor refresh rate that will be used (XP and Vista only).
' - The Control Panel, Mouse, pointer speed slider position that will be used.
' - Windows-2000+98+95-style acceleration thresholds (optional).
' - The pointer speed scaling (sensitivity) factor for that pointer speed setting.
' - Where you want to save the fix to and what name.
'
' It creates a registry .reg file with the settings entered, and
' optionally lets you merge / apply it into the registry.
'
' Credits:
'  hoppan and scandalous for debugging and testing,
'  jaclaz for wondering if there might be 6 curve points (rather than 5),
'  Microsoft for inspiration.
'
' Version 1.4, fix a problem with Vista / Multiple video controllers.
' Version 2.0, Create Windows 2000 and earlier 'step-up'/threshold style acceleration curves.
' Version 2.1, Windows 8.
' Version 2.2, Fix problem with threshold guidance text.
' Version 2.3, Windows 8.1.
' Version 2.4, Windows 10.
' Version 2.5, Windows 10 1709 DPI/mouse scaling.
' Version 2.6, Do not allow Windows 10 2 threshold (Windows 2000) curves

option explicit
const XPVistaFix  = "XP+Vista"
const Windows7Fix = "Windows 7"
const Windows8Fix = "Windows 8.1+8"
const Windows10Fix = "Windows 10"
dim WshShell, WMIService, OS, VideoController, Shell, Folder, RegFile, FileSystem ' as Object
dim OSVersion, OSVersionNumber, FixType, DPI, RefreshRate, MouseSensitivity, DPISensitivity, EPPOffMouseScaling
dim MouseSensitivityFactor, PointerSpeed, Scaling, ScalingDescr
dim RegFilename, FolderName, OSConfirmText, RegComment
dim SmoothX, SmoothY, SmoothYPixels, DPIFactor
dim SpeedSteps, Threshold1, Threshold2, ScalingAfterThreshold1, ScalingAfterThreshold2
dim OldWindowsAccelName, OldWindowsAccelCode, OldWindowsThreshold1, OldWindowsThreshold2
dim SmoothX0, SmoothX1, SmoothX2, SmoothX3, SmoothX4
dim SmoothY0, SmoothY1, SmoothY2, SmoothY3, SmoothY4

set WshShell = WScript.CreateObject("WScript.Shell")
set WMIService = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")

' Get the OS on this machine, and display DPI
for each OS in WMIService.ExecQuery("select * from Win32_OperatingSystem where Primary='True'")
	OSVersion = Left(OS.Version, InStr(InStr(OS.Version,".")+1, OS.Version, ".")-1)
	OSVersionNumber = OSVersion
	DPI = 96 ' Default in case RegRead errors
	EPPOffMouseScaling = 1
	on error resume next ' On 7, Desktop\LogPixels not present until DPI is changed
	select case OSVersion
	case "5.1","6.0"
		FixType = XPVistaFix
		OSVersion = XPVistaFix
		DPI = WshShell.RegRead("HKEY_CURRENT_CONFIG\Software\Fonts\LogPixels")
	case "6.1"
		FixType = Windows7Fix
		OSVersion = Windows7Fix
		DPI = WshShell.RegRead("HKEY_CURRENT_USER\Control Panel\Desktop\LogPixels")
	case "6.2"
		FixType = Windows8Fix
		OSVersion = Windows8Fix
		DPI = WshShell.RegRead("HKEY_CURRENT_USER\Control Panel\Desktop\LogPixels")
	case "6.3"
		FixType = Windows8Fix
		OSVersion = Windows8Fix
		DPI = WshShell.RegRead("HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics\AppliedDPI")
	case "10.0"
		FixType = Windows10Fix
		OSVersion = Windows10Fix
		DPI = WshShell.RegRead("HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics\AppliedDPI")
		if Fix(OS.BuildNumber) >= 16299 then EPPOffMouseScaling = -1 ' New EPP=OFF mouse scaling for Windows 10 1709+
	case else
		FixType = Windows10Fix
	end select
	on error goto 0 ' Normal errors
next

' Get which OS the fix will be used for
do
	FixType = InputBox( _
		"This script program creates a registry .REG file that removes Windows' mouse acceleration," _
		& " or emulates Windows 2000 or Windows 98 or Windows 95 acceleration." _
		& vbNewLine & vbNewLine _
		& "The registry fix created works like the CPL and Cheese and MarkC fixes," _
		& " but is customized for your specific desktop display text size (DPI)," _
		& " your specific mouse pointer speed slider setting, your specific refresh rate" _
		& " and has any pointer speed scaling/sensitivity factor you want." _
		& vbNewLine & vbNewLine _
		& "Enter the operating system that the fix will be used for." _
		& vbNewLine & vbNewLine _
		& "1/XP+Vista   	= Windows XP or Vista" & vbNewLine _
		& "2/Windows 7  	= Windows 7" & vbNewLine _
		& "3/Windows 8.x	= Windows 8.1 or 8" & vbNewLine _
		& "4/Windows 10 	= Windows 10", _
		"Operating System - MarkC Mouse Acceleration Fix", FixType)
	select case LCase(FixType)
	case ""
		WScript.Quit
	case "1", "xp", "vista", "xpvista", "xp+vista", "xp or vista"
		FixType = XPVistaFix
		exit do
	case "2", "7", "win7", "windows7", "windows 7"
		FixType = Windows7Fix
		DPI = int((100*DPI/96)+0.5) ' round() rounds to even: we don't want that
		exit do
	case "3", "8", "win8", "windows8", "windows 8", "8.1", "win8.1", "windows8.1", "windows 8.1", "windows 8.x"
		FixType = Windows8Fix
		DPI = int((100*DPI/96)+0.5) ' round() rounds to even: we don't want that
		exit do
	case "4", "10", "win10", "windows10", "windows 10"
		FixType = Windows10Fix
		DPI = int((100*DPI/96)+0.5) ' round() rounds to even: we don't want that
		exit do
	case else
		WshShell.Popup "'" & FixType & "' is not valid.",, "Error", vbExclamation
	end select
loop while true

' Get the display DPI the fix will be used with
dim CurrentDPI : CurrentDPI = DPI
do
	dim NumDPI
	if FixType = XPVistaFix then
		DPI = InputBox( _
			"Enter the desktop Control Panel, Display, font size (DPI) scaling setting that will be used." _
			& vbNewLine & vbNewLine _
			& "Your current font size (DPI) is " & CurrentDPI & ".", _
			"Display DPI - MarkC Mouse Acceleration Fix", DPI)
		if DPI = "" then WScript.Quit
		if IsNumeric(DPI) then 
			NumDPI = CInt(DPI)
			if NumDPI > 0 and CStr(NumDPI) = DPI then DPI = NumDPI : exit do
		end if
		WshShell.Popup "'" & DPI & "' is not valid.",, "Error", vbExclamation
	else if FixType = Windows7Fix then
		if InStr(DPI,"%") = 0 then DPI = DPI & "%"
		if InStr(CurrentDPI,"%") = 0 then CurrentDPI = CurrentDPI & "%"
		DPI = InputBox( _
			"Enter the desktop Control Panel, Display, text size (DPI) that will be used." _
			& vbNewLine & vbNewLine _
			& "Your current text size (DPI) is " & CurrentDPI & ".", _
			"Text Size DPI - MarkC Mouse Acceleration Fix", DPI)
		if DPI = "" then WScript.Quit
		if InStr(DPI,"%") = len(DPI) and IsNumeric(left(DPI,len(DPI)-1)) then
			NumDPI = CInt(left(DPI,len(DPI)-1))
			if NumDPI > 0 and CStr(NumDPI) & "%" = DPI then DPI = NumDPI : exit do
		end if
		WshShell.Popup "'" & DPI & "' is not valid.",, "Error", vbExclamation
	else ' Windows10Fix or Windows8Fix
		if InStr(DPI,"%") = 0 then DPI = DPI & "%"
		if InStr(CurrentDPI,"%") = 0 then CurrentDPI = CurrentDPI & "%"
		dim Windows81Text : Windows81Text = ""
		if OSVersionNumber >= "6.3" then _
			Windows81Text = "If not using one scaling level for all displays, then" _
				& vbNewLine & "- the 1st slider position should be 100%," _
				& vbNewLine & "- the 2nd slider position should be 125%," _
				& vbNewLine & "- the 3rd slider position (might not be shown) should be 150%" _
				& vbNewLine _
				& vbNewLine & "(Very high DPI monitors might need a custom size to get exact 1-to-1.)" _
				& vbNewLine & vbNewLine
		DPI = InputBox( _
			"Enter the desktop Settings, Display, Scale and layout, size of items setting that will be used." _
			& vbNewLine & vbNewLine _
			& Windows81Text _
			& "Your current size of items setting is " & CurrentDPI & ".", _
			"Items Size - MarkC Mouse Acceleration Fix", DPI)
		if DPI = "" then WScript.Quit
		if InStr(DPI,"%") = len(DPI) and IsNumeric(left(DPI,len(DPI)-1)) then
			NumDPI = CInt(left(DPI,len(DPI)-1))
			if NumDPI > 0 and CStr(NumDPI) & "%" = DPI then DPI = NumDPI : exit do
		end if
		WshShell.Popup "'" & DPI & "' is not valid.",, "Error", vbExclamation
	end if end if
loop while true

if FixType = XPVistaFix then
	' Get the monitor refresh rate the fix will be used with
	for each VideoController in WMIService.InstancesOf("Win32_VideoController")
		RefreshRate = VideoController.CurrentRefreshRate
		if not IsNull(RefreshRate) then exit for
	next
	if IsNull(RefreshRate) then
		for each VideoController in WMIService.InstancesOf("Win32_DisplayConfiguration")
			RefreshRate = VideoController.DisplayFrequency
			if not IsNull(RefreshRate) then exit for
		next
	end if
	if IsNull(RefreshRate) then RefreshRate = "(unknown)"
	dim CurrentRefreshRate : CurrentRefreshRate = RefreshRate
	do
		RefreshRate = InputBox( _
			"Enter the in-game monitor refresh rate that will be used." _
			& vbNewLine & vbNewLine _
			& "NOTE: Your desktop refresh rate is " & CurrentRefreshRate & "Hz." _
			& vbNewLine & vbNewLine _
			& "Enter the refresh rate USED BY YOUR GAME, when the fix will be active.", _
			"Refresh Rate - MarkC Mouse Acceleration Fix", RefreshRate)
		if RefreshRate = "" then WScript.Quit
		if IsNumeric(RefreshRate) then
			dim NumRefreshRate : NumRefreshRate = CInt(RefreshRate)
			if NumRefreshRate > 0 and CStr(NumRefreshRate) = RefreshRate then RefreshRate = NumRefreshRate : exit do
		end if
		WshShell.Popup "'" & RefreshRate & "' is not valid, enter a number.",, "Error", vbExclamation
	loop while true
end if

' Get the pointer speed slider setting the fix will be used with
MouseSensitivity = CInt(WshShell.RegRead("HKEY_CURRENT_USER\Control Panel\Mouse\MouseSensitivity"))
if MouseSensitivity > 2 then PointerSpeed = MouseSensitivity / 2 + 1 else PointerSpeed = MouseSensitivity
dim CurrentPointerSpeed : CurrentPointerSpeed = PointerSpeed
do
	PointerSpeed = InputBox( _
		"Enter the Control Panel, Mouse, pointer speed slider position that will be used." _
		& vbNewLine & vbNewLine _
		& "1	= extreme left, Slow" & vbNewLine _
		& "2-5" & vbNewLine _
		& "6	= middle, 6/11 position" & vbNewLine _
		& "7-10	" & vbNewLine _
		& "11	= extreme right, Fast" _
		& vbNewLine & vbNewLine _
		& "Your current pointer speed slider position is " & CurrentPointerSpeed & ".", _
		"Pointer Speed Slider - MarkC Mouse Acceleration Fix", CStr(PointerSpeed))
	if PointerSpeed = "" then WScript.Quit
	if IsNumeric(PointerSpeed) then
		dim NumSpeed : NumSpeed = CDbl(PointerSpeed)
		if NumSpeed >= 1 and NumSpeed <= 11 _
				and (NumSpeed = 1 or (NumSpeed >= 2 and int(2*NumSpeed) = 2*NumSpeed)) then
			PointerSpeed = NumSpeed
			exit do
		end if
	end if
	WshShell.Popup "'" & PointerSpeed & "' is not valid.",, "Error", vbExclamation
loop while true

' Convert pointer speed slider to a numeric sensitivity
if PointerSpeed > 2 then MouseSensitivity = CInt(2*PointerSpeed - 2) else MouseSensitivity = CInt(PointerSpeed)
if MouseSensitivity <= 2 then
	MouseSensitivityFactor = MouseSensitivity / 32
elseif MouseSensitivity <= 10 then
	MouseSensitivityFactor = (MouseSensitivity-2) / 8
else
	MouseSensitivityFactor = (MouseSensitivity-6) / 4
end if

' Get the number of pointer acceleration zones
SpeedSteps = "No acceleration" : Threshold1 = 0 : Threshold2 = 0
do
	dim SpeedStepsPrompt
	if FixType = Windows10Fix then
		SpeedStepsPrompt = _
			"Enter the number of pointer speed acceleration zones that you want." & vbNewLine & vbNewLine _
			& "0 = No acceleration" & vbNewLine _
			& "1 = Accelerate the pointer speed when the mouse is faster than a threshold" & vbNewLine _
			& "2 = [Not available for Windows 10]" & vbNewLine _
			& vbNewLine _
			& "Low	= Emulate Windows 2000 Low accel" & vbNewLine _
			& "Medium	= [Not available for Windows 10]" & vbNewLine _
			& "High	= [Not available for Windows 10]" & vbNewLine _
			& vbNewLine _
			& "2/7  = Emulate Windows 95+98 2/7 pointer speed" & vbNewLine _
			& "3/7  = Emulate Windows 95+98 3/7 pointer speed" & vbNewLine _
			& "4/7  = Emulate Windows 95+98 4/7 pointer speed" & vbNewLine _
			& "5+/7 = [Not available for Windows 10]"
	else
		SpeedStepsPrompt = _
			"Enter the number of pointer speed acceleration zones that you want." & vbNewLine & vbNewLine _
			& "0 = No acceleration" & vbNewLine _
			& "1 = Accelerate the pointer speed when the mouse is faster than a threshold" & vbNewLine _
			& "2 = Accelerate the pointer speed when the mouse is faster than threshold 1," _
			& " and accelerate again when the mouse is faster than threshold 2" & vbNewLine _
			& vbNewLine _
			& "Low	= Emulate Windows 2000 Low accel" & vbNewLine _
			& "Medium	= Emulate Windows 2000 Medium accel" & vbNewLine _
			& "High	= Emulate Windows 2000 High accel" & vbNewLine _
			& vbNewLine _
			& "2/7  = Emulate Windows 95+98 2/7 pointer speed" & vbNewLine _
			& "n/7  = Emulate Windows 95+98 n/7 pointer speed" & vbNewLine _
			& "7/7  = Emulate Windows 95+98 7/7 pointer speed"
	end if
	SpeedSteps = InputBox(SpeedStepsPrompt, "Pointer Speed Acceleration - MarkC Mouse Acceleration Fix", SpeedSteps)
	if SpeedSteps = "" then WScript.Quit
	select case LCase(SpeedSteps)
	case "0", "no acceleration", "none", "no"
		SpeedSteps = 0
		exit do
	case "low"
		SpeedSteps = 1 : Threshold1 = 7
		OldWindowsAccelName = "Windows 2000 Low" : OldWindowsAccelCode = "W2K_Low"
		exit do
	case "medium"
		SpeedSteps = 2 : Threshold1 = 4 : Threshold2 = 12
		OldWindowsAccelName = "Windows 2000 Medium" : OldWindowsAccelCode = "W2K_Medium"
		exit do
	case "high"
		SpeedSteps = 2 : Threshold1 = 4 : Threshold2 = 6
		OldWindowsAccelName = "Windows 2000 High" : OldWindowsAccelCode = "W2K_High"
		exit do
	case "2/7", "3/7", "4/7", "5/7", "6/7", "7/7"
		OldWindowsAccelName = "Windows 95+98 " & SpeedSteps
		OldWindowsAccelCode = "W95+98_" & Replace(SpeedSteps, "/", "of")
		select case SpeedSteps
		case "2/7"
			SpeedSteps = 1 : Threshold1 = 10
		case "3/7"
			SpeedSteps = 1 : Threshold1 = 7
		case "4/7"
			SpeedSteps = 1 : Threshold1 = 4
		case "5/7"
			SpeedSteps = 2 : Threshold1 = 4 : Threshold2 = 12
		case "6/7"
			SpeedSteps = 2 : Threshold1 = 4 : Threshold2 = 9
		case "7/7"
			SpeedSteps = 2 : Threshold1 = 4 : Threshold2 = 6
		end select
		exit do
	end select
	if IsNumeric(SpeedSteps) then
		dim NumSpeedSteps : NumSpeedSteps = CInt(SpeedSteps)
		if NumSpeedSteps >= 0 and NumSpeedSteps <= 2 and CStr(NumSpeedSteps) = SpeedSteps then _
			SpeedSteps = NumSpeedSteps : exit do
	end if
	WshShell.Popup "'" & SpeedSteps & "' is not valid.",, "Error", vbExclamation
loop while true
' Record standard thresholds for info messages later
if OldWindowsAccelName <> "" then OldWindowsThreshold1 = Threshold1 : OldWindowsThreshold2 = Threshold2

' SpeedSteps = 2 causes BugCheck/BSOD on Windows 10 x64
if FixType = Windows10Fix and SpeedSteps = 2 then
	WshShell.Popup _
		"2 pointer speed acceleration zones are not available for Windows 10," _
		& " because it causes BugChecks/BSOD.", , _
		"Not available for Windows 10", vbCritical
	WScript.Quit
end if

' Get the scaling (sensitivity) factor
dim SegmentText, ThresholdText
if SpeedSteps > 0 then
	SegmentText = " when the pointer is not accelerated,"
	if MouseSensitivityFactor = 1 then ScalingDescr = "1-to-1" else ScalingDescr = CStr(MouseSensitivityFactor)
	ThresholdText = vbNewLine _
		& vbNewLine _
		& "The pointer speed factor used by Windows 2000 at " & CStr(PointerSpeed) & "/11 is " _
		& ScalingDescr & "." & vbNewLine _
		& "The pointer speed factor used by Windows 95+98 is 1-to-1."
end if
Scaling = "1-to-1"
if FixType = XPVistaFix then
	DPISensitivity = (Max(60,RefreshRate)/Max(96,DPI)) * 96 / 60
	EPPOffMouseScaling = 1
else
	DPISensitivity = round(DPI*96/100)/96
	if EPPOffMouseScaling = -1 then EPPOffMouseScaling = DPISensitivity
end if
do
	Scaling = InputBox( _
		"Enter the pointer speed scaling (sensitivity) factor that you want" & SegmentText _
		& " when the pointer speed slider is at the " & CStr(PointerSpeed) & "/11 position." _
		& vbNewLine & vbNewLine _
		& "1/1-to-1	= Exactly 1-to-1 (RECOMMENDED)" & vbNewLine _
		& "E	= x " & CStr(DPISensitivity * MouseSensitivity/10) & " (same as EPP=ON, enter 'E')" & vbNewLine _
		& "N	= x " & Cstr(EPPOffMouseScaling * MouseSensitivityFactor) & " (same as EPP=OFF, enter 'N')" & vbNewLine _
		& replace(CStr(1.111),"1","n",1,-1) & "	= a custom speed factor (example: " & CStr(1.25) & ")" _
		& ThresholdText, _
		"Pointer Speed Scaling - MarkC Mouse Acceleration Fix", Scaling)
	if Scaling = "" then WScript.Quit
	select case LCase(Scaling)
	case "1", "1-to-1", "1/1-to-1"
		Scaling = 1
		exit do
	case "e"
		Scaling = DPISensitivity * MouseSensitivity/10
		exit do
	case "n"
		Scaling = EPPOffMouseScaling * MouseSensitivityFactor
		exit do
	end select
	if IsNumeric(Scaling) then if CDbl(Scaling) > 0 and CDbl(Scaling) <= 16 then Scaling = CDbl(Scaling) : exit do
	WshShell.Popup "'" & Scaling & "' is not valid.",, "Error", vbExclamation
loop while true

dim NumThreshold, ThresholdNotes
if SpeedSteps > 0 then
	' Get the first (or only) threshold and sensitivity when speed is > threshold1
	if MsgBox("Notes:" & vbNewLine _
		& vbNewLine _
		& "- If your current mouse has a different polling rate than the mouse you used with" _
		& " your old version of Windows, then the thresholds may need to be adjusted before" _
		& " mouse response will be similar." & vbNewLine _
		& vbNewLine _
		& "- Acceleration will most closely match your old version of Windows for movements" _
		& " that are mainly horizontal or mainly vertical." & vbNewLine _
		& "If your mouse movements are often diagonal or at an angle, then the thresholds may" _
		& " need to be increased by 10% to 30% before mouse response will be similar." & vbNewLine _
		& vbNewLine _
		& "- See file !Threshold_Acceleration_ReadMe.txt for guidance.", _
		vbOKCancel + vbInformation, "Acceleration Thresholds - MarkC Mouse Acceleration Fix") <> vbOK then WScript.Quit
	do ' Get threshold1
		if SpeedSteps = 1 then
			SegmentText = ""
		else
			SegmentText = "first "
		end if
		ThresholdText = ""
		if OldWindowsAccelName <> "" then _
			ThresholdText = vbNewLine & vbNewLine _
				& "The " & SegmentText & "threshold for " & OldWindowsAccelName & " acceleration is " _
				& OldWindowsThreshold1 & "."
		Threshold1 = InputBox( _
			"Enter the " & SegmentText & "acceleration threshold that you want." & vbNewLine _
			& vbNewLine _
			& "When the mouse is faster than this, the pointer speed will be accelerated." & vbNewLine _
			& vbNewLine _
			& "See the !Threshold_Acceleration_ReadMe.txt file for guidance." _
			& ThresholdText, _
			"Pointer Speed Acceleration - MarkC Mouse Acceleration Fix", Threshold1)
		if Threshold1 = "" then WScript.Quit
		if IsNumeric(Threshold1) then
			NumThreshold = CInt(Threshold1)
			if NumThreshold > 0 and CStr(NumThreshold) = Threshold1 then Threshold1 = NumThreshold : exit do
		end if
		WshShell.Popup "'" & Threshold1 & "' is not valid (must be greater than 0).",, "Error", vbExclamation
	loop while true

	ThresholdText = vbNewLine _
		& vbNewLine _
		& "The pointer speed factor used by Windows 2000 at " & CStr(PointerSpeed) & "/11 is " _
		& CStr(2*MouseSensitivityFactor) & "." & vbNewLine _
		& "The pointer speed factor used by Windows 95+98 is 2."
	ScalingAfterThreshold1 = 2 * Scaling
	do ' Get the scaling (sensitivity) factor when faster than threshold1
		ScalingAfterThreshold1 = InputBox( _
			"Enter the pointer speed scaling (sensitivity) factor that you want" _
			& " when the mouse is faster than " & CStr(Threshold1) & "." _
			& ThresholdText, _
			"Pointer Speed Scaling - MarkC Mouse Acceleration Fix", ScalingAfterThreshold1)
		if ScalingAfterThreshold1 = "" then WScript.Quit
		if IsNumeric(ScalingAfterThreshold1) then _
			if CDbl(ScalingAfterThreshold1) > Scaling and CDbl(ScalingAfterThreshold1) <= 16 then _
				ScalingAfterThreshold1 = CDbl(ScalingAfterThreshold1) : exit do
		WshShell.Popup "'" & ScalingAfterThreshold1 & "' is not valid (must be greater than " & CStr(Scaling) & ")." _
			,, "Error", vbExclamation
	loop while true
end if

if SpeedSteps = 2 then
	' Get the second threshold and sensitivity when speed is > threshold2
	do ' Get threshold2
		ThresholdText = ""
		if OldWindowsAccelName <> "" then _
			ThresholdText = vbNewLine & vbNewLine _
				& "The second threshold for " & OldWindowsAccelName & " acceleration is " & OldWindowsThreshold2 & "."
		Threshold2 = InputBox( _
			"Enter the second acceleration threshold that you want." & vbNewLine _
			& vbNewLine _
			& "When the mouse is faster than this, the pointer speed will be further accelerated." & vbNewLine _
			& vbNewLine _
			& "See the !Threshold_Acceleration_ReadMe.txt file for guidance." _
			& ThresholdText, _
			"Pointer Speed Acceleration - MarkC Mouse Acceleration Fix", Threshold2)
		if Threshold2 = "" then WScript.Quit
		if IsNumeric(Threshold2) then
			NumThreshold = CInt(Threshold2)
			if NumThreshold > Threshold1 and CStr(NumThreshold) = Threshold2 then Threshold2 = NumThreshold : exit do
		end if
		WshShell.Popup "'" & Threshold2 & "' is not valid (must be greater than " & CStr(Threshold1) & ")." _
			,, "Error", vbExclamation
	loop while true

	ThresholdText = vbNewLine _
		& vbNewLine _
		& "The pointer speed factor used by Windows 2000 at " & CStr(PointerSpeed) & "/11 is " _
		& CStr(4*MouseSensitivityFactor) & "." & vbNewLine _
		& "The pointer speed factor used by Windows 95+98 is 4."
	ScalingAfterThreshold2 = 4 * Scaling
	do ' Get the scaling (sensitivity) factor when faster than threshold1
		ScalingAfterThreshold2 = InputBox( _
			"Enter the pointer speed scaling (sensitivity) factor that you want" _
			& " when the mouse is faster than " & CStr(Threshold2) & "." _
			& ThresholdText, _
			"Pointer Speed Scaling - MarkC Mouse Acceleration Fix", ScalingAfterThreshold2)
		if ScalingAfterThreshold2 = "" then WScript.Quit
		if IsNumeric(ScalingAfterThreshold2) then _
			if CDbl(ScalingAfterThreshold2) > ScalingAfterThreshold1 and CDbl(ScalingAfterThreshold2) <= 16 then _
				ScalingAfterThreshold2 = CDbl(ScalingAfterThreshold2) : exit do
		WshShell.Popup "'" & ScalingAfterThreshold2 & "' is not valid (must be greater than " _
			& CStr(ScalingAfterThreshold1) & ")." _
			,, "Error", vbExclamation
	loop while true
end if

' Get the folder where the fix is to be created
set Shell = CreateObject("Shell.Application")
const BIF_RETURNONLYFSDIRS   = &h0001
const BIF_RETURNFSANCESTORS  = &h0008
const BIF_NEWDIALOGSTYLE 	 = &h0040
const BIF_NONEWFOLDERBUTTON  = &h0200
const BIF_SHAREABLE          = &h8000
set Folder = Shell.BrowseForFolder(0, _
	"Select the folder where the registry mouse acceleration fix will be saved.", _
	BIF_NEWDIALOGSTYLE or BIF_RETURNONLYFSDIRS or BIF_RETURNFSANCESTORS or BIF_NONEWFOLDERBUTTON)
if Folder is nothing then WScript.Quit
FolderName = Folder.Self.Path

' Sanity check on folder name
set FileSystem = CreateObject("Scripting.FileSystemObject")
if not FileSystem.FolderExists(FolderName) then
	WshShell.Popup "'" & Folder.Title & "' is not a usable folder.",, "Invalid Folder", vbExclamation
	WScript.Quit
end if

' Get a suggested filename for the registry fix
dim ScalingConfirmText
if SpeedSteps = 0 then
	if Scaling = 1 then ScalingDescr = "1-to-1" else ScalingDescr = "x" & CStr(Scaling)
	if Scaling = 1 then ScalingConfirmText = "1-to-1" else ScalingConfirmText = "x " & CStr(Scaling)
else
	ScalingDescr = ""
	if OldWindowsAccelCode <> "" then
		ScalingDescr = OldWindowsAccelCode & "_"
		ScalingConfirmText = OldWindowsAccelName
	end if
	ScalingDescr = ScalingDescr & "x" & CStr(Scaling) & "_x" & CStr(ScalingAfterThreshold1) & "@" & Threshold1 & "+" 
	ScalingConfirmText = ScalingConfirmText & vbNewLine _
		& vbTab & "x " & CStr(Scaling) & vbNewLine _
		& vbTab & "x " & CStr(ScalingAfterThreshold1) & " when >= " & Threshold1
	if SpeedSteps = 2 then
		ScalingDescr = ScalingDescr & "_x" & CStr(ScalingAfterThreshold2) & "@" & Threshold2 & "+" 
		ScalingConfirmText = ScalingConfirmText & vbNewLine _
			& vbTab & "x " & CStr(ScalingAfterThreshold2) & " when >= " & Threshold2
	end if
end if
if FixType = XPVistaFix then
	if SpeedSteps = 0 then
		RegFilename = "XP+Vista_MouseFix_@" & RefreshRate & "Hz_DPI=" & DPI _
			& "_Scale=" & ScalingDescr & "_@" & PointerSpeed & "-of-11"
	else
		RegFilename = "XP+Vista_MouseFix_Scale=" & ScalingDescr _
			& "_@" & RefreshRate & "Hz_DPI=" & DPI & "_@" & PointerSpeed & "-of-11"
	end if
	OSConfirmText = _
		"OS : XP or Vista" & vbNewLine _
		& "Desktop monitor DPI : " & DPI & vbNewLine _
		& "In-game refresh rate : " & RefreshRate & "Hz" & vbNewLine
else if FixType = Windows7Fix then
	OSConfirmText = "OS : Windows 7"
	RegFilename = "Windows_7"
	if SpeedSteps = 0 then
		RegFilename = RegFilename & "_MouseFix_TextSize(DPI)=" & DPI _
			& "%_Scale=" & ScalingDescr & "_@" & PointerSpeed & "-of-11"
	else
		RegFilename = RegFilename & "_MouseFix_Scale=" & ScalingDescr _
			& "_TextSize(DPI)=" & DPI & "%_@" & PointerSpeed & "-of-11"
	end if
	OSConfirmText = OSConfirmText & vbNewLine _
		& "Text size (DPI) : " & DPI & "%" & vbNewLine
else
	if SpeedSteps = 0 then
		OSConfirmText = "OS : Windows 10 or 8.1 or 8"
		RegFilename = "Windows_10+8.x"
	else if FixType = Windows10Fix then
		OSConfirmText = "OS : Windows 10"
		RegFilename = "Windows_10"
	else
		OSConfirmText = "OS : Windows 8.1 or 8"
		RegFilename = "Windows_8.x"
	end if end if
	if SpeedSteps = 0 then
		RegFilename = RegFilename & "_MouseFix_ItemsSize=" & DPI _
			& "%_Scale=" & ScalingDescr & "_@" & PointerSpeed & "-of-11"
	else
		RegFilename = RegFilename & "_MouseFix_Scale=" & ScalingDescr _
			& "_ItemsSize=" & DPI & "%_@" & PointerSpeed & "-of-11"
	end if
	OSConfirmText = OSConfirmText & vbNewLine _
		& "All items size : " & DPI & "%" & vbNewLine
end if end if
RegComment = RegFilename
RegFilename = RegFilename & ".reg"

' Ask for confirmation of parameters and filename
RegFilename = InputBox( _
	"Confirm the fix details and click OK." _
	& vbNewLine & vbNewLine _
	& OSConfirmText _
	& "Pointer speed slider : " & PointerSpeed & "/11" & vbNewLine _
	& "Pointer speed scaling : " & ScalingConfirmText & vbNewLine _
	& "Save to folder : " & FolderName & vbNewLine _
	& "Save to file : (file name below)", _
	"Save Fix - MarkC Mouse Acceleration Fix", RegFilename)
if RegFilename = "" then WScript.Quit

' Check and open the file
RegFilename = FileSystem.BuildPath(FolderName, FileSystem.GetBaseName(RegFilename) & ".reg")
if FileSystem.FileExists(RegFilename) then
	if WshShell.Popup( _
			RegFilename & " already exists." & vbNewLine & "Do you want to replace it?", , _
			"Save As", vbExclamation or vbYesNo) <> vbYes then
		WScript.Quit
	end if
end if
set RegFile = FileSystem.CreateTextFile(RegFilename, True)

' Compute the magic SmoothMouseCurve numbers
if FixType = Windows10Fix or FixType = Windows8Fix then
	DPI = round(DPI*96/100)
	DPIFactor = B(Max(96,DPI)/120)
else if FixType = Windows7Fix then
	DPI = round(DPI*96/100)
	DPIFactor = B(Max(96,DPI)/150)
else
	DPIFactor = B(Max(60,RefreshRate)/Max(96,DPI))
end if end if

if SpeedSteps = 0 then

	' No acceleration anywhere on the curve; original acceleration fix curve
	SmoothY = B(16*3.5)
	if MouseSensitivity  = 1 then SmoothY = SmoothY * 2 ' Ensure we
	if MouseSensitivity <= 2 then SmoothY = SmoothY * 2 ' have enough
	if Scaling > 3 then SmoothY = SmoothY * 2           ' bits of
	if Scaling > 6 then SmoothY = SmoothY * 2           ' precision
	if Scaling > 9 then SmoothY = SmoothY * 2           ' using
	if Scaling > 12 then SmoothY = SmoothY * 2          ' somewhat arbitrary
	if DPI > 144 and Scaling > 1 then SmoothY = SmoothY * 2 ' rules

	SmoothYPixels = BMult(BMult(SmoothY, DPIFactor), B(MouseSensitivity/10))
	SmoothX = B(SmoothYPixels/(B(Scaling)*3.5))
	' Make sure the magic numbers give the exact result
	SmoothY = GetSmoothY(SmoothX, Scaling, 0, 0)
	' if ActualScaling <> B(Scaling) now, then I don't care: close enough!

	SmoothX0 = 0
	SmoothX1 = SmoothX
	SmoothX2 = 2*SmoothX
	SmoothX3 = 3*SmoothX
	SmoothX4 = 4*SmoothX
	SmoothY0 = 0
	SmoothY1 = SmoothY
	SmoothY2 = 2*SmoothY
	SmoothY3 = 3*SmoothY
	SmoothY4 = 4*SmoothY

else if SpeedSteps = 1 then

	' Windows 2000 and earlier style 'step-up' acceleration with 1 threshold
	' Mouse movement > the threshold uses higher scaling
	SmoothX0 = 0
	SmoothY0 = 0

	SmoothX1 = 0
	SmoothY1 = 0

	' A segment for speeds lower than Threshold1
	SmoothX2 = round((Threshold1 + 0.75)/3.5 * 8) * &h2000
	SmoothY2 = GetSmoothY(SmoothX2, Scaling, 0, 0)

	SmoothX3 = 0
	SmoothY3 = 0

	' A segment for speeds higher than Threshold1
	SmoothX4 = B(40)
	SmoothY4 = GetSmoothY(SmoothX4, ScalingAfterThreshold1, 0, 0)

else if SpeedSteps = 2 then

	if FixType = Windows10Fix then WScript.Quit

	' Windows 2000 and earlier style 'step-up' acceleration with 2 thresholds
	' Mouse movement > threshold1 uses higher scaling, > threshold2 uses even higher scaling
	' Check for a blog about this @ 

	' A magic segment -1>0 with SmoothX=Threshold1 (and the same slope as segment 0>1)
	SmoothX0 = round((Threshold1 + 0.75)/3.5 * 8) * &h2000
	SmoothY0 = GetSmoothY(SmoothX0, ScalingAfterThreshold1, 0, 0)

	' A segment for speeds higher than Threshold1 and lower than Threshold2
	SmoothX1 = round((Threshold2 + 0.75)/3.5 * 8) * &h2000
	SmoothY1 = GetSmoothY(SmoothX1, ScalingAfterThreshold1, SmoothX0, SmoothY0)

	SmoothX2 = 0
	SmoothY2 = 0

	' A segment for speeds higher than Threshold2 (and lower than a magic high limit)
	if ScalingAfterThreshold2 <= 4 then
		SmoothX3 = B(&h900)
	else
		SmoothX3 = B(int(&h900 * 4 / ScalingAfterThreshold2))
	end if
	SmoothY3 = GetSmoothY(SmoothX3, ScalingAfterThreshold2, 0, 0)
	
	' A magic segment with the scaling for speeds lower than Threshold1
	SmoothX4 = B(&h24920000) ' A bit less than 2^31/3.5
	SmoothY4 = -BDiv(BDiv(-B(Scaling), B(MouseSensitivity/10)), DPIFactor)

else
	Err.Raise 0,, "Invalid value for SpeedSteps."
end if end if end if

' Write the registry fix to the file
RegFile.WriteLine "Windows Registry Editor Version 5.00"
RegFile.WriteLine "; " & RegComment
RegFile.WriteLine
RegFile.WriteLine "[HKEY_CURRENT_USER\Control Panel\Mouse]"
RegFile.WriteLine
RegFile.WriteLine """MouseSensitivity""=""" & MouseSensitivity & """"
RegFile.WriteLine """SmoothMouseXCurve""=hex:\"
RegFile.WriteLine vbTab & CurveHex(SmoothX0) & ",\"
RegFile.WriteLine vbTab & CurveHex(SmoothX1) & ",\"
RegFile.WriteLine vbTab & CurveHex(SmoothX2) & ",\"
RegFile.WriteLine vbTab & CurveHex(SmoothX3) & ",\"
RegFile.WriteLine vbTab & CurveHex(SmoothX4)
RegFile.WriteLine """SmoothMouseYCurve""=hex:\"
RegFile.WriteLine vbTab & CurveHex(SmoothY0) & ",\"
RegFile.WriteLine vbTab & CurveHex(SmoothY1) & ",\"
RegFile.WriteLine vbTab & CurveHex(SmoothY2) & ",\"
RegFile.WriteLine vbTab & CurveHex(SmoothY3) & ",\"
RegFile.WriteLine vbTab & CurveHex(SmoothY4)
if FixType <> XPVistaFix then
	RegFile.WriteLine
	RegFile.WriteLine "[HKEY_USERS\.DEFAULT\Control Panel\Mouse]"
	RegFile.WriteLine
	RegFile.WriteLine """MouseSpeed""=""0"""
	RegFile.WriteLine """MouseThreshold1""=""0"""
	RegFile.WriteLine """MouseThreshold2""=""0"""
end if
RegFile.Close

if OSVersion = FixType then

	' Confirm save
	WshShell.Popup "Mouse acceleration fix " & RegFilename & " saved.", , "Fix Saved", vbInformation

	' Offer to apply the created reg file
	dim FixApplied : FixApplied = false
	if WshShell.Popup( _
			"IMPORTANT: The fix has NOT been applied." _
			& vbNewLine & vbNewLine _
			& "To apply the fix you must:" & vbNewLine _
			& "1) Add it to the registry, then" & vbNewLine _
			& "2) Log off or reboot." _
			& vbNewLine & vbNewLine _
			& "Do you want to add the information in the fix to the registry?", , _
			"Fix Not Yet Applied", vbExclamation or vbYesNo) = vbYes then
		WshShell.Run "regedit.exe """ & RegFilename & """", 1, True ' Wait for regedit to exit
		' Check it has been merged
		dim SmoothMouseXCurveBytes, SmoothMouseYCurveBytes
		SmoothMouseXCurveBytes = WshShell.RegRead("HKEY_CURRENT_USER\Control Panel\Mouse\SmoothMouseXCurve")
		SmoothMouseYCurveBytes = WshShell.RegRead("HKEY_CURRENT_USER\Control Panel\Mouse\SmoothMouseYCurve")
		if CInt(WshShell.RegRead("HKEY_CURRENT_USER\Control Panel\Mouse\MouseSensitivity")) _
				= MouseSensitivity _
			and DWordFromBytes(0, SmoothMouseXCurveBytes) = SmoothX0 _
			and DWordFromBytes(1, SmoothMouseXCurveBytes) = SmoothX1 _
			and DWordFromBytes(2, SmoothMouseXCurveBytes) = SmoothX2 _
			and DWordFromBytes(3, SmoothMouseXCurveBytes) = SmoothX3 _
			and DWordFromBytes(4, SmoothMouseXCurveBytes) = SmoothX4 _
			and DWordFromBytes(0, SmoothMouseYCurveBytes) = SmoothY0 _
			and DWordFromBytes(1, SmoothMouseYCurveBytes) = SmoothY1 _
			and DWordFromBytes(2, SmoothMouseYCurveBytes) = SmoothY2 _
			and DWordFromBytes(3, SmoothMouseYCurveBytes) = SmoothY3 _
			and DWordFromBytes(4, SmoothMouseYCurveBytes) = SmoothY4 then
			FixApplied = true
		end if
	end if
	if not FixApplied then
		' Have kittens (I don't want the support headache...)
		WshShell.Popup _
			"IMPORTANT: The fix has NOT been applied!" _
			& vbNewLine & vbNewLine _
			& "To apply the fix you must:" _
			& vbNewLine & vbNewLine _
			& "1) Add it to the registry (select it in Windows Explorer and double-click it), then" _
			& vbNewLine & vbNewLine _
			& "2) Log off or reboot.", , _
			"Fix Not Applied!", vbCritical
	end if

	if FixApplied and FixType <> XPVistaFix then
		' Check if non-administrator account has prevented update to .DEFAULT\...\MouseSpeed
		dim LoginMouseSpeed
		LoginMouseSpeed = WshShell.RegRead("HKEY_USERS\.DEFAULT\Control Panel\Mouse\MouseSpeed")
		if LoginMouseSpeed <> "0" then
			on error resume next
			WshShell.RegWrite "HKEY_USERS\.DEFAULT\Control Panel\Mouse\MouseSpeed", LoginMouseSpeed
			if Err.Number <> 0 then ' RegWrite fails => non admin account
				WshShell.Popup _
					"Part of the mouse acceleration fix can't be applied," _
					& " because you are not logged in as an Administrator." _
					& vbNewLine & vbNewLine _
					& "To apply this part, run CMD file" & vbNewLine _
					& "MarkC_Disable_WelcomeScreen+Login_Accel.CMD" & vbNewLine _
					& "while logged in as an administrator" _
					& ", or see the ReadMe.txt file for more information.", , _
					"Part of Fix Not Applied!", vbCritical
			end if
			on error goto 0 ' Normal errors
		end if
	end if

else ' OSVersion <> FixType

	' Confirm save
	WshShell.Popup _
		"Mouse acceleration fix " & RegFilename & " saved." _
		& vbNewLine & vbNewLine _
		& "NOTE: The fix has NOT been applied." & vbNewLine & vbNewLine _
		& "To apply the fix you must add it to the registry then log off or reboot.", , _
		"Fix Saved", vbInformation

end if

' END

' Convert to fixed point (n.16) binary
function B(n)
	B = int(&h10000 * n)
end function

' Fixed point (n.16) binary multiply
function BMult(m1, m2)
	BMult = int(m1 * m2 / &h10000)
end function

' Fixed point (n.16) binary divide
function BDiv(n, d)
	BDiv = int(&h10000 * n / d)
end function

' Calculate the SmoothY value that gives the desired TargetScaling
function GetSmoothY(ByRef SmoothX, TargetScaling, PreviousSmoothX, PreviousSmoothY)

	dim SmoothY, ExtraX, Slope, Intercept
	dim SmoothXMickeys, SmoothYPixels, PreviousSmoothXMickeys, PreviousSmoothYPixels
	PreviousSmoothXMickeys = BMult(PreviousSmoothX, B(3.5))
	PreviousSmoothYPixels = BMult(BMult(PreviousSmoothY, DPIFactor), B(MouseSensitivity/10))

	for ExtraX = 0 to 128 ' (Can go as high as +1100 and still be Mickeys < Threshold+1)
		SmoothY = -BDiv( _
			BDiv( _
				BMult( _
					-B(TargetScaling), _
					BMult(SmoothX + ExtraX, B(3.5)) - PreviousSmoothXMickeys) _
				+ -PreviousSmoothYPixels, _
				B(MouseSensitivity/10)), _
			DPIFactor)
		if ExtraX = 0 then GetSmoothY = SmoothY ' lock in at least the first value

		' Check if SmoothY & SmoothX are exactly the right slope & intercept
		SmoothYPixels = BMult(BMult(SmoothY, DPIFactor), B(MouseSensitivity/10))
		SmoothXMickeys = BMult(SmoothX + ExtraX, B(3.5))
		Slope = BDiv(SmoothYPixels - PreviousSmoothYPixels, SmoothXMickeys - PreviousSmoothXMickeys)
		Intercept = SmoothYPixels - BMult(Slope, SmoothXMickeys)

		if Slope = B(TargetScaling) and Intercept = 0 then
			' Exact match: return
			SmoothX = SmoothX + ExtraX
			GetSmoothY = SmoothY
			exit function
		end if
		' Bump SmoothX a little & try again (eventually a calculation is usually exact for normal input values)
	next

end function

' Convert number to registry REG_BINARY hex: format
function CurveHex(n)
	dim h, ch, i, high, low6
	high = int(n / &h1000000) ' 16^6: 6 hex digits
	low6 = n - &h1000000 * high
	h = right("00000" & hex(high), 6) & right("00000" & hex(low6), 6)
	ch = ""
	for i = 5 to 0 step -1
		ch = ch & mid(h, i*2+1, 2) & ","
	next
	CurveHex = ch & "00,00"
end function

function Max(n1, n2)
	if n1 > n2 then
		Max = n1
	else
		Max = n2
	end if
end function

function DWordFromBytes(i, Bytes)
	i = 8*i
	DWordFromBytes = 256*(256*(256*(256*(256*Bytes(i+5) + Bytes(i+4)) + Bytes(i+3)) + Bytes(i+2)) + Bytes(i+1)) + Bytes(i)
end function