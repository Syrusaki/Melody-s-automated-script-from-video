@echo off
set Version=1.6
title Melody Video Tweaks
color 03
SetLocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul 2>&1
mode con cols=86 lines=30
cls
call :melodyLogo
echo Press any key to start...
pause > nul
cls

:: Getting Admin Permissions https://stackoverflow.com/questions/1894967/how-to-request-administrator-access-inside-a-batch-file
call :melodyLogo
echo Checking for Administrative Privelages...
timeout /t 3 /nobreak > NUL
IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)

if '%errorlevel%' NEQ '0' (
    goto UACPrompt
) else ( goto GotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params= %*
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B
	cls

:GotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
	cls

call :melodyLogo
echo Melody's settings starting...
timeout /t 3 >nul
cls

call :melodyLogo
echo Powershell Unrestricted
powershell "Set-ExecutionPolicy Unrestricted"
timeout /t 1 >nul
cls

call :melodyLogo
echo Installing DirectX Graphic Tool...
timeout /t 2 >nul
dism /online /add-capability /capabilityname:Tools.Graphics.DirectX~~~~0.0.1.0
cls

call :melodyLogo
echo You want to disable Windows Update?
echo 1. Yes
echo 2. No

set /p choice=Enter the number of the desired option and press Enter:

if "%choice%"=="1" (
	timeout /t 2 >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\EOSnotify.exe" /v "Debugger" /d "/" /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\InstallAgent.exe" /v "Debugger" /d "/" /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotification.exe" /v "Debugger" /d "/" /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MusNotificationUx.exe" /v "Debugger" /d "/" /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\remsh.exe" /v "Debugger" /d "/" /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SihClient.exe" /v "Debugger" /d "/" /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\UpdateAssistant.exe" /v "Debugger" /d "/" /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\upfc.exe" /v "Debugger" /d "/" /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\UsoClient.exe" /v "Debugger" /d "/" /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WaaSMedic.exe" /v "Debugger" /d "/" /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WaasMedicAgent.exe" /v "Debugger" /d "/" /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Windows10Upgrade.exe" /v "Debugger" /d "/" /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Windows10UpgraderApp.exe" /v "Debugger" /d "/" /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWindowsUpdate" /t REG_DWORD /d 1 /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v "OSUpgrade" /t REG_DWORD /d 0 /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v "ReservationsAllowed" /t REG_DWORD /d 0 /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsUpdate\UX\Settings" /v "TrayIconVisibility" /t REG_DWORD /d 0 /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft" /v "WindowsStore" /t REG_DWORD /d 1 /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableOSUpgrade" /t REG_DWORD /d 1 /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWindowsUpdateAccess" /t REG_DWORD /d 1 /f >nul
	reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f >nul
	reg add "HKEY_LOCAL_MACHINE\System\ControlSet001\Services\DoSvc" /v "Start" /t REG_DWORD /d 4 /f >nul
	reg add "HKEY_LOCAL_MACHINE\System\ControlSet001\Services\UsoSvc" /v "Start" /t REG_DWORD /d 4 /f >nul
	reg add "HKEY_LOCAL_MACHINE\System\ControlSet001\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d 4 /f >nul
	reg add "HKEY_LOCAL_MACHINE\System\ControlSet001\Services\wuauserv" /v "Start" /t REG_DWORD /d 4 /f >nul
	sc stop DoSvc >nul
	sc config DoSvc start= disabled >nul
	
	sc stop UsoSvc >nul
	sc config UsoSvc start= disabled >nul
	
	sc stop WaaSMedicSvc >nul
	sc config WaaSMedicSvc start= disabled >nul
	
	sc stop wuauserv >nul
	sc config wuauserv start= disabled >nul
	cls
) else if "%choice%"=="0" (
	echo Skip disable Windows Update
	timeout /t 2 >nul
) else (
    echo Invalid option. Please choose a valid option.
)
cls
	
call :melodyLogo
echo Disable Windows Defender
timeout /t 2 >nul
echo reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d 4 /f ^>nul >> "%temp%\defender.bat"
echo reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d 4 /f ^>nul >> "%temp%\defender.bat"
echo reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d 4 /f ^>nul >> "%temp%\defender.bat"
echo reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d 4 /f ^>nul >> "%temp%\defender.bat"
echo reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d 4 /f ^>nul >> "%temp%\defender.bat"
echo. >nul >> "%temp%\defender.bat"
echo reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d 4 /f ^>nul >> "%temp%\defender.bat"
echo. >nul >> "%temp%\defender.bat"
echo reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f ^>nul >> "%temp%\defender.bat"
echo reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d 1 /f ^>nul >> "%temp%\defender.bat"
echo reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 0 /f ^>nul >> "%temp%\defender.bat"
echo. >nul >> "%temp%\defender.bat"
echo reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f ^>nul >> "%temp%\defender.bat"
echo reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 1 /f ^>nul >> "%temp%\defender.bat"
echo reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d 1 /f ^>nul >> "%temp%\defender.bat"
echo reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f ^>nul >> "%temp%\defender.bat"
echo. >nul >> "%temp%\defender.bat"
echo reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d 1 /f ^>nul >> "%temp%\defender.bat"
echo. >nul >> "%temp%\defender.bat"
echo reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d 1 /f ^>nul >> "%temp%\defender.bat"
echo. >nul >> "%temp%\defender.bat"
echo reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d 1 /f ^>nul >> "%temp%\defender.bat"
echo reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d 1 /f ^>nul >> "%temp%\defender.bat"
echo. >nul >> "%temp%\defender.bat"
echo reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f ^>nul >> "%temp%\defender.bat"
echo. >nul >> "%temp%\defender.bat"
echo reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f ^>nul >> "%temp%\defender.bat"
echo. >nul >> "%temp%\defender.bat"
echo reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "DontReportInfectionInformation" /t REG_DWORD /d 0 /f ^>nul >> "%temp%\defender.bat"
move /y "%temp%\defender.bat" "C:\defender.bat" >nul
start "" MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "C:\defender.bat"
timeout /t 1 >nul
cls

call :melodyLogo
echo Uninstalling OneDrive if exist...
REM (Thx for Amitxv)
timeout /t 2 >nul
for %%a in (SysWOW64 System32) do (
    if exist "%windir%\%%a\OneDriveSetup.exe" (
        "%windir%\%%a\OneDriveSetup.exe" /uninstall
    )
)

reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1
cls

call :melodyLogo
echo Choose a browser to download:
echo 1. Thorium
echo 2. Firefox Mercury
echo 3. Brave
echo 0. None

set /p choice=Enter the number of the desired option and press Enter: 

if "%choice%"=="1" (
    echo Downloading Thorium...
    REM Command to download Thorium
	powershell Invoke-WebRequest "https://github.com/Alex313031/Thorium-Win/releases/download/M121.0.6167.204/thorium_AVX2_mini_installer.exe" -OutFile "%temp%\thorium_AVX2_mini_installer.exe" >nul 2>&1
if not exist "%temp%\thorium_AVX2_mini_installer.exe" (
    @echo Error: Failed to download Thorium browser.
    pause
    exit /b 1
)
%temp%\thorium_AVX2_mini_installer.exe /y
del /f "%temp%\thorium_AVX2_mini_installer.exe"
cls
) else if "%choice%"=="2" (
    echo Downloading Firefox Mercury...
    REM Command to download Firefox Mercury
	powershell Invoke-WebRequest "https://github.com/Alex313031/Mercury/releases/download/v.122.0.2/mercury_122.0.2_win64_AVX2_installer.exe" -OutFile "%temp%\mercury_122.0.2_win64_AVX2_installer.exe" >nul 2>&1
if not exist "%temp%\mercury_122.0.2_win64_AVX2_installer.exe" (
    @echo Error: Failed to download Mercury browser.
    pause
    exit /b 1
)
%temp%\mercury_122.0.2_win64_AVX2_installer.exe /y
del /f "%temp%\mercury_122.0.2_win64_AVX2_installer.exe"
cls
) else if "%choice%"=="3" (
    echo Downloading Brave...
    REM Command to download Brave
	powershell Invoke-WebRequest "https://github.com/brave/brave-browser/releases/download/v1.63.165/BraveBrowserStandaloneSetup.exe" -OutFile "%temp%\BraveBrowserStandaloneSetup.exe" >nul 2>&1
if not exist "%temp%\BraveBrowserStandaloneSetup.exe" (
    @echo Error: Failed to download Brave browser.
    pause
    exit /b 1
)
%temp%\BraveBrowserStandaloneSetup.exe /y
del /f "%temp%\BraveBrowserStandaloneSetup.exe"
cls
) else if "%choice%"=="0" (
	echo Skip browser install...
	timeout /t 2 >nul
) else (
    echo Invalid option. Please choose a valid option.
)
cls

call :melodyLogo
echo You want to use OpenShell?
echo 1. Yes
echo 0. No

set /p choice=Enter the number of the desired option and press Enter: 

if "%choice%"=="1" (
    echo Downloading OpenShell...
	timeout /t 1 >nul
    REM Command to download OpenShell
	powershell Invoke-WebRequest "https://github.com/Open-Shell/Open-Shell-Menu/releases/download/v4.4.191/OpenShellSetup_4_4_191.exe" -OutFile "%temp%\OpenShellSetup_4_4_191.exe" >nul 2>&1
if not exist "%temp%\OpenShellSetup_4_4_191.exe" (
    @echo Error: Failed to download OpenShell.
    pause
    exit /b 1
)
%temp%\OpenShellSetup_4_4_191.exe /quiet
del /f "%temp%\OpenShellSetup_4_4_191.exe" >nul
echo Disabling the Windows Start menu
timeout /t 2 >nul
sc stop UdkUserSvc >nul
sc config UdkUserSvc start= disable >nul
) else if "%choice%"=="0" (
    echo Skip OpenShell install...
	timeout /t 2 >nul
) else (
    echo Invalid option. Please choose a valid option.
)
cls

call :melodyLogo
echo You want to use Melody profile for Openshell?
echo 1. Yes
echo 0. No

set /p choice=Enter the number of the desired option and press Enter: 

if "%choice%"=="1" (
    echo Applying Melody Profile...
	timeout /t 1	
	if not exist "%CD%Melody.xml" (
    @echo Error: You don't have xml profile
    pause
    exit /b 1
)
"C:\Program Files\Open-Shell\StartMenu.exe" -xml "%CD%\Melody.xml"
) else if "%choice%"=="0" (
    echo Skip XML Profile install...
	timeout /t 2 >nul
) else (
    echo Invalid option. Please choose a valid option.
)
cls

call :melodyLogo
echo Mouse settings...
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >nul
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >nul
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >nul
timeout /t 1 >nul
cls

call :melodyLogo
echo Keyboard Settings...
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f >nul
timeout /t 1 >nul
cls

call :melodyLogo
echo Setting notification from Security and Maintenance...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f >nul
timeout /t 1 >nul
cls

call :melodyLogo
echo Virtual Memory...
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=false >nul
wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=16384,MaximumSize=16384 >nul
timeout /t 1 >nul
cls

call :melodyLogo
echo Visual Settings...
timeout /t 1 >NUL
sysdm.cpl ,3
echo Click on performance settings and change the appearance to performance or customize it however you like
echo Press any key to continue...
pause > nul
cls

call :melodyLogo
echo SvHostSplitThresholdInKB...
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d 4294967295 /f >nul
timeout /t 1 >nul
cls

call :melodyLogo
echo BCDEDIT Settings...
powershell bcdedit /set isolatedcontext No >nul
powershell bcdedit /set vsmlaunchtype Off >nul
powershell bcdedit /set disableelamdrivers Yes >nul
powershell bcdedit /set allowedinmemorysettings 0x0 >nul
powershell bcdedit /set loadoptions "DISABLE-LSA-ISO,DISABLE-VBS" >nul
powershell bcdedit /set pciexpress forceddisable >nul

echo You play Valorant?
echo 1. Yes
echo 0. No

set /p choice=Enter the number of the desired option and press Enter: 

if "%choice%"=="1" (
    powershell bcdedit /set nx optout >nul
)
) else if "%choice%"=="0" (
    powershell bcdedit /set nx AlwaysOff >nul
) else (
    echo Invalid option. Please choose a valid option.
)
cls

call :melodyLogo
echo Policies...
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f >NUL
timeout /t 1 >nul
cls

call :melodyLogo
echo Kernel...
reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d 222222222222222222222222222222222222222222222222222222222222222 /f >nul
reg add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d 222222222222222222222222222222222222222222222222222222222222222 /f >nul
timeout /t 1 >nul
cls

call :melodyLogo
echo Memory Management...
reg add "HKLM\System\ControlSet001\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\System\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\System\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 3 /f >nul
reg add "HKLM\System\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f >nul
timeout /t 1 >nul
cls

call :melodyLogo
echo Graphics Drivers...
reg add "HKLM\System\ControlSet001\Control\GraphicsDrivers" /v "IOMMUFlags" /t REG_DWORD /d 0 /f >nul
timeout /t 1 >nul
cls

call :melodyLogo
echo Accessibility...
reg add "HKCU\Control Panel\Accessibility\HighContrast" /v "Flags" /t REG_SZ /d "0" /f >nul
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f >nul
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f >nul
reg add "HKCU\Control Panel\Accessibility\SoundSentry" /v "Flags" /t REG_SZ /d "0" /f >nul
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f >nul
reg add "HKCU\Control Panel\Accessibility\TimeOut" /v "Flags" /t REG_SZ /d "0" /f >nul
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f >nul
timeout /t 1 >nul
cls

call :melodyLogo
echo Desktop delay...
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >nul
timeout /t 1 >nul
cls

call :melodyLogo
echo MouseClass and KeyboardClass Parameters...
reg add "HKLM\System\ControlSet001\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d 16 /f >nul
reg add "HKLM\System\ControlSet001\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d 16 /f >nul
timeout /t 1 >nul
cls

call :melodyLogo
echo Powerplan settings...
timeout /t 1 >nul
REM Activate High Performance power plan
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

REM Disable USB 3 Link Power Management
powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0

REM Disable USB Selective Suspend
powercfg /setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0

REM Set Processor performance core parking min cores to 100
powercfg /setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318583 100
powercfg /setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318584 100

REM Ask user about CPU frequency mode
set /p freqmode="Are you using static frequency (if u not sure, select no) (y/n)? "
if /i "%freqmode%"=="y" (
    REM Set Processor performance time check interval to 5000
    powercfg /setacvalueindex scheme_current 54533251-82be-4824-96c1-47b60b740d00 4d2b0152-7d5c-498b-88e2-34345392a2c5 5000
) else (
    echo Please set a static clock frequency for better performance.
	timeout /t 2 >nul
)

REM Disabling hibernation
powercfg -h off >nul
REM Update the power plan
powercfg /setactive scheme_current
cls

call :melodyLogo
echo What ur Windows version?
echo 1. Windows 10
echo 2. Windows 11

set /p choice=Enter the number of the desired option and press Enter: 

if "%choice%"=="1" (
    echo Applying internet tweaks for Windows 10
	timeout /t 2 >nul
    REM Command to download XML Profile
	powershell netsh int tcp set security profiles=disable
	netsh int tcp set global autotuninglevel=experimental
	netsh int tcp set supp internet congestionprovider=newreno
) else if "%choice%"=="2" (
    echo Applying internet tweaks for Windows 11
	timeout /t 2 >nul
	powershell netsh int tcp set security profiles=disable
	netsh int tcp set global autotuninglevel=experimental
	netsh int tcp set supp internet congestionprovider=BBR2
) else (
    echo Invalid option. Please choose a valid option.
)
cls

call :melodyLogo
echo Firewall Inbound Settings
reg add "HKLM\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DefaultInboundAction" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DefaultInboundAction" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DefaultInboundAction" /t REG_DWORD /d 0 /f >nul
timeout /t 1 >nul
cls

call :melodyLogo
echo Installing Reddists...
timeout /t 5 > nul
cls
call :melodyLogo
echo Granting permissions to C:\Windows\Temp folder...
icacls "C:\Windows\Temp" /grant Everyone:(OI)(CI)F /T > NUL
timeout /t 1 > nul
cls
REM Grant full access permissions to the Everyone group for the %temp%
call :melodyLogo
echo Granting permissions to %temp% folder...
icacls "%temp%" /grant Everyone:(OI)(CI)F /T > NUL
timeout /t 1 > nul
cls

call :melodyLogo
echo Installing Visual C++...
timeout /t 2 >nul
cls
call :melodyLogo
echo Installing Visual C++
echo.
echo Press OK on any popups
timeout /t 1 >nul
powershell Invoke-WebRequest "https://github.com/abbodi1406/vcredist/releases/download/v0.79.0/VisualCppRedist_AIO_x86_x64.exe" -OutFile "%temp%\VisualCppRedist_AIO_x86_x64.exe" >nul 2>&1
if not exist "%temp%\VisualCppRedist_AIO_x86_x64.exe" (
    @echo Error: Failed to download Visual C++ redistributable package.
    pause
    exit /b 1
)
%temp%\VisualCppRedist_AIO_x86_x64.exe /aiA /gm2
del /f "%temp%\VisualCppRedist_AIO_x86_x64.exe"
cls

call :melodyLogo
echo Installing DirectX...
timeout /t 2 >nul
curl -g -k -L -# -o "C:\dxwebsetup.exe" "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe"
start /wait C:\dxwebsetup.exe /Q
del /F /Q C:\dxwebsetup.exe
cls

call :melodyLogo
echo Installing NetFramework 4.81...
timeout /t 2 >nul
powershell -Command "Invoke-WebRequest 'https://download.microsoft.com/download/4/b/2/cd00d4ed-ebdd-49ee-8a33-eabc3d1030e3/NDP481-x86-x64-AllOS-ENU.exe' -OutFile 'C:\NDP481-x86-x64-AllOS-ENU.exe'
start /wait C:\NDP481-x86-x64-AllOS-ENU.exe /Q
del /F /Q C:\NDP481-x86-x64-AllOS-ENU.exe
cls

call :melodyLogo
echo Installing NetFramework 5 x64...
timeout /t 2 >nul
powershell -Command "Invoke-WebRequest 'https://download.visualstudio.microsoft.com/download/pr/3aa4e942-42cd-4bf5-afe7-fc23bd9c69c5/64da54c8864e473c19a7d3de15790418/windowsdesktop-runtime-5.0.17-win-x64.exe' -OutFile 'C:\windowsdesktop-runtime-5.0.17-win-x64.exe'
start /wait C:\windowsdesktop-runtime-5.0.17-win-x64.exe /Q
del /F /Q C:\windowsdesktop-runtime-5.0.17-win-x64.exe
cls

call :melodyLogo
echo Installing NetFramework 5 x86...
timeout /t 2 >nul
powershell -Command "Invoke-WebRequest 'https://download.visualstudio.microsoft.com/download/pr/b6fe5f2a-95f4-46f1-9824-f5994f10bc69/db5ec9b47ec877b5276f83a185fdb6a0/windowsdesktop-runtime-5.0.17-win-x86.exe' -OutFile 'C:\windowsdesktop-runtime-5.0.17-win-x86.exe'
start /wait C:\windowsdesktop-runtime-5.0.17-win-x86.exe /Q
del /F /Q C:\windowsdesktop-runtime-5.0.17-win-x86.exe
cls

call :melodyLogo
echo Installing NetFramework 6 x64...
timeout /t 2 >nul
powershell -Command "Invoke-WebRequest 'https://download.visualstudio.microsoft.com/download/pr/3ef3cd0c-8c7f-4146-bd8d-589d748b997e/3477d059f8fe5cceb5166b367d7995c6/windowsdesktop-runtime-6.0.27-win-x64.exe' -OutFile 'C:\windowsdesktop-runtime-6.0.27-win-x64.exe'
start /wait C:\windowsdesktop-runtime-6.0.27-win-x64.exe /Q
del /F /Q C:\windowsdesktop-runtime-6.0.27-win-x64.exe
cls

call :melodyLogo
echo Installing NetFramework 6 x86...
timeout /t 2 >nul
powershell -Command "Invoke-WebRequest 'https://download.visualstudio.microsoft.com/download/pr/a9669480-f3e0-42a6-b381-108950dfe290/b54d6613c0fa2839c41d61478926ccb9/windowsdesktop-runtime-6.0.27-win-x86.exe' -OutFile 'C:\windowsdesktop-runtime-6.0.27-win-x86.exe'
start /wait C:\windowsdesktop-runtime-6.0.27-win-x86.exe /Q
del /F /Q C:\windowsdesktop-runtime-6.0.27-win-x86.exe
cls

call :melodyLogo
echo Installing NetFramework 7 x64...
timeout /t 2 >nul
powershell -Command "Invoke-WebRequest 'https://download.visualstudio.microsoft.com/download/pr/38c809cc-858d-45ed-88f5-a7f098cab691/2e4f859f8f6cf64aa952df2a80f16d2e/windowsdesktop-runtime-7.0.16-win-x64.exe' -OutFile 'C:\windowsdesktop-runtime-7.0.16-win-x64.exe'
start /wait C:\windowsdesktop-runtime-7.0.16-win-x64.exe /Q
del /F /Q C:\windowsdesktop-runtime-7.0.16-win-x64.exe
cls

call :melodyLogo
echo Installing NetFramework 7 x84...
timeout /t 2 >nul
powershell -Command "Invoke-WebRequest 'https://download.visualstudio.microsoft.com/download/pr/ff4b13ba-07aa-4aa7-b5ae-9111c363c802/5fdedee9a9fae645bfdda3a8930c923d/windowsdesktop-runtime-7.0.16-win-x86.exe' -OutFile 'C:\windowsdesktop-runtime-7.0.16-win-x86.exe'
start /wait C:\windowsdesktop-runtime-7.0.16-win-x86.exe /Q
del /F /Q C:\windowsdesktop-runtime-7.0.16-win-x86.exe
cls

call :melodyLogo
echo Installing NetFramework 8 x64...
timeout /t 2 >nul
powershell -Command "Invoke-WebRequest 'https://download.visualstudio.microsoft.com/download/pr/84ba33d4-4407-4572-9bfa-414d26e7c67c/bb81f8c9e6c9ee1ca547396f6e71b65f/windowsdesktop-runtime-8.0.2-win-x64.exe' -OutFile 'C:\windowsdesktop-runtime-8.0.2-win-x64.exe'
start /wait C:\windowsdesktop-runtime-8.0.2-win-x64.exe /Q
del /F /Q C:\windowsdesktop-runtime-8.0.2-win-x64.exe
cls

call :melodyLogo
echo Installing NetFramework 8 x86...
timeout /t 2 >nul
powershell -Command "Invoke-WebRequest 'https://download.visualstudio.microsoft.com/download/pr/9b77b480-7e32-4321-b417-a41e0f8ea952/3922bbf5538277b1d41e9b49ee443673/windowsdesktop-runtime-8.0.2-win-x86.exe' -OutFile 'C:\windowsdesktop-runtime-8.0.2-win-x86.exe'
start /wait C:\windowsdesktop-runtime-8.0.2-win-x86.exe /Q
del /F /Q C:\windowsdesktop-runtime-8.0.2-win-x86.exe
cls

call :melodyLogo
echo Installing XNA...
timeout /t 2 >nul
curl -g -k -L -# -o "C:\XNA.msi" "https://download.microsoft.com/download/A/C/2/AC2C903B-E6E8-42C2-9FD7-BEBAC362A930/xnafx40_redist.msi"
start /wait C:\XNA.msi /Q
del /F /Q C:\XNA.msi
cls

call :melodyLogo
echo Disabling startup event trace sessions...
timeout /t 2 >nul
echo @echo off > "%temp%\perfmon_temp.bat"
echo echo Disabling startup event trace sessions... >> "%temp%\perfmon_temp.bat"
echo for /f "tokens=*" %%%%b in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger"') do ( >> "%temp%\perfmon_temp.bat"
echo     if /i "%%%%b" neq "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger" ( >> "%temp%\perfmon_temp.bat"
echo         reg add "%%%%b" /v "Start" /t REG_DWORD /d 0 /f ^>nul 2^>^&1 >> "%temp%\perfmon_temp.bat"
echo         if not errorlevel 1 ( >> "%temp%\perfmon_temp.bat"
echo             echo DWORD Start value successfully added and set to 0 at %%%%b. >> "%temp%\perfmon_temp.bat"
echo         ) else ( >> "%temp%\perfmon_temp.bat"
echo             echo Unable to add or set the DWORD Start value to 0 at %%%%b. >> "%temp%\perfmon_temp.bat"
echo         ) >> "%temp%\perfmon_temp.bat"
echo     ) >> "%temp%\perfmon_temp.bat"
echo ) >> "%temp%\perfmon_temp.bat"
echo cls >> "%temp%\perfmon_temp.bat"

move /y "%temp%\perfmon_temp.bat" "C:\perfmon.bat" >nul
start "" MinSudo.exe --NoLogo --TrustedInstaller --Privileged cmd /c "C:\perfmon.bat"
timeout /t 1 >nul
del /F /Q C:\perfmon.bat
cls

call :melodyLogo
echo Making a update framework to start on next boot...
timeout /t 5 >nul
(
  echo @echo off
  echo echo Continuing... updating Framework
  echo timeout /t 10
  echo cls
  echo start /wait "" "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe" update
  echo start /wait "" "C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe" update
  echo cd C:\Windows\System32\
  echo dism /online /cleanup-image /startcomponentcleanup /resetbase /defer
  echo cls
  echo echo restart computer to make changes...
  echo timeout /t 10
  echo del "\"%temp%\ngen_update.bat\"
) > "%temp%\ngen_update.bat"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "ngenUpdate" /t REG_SZ /d "\"%temp%\ngen_update.bat\"" /f

call :melodyLogo
echo Applying Gpedit Tweaks...
timeout /t 2 >nul
powershell Invoke-WebRequest https://github.com/Fleex255/PolicyPlus/releases/download/June2021/PolicyPlus.exe -OutFile "%temp%\PolicyPlus.exe" >nul 2>&1
echo On PolicyPlus click on share tab, IMPORT REG, select COMPUTER, select "gpedit.reg" on script folder, import and make Ctrl + S to save modifications and close
%temp%\PolicyPlus.exe
echo Press any key to continue...
pause > nul
del /F /Q %temp%\PolicyPlus.exe

call :melodyLogo
echo Finished... Restart computer to make changes
pause > nul
:melodyLogo
cls
echo  .--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--. 
echo / .. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \
echo \ \/\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ \/ /
echo  \/ /`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'\/ / 
echo  / /\                                                                            / /\ 
echo / /\ \                                                                          / /\ \
echo \ \/ /   ::::    ::::  :::::::::: :::         ::::::::  :::::::::  :::   :::    \ \/ /
echo  \/ /    +:+:+: :+:+:+ :+:        :+:        :+:    :+: :+:    :+: :+:   :+:     \/ / 
echo  / /\    +:+ +:+:+ +:+ +:+        +:+        +:+    +:+ +:+    +:+  +:+ +:+      / /\ 
echo / /\ \   +#+  +:+  +#+ +#++:++#   +#+        +#+    +:+ +#+    +:+   +#++:      / /\ \
echo \ \/ /   +#+       +#+ +#+        +#+        +#+    +#+ +#+    +#+    +#+       \ \/ /
echo  \/ /    #+#       #+# #+#        #+#        #+#    #+# #+#    #+#    #+#        \/ / 
echo  / /\    ###       ### ########## ##########  ########  #########     ###        / /\ 
echo / /\ \                                                                          / /\ \
echo \ \/ /                                                                          \ \/ /
echo  \/ /    made by rotina                                        Version: %Version%      \/ / 
echo  / /\.--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--./ /\ 
echo / /\ \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \/\ \
echo \ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `' /
echo  `--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--' 
echo.
echo.
goto :eof
