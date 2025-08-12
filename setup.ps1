[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$CID,

    [Parameter(Mandatory=$true)]
    [string]$JumpCloudConnectKey

    [Parameter(Mandatory=$true)]
    [string]$MEURL
)

# Falcon Agent Installation Variables
$falconInstallerURL = "https://cdfiles-infrastucture.s3.us-east-1.amazonaws.com/CwordStrikeFalcon-Installer.exe"
$falconInstallerTempLocation = "C:\Windows\Temp\CSFalconAgentInstaller.exe"

# JumpCloud Agent Installation Variables
$jumpCloudInstallerURL = "https://raw.githubusercontent.com/TheJumpCloud/support/master/scripts/windows/InstallWindowsAgent.ps1"
$jumpCloudInstallerTempLocation = "C:\Windows\Temp\InstallWindowsAgent.ps1"

# ManageEngine Agent Installation Variables
$manageEngineInstallerURL = "https://patch.manageengine.com/download?encapiKey=wSsVR61xrx70DKornTGqJbs%2BmQhWBFijRk99jAah4yP%2FHPzF8cc%2FwkydAgHxT%2FkdGWU7EmRAoLp6zhwE0DYJit0tzFBWCyiF9mqRe1U4J3x18bntw2XOD2s%3D&os=windows"
$manageEngineInstallerTempLocation = "$env:windir\temp\DCAgent.exe"

# Set security protocol for downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Start JumpCloud Agent Installation ---

Write-Host "--- Checking for JumpCloud Agent ---"
if (Get-Service "JumpCloudService" -ErrorAction SilentlyContinue) {
    Write-Host "JumpCloud Agent already installed, nothing to do."
} else {
    Write-Host "JumpCloud Agent not installed. Downloading now."
    try {
        Invoke-WebRequest -Uri $jumpCloudInstallerURL -OutFile $jumpCloudInstallerTempLocation
        Write-Host "Finished downloading JumpCloud Agent installer."

        Write-Host "Installing JumpCloud Agent now, this may take a few minutes."
        # This executes the downloaded script with the provided key
        & $jumpCloudInstallerTempLocation -JumpCloudConnectKey $JumpCloudConnectKey
        Write-Host "JumpCloud Agent installation command executed."
    }
    catch {
        Write-Error "Failed to install JumpCloud Agent."
        exit 1
    }
}

Write-Host " " # Add a blank line for readability

# --- Start ManageEngine Agent Installation ---

Write-Host "--- Checking for ManageEngine Agent ---"
if (Get-Service "ManageEngineDCAgent" -ErrorAction SilentlyContinue) {
    Write-Host "ManageEngine Agent already installed, nothing to do."
} else {
    Write-Host "ManageEngine Agent not installed. Downloading now."
    try {
        Invoke-WebRequest -Uri $MEURL -OutFile $manageEngineInstallerTempLocation
        Write-Host "Finished downloading ManageEngine Agent installer."

        Write-Host "Installing ManageEngine Agent now, this may take a few minutes."
        Start-Process -FilePath $manageEngineInstallerTempLocation -Wait -ArgumentList "/silent"
        Write-Host "ManageEngine Agent installation command executed."
    }
    catch {
        Write-Error "Failed to install ManageEngine Agent."
        exit 1
    }
}

#-----------------------------------------------------------------------------------------------------------------------
# Script: Azure VM Initial Setup
# Description: Automates common setup tasks for new Azure Virtual Machines.
#-----------------------------------------------------------------------------------------------------------------------

#---------------------------------------
# Download URLs - Modify if needed
#---------------------------------------
$urls = @{
    Chrome        = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
    PsTools       = "https://download.sysinternals.com/files/PSTools.zip"
    NotepadPlus   = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.8.1/npp.8.8.1.Installer.x64.exe" # Consider using 'latest' if the version changes often
}

#---------------------------------------
# Define Paths
#---------------------------------------
$DownloadPath = "C:\Temp"
if (!(Test-Path $DownloadPath)) {
    Write-Host "Creating download directory: $DownloadPath"
    New-Item -Path $DownloadPath -ItemType Directory -Force | Out-Null
}

#-----------------------------------------------------------------------------------------------------------------------
# SECTION 1: Software Installation Functions
#-----------------------------------------------------------------------------------------------------------------------

# Function to Install Google Chrome
function Install-Chrome {
    Write-Host "Installing Google Chrome..." -ForegroundColor Green
    $chromeInstaller = Join-Path -Path $DownloadPath -ChildPath "ChromeSetup.exe"
    try {
        Invoke-WebRequest -Uri $urls.Chrome -OutFile $chromeInstaller -ErrorAction Stop
        Start-Process -FilePath $chromeInstaller -ArgumentList "/silent /install" -NoNewWindow -Wait
        Write-Host "Google Chrome Installed."
    }
    catch {
        Write-Warning "Failed to install Google Chrome: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path $chromeInstaller) {
            Remove-Item $chromeInstaller -Force -ErrorAction SilentlyContinue
        }
    }
}

# Function to Install PsTools and Create Shortcut
function Install-PsTools {
    Write-Host "Installing PsTools..." -ForegroundColor Green
    $psToolsZip = Join-Path -Path $DownloadPath -ChildPath "PSTools.zip"
    $psToolsExtractPath = "C:\Program Files\PSTools" # Standardized path
    try {
        Invoke-WebRequest -Uri $urls.PsTools -OutFile $psToolsZip -ErrorAction Stop
        Expand-Archive -Path $psToolsZip -DestinationPath $psToolsExtractPath -Force
        Write-Host "PsTools extracted to $psToolsExtractPath."

        # Create a desktop shortcut
        $shortcutPath = Join-Path -Path $env:Public -ChildPath "Desktop\PsTools.lnk"
        $wshShell = New-Object -ComObject WScript.Shell
        $shortcut = $wshShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $psToolsExtractPath # Target the folder for PsTools
        $shortcut.Save()
        Write-Host "PsTools Shortcut Created on Public Desktop."
    }
    catch {
        Write-Warning "Failed to install PsTools: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path $psToolsZip) {
            Remove-Item $psToolsZip -Force -ErrorAction SilentlyContinue
        }
    }
}

# Function to Install Notepad++
function Install-NotepadPlusPlus {
    Write-Host "Installing Notepad++..." -ForegroundColor Green
    $nppInstaller = Join-Path -Path $DownloadPath -ChildPath "nppInstaller.exe"
    try {
        Invoke-WebRequest -Uri $urls.NotepadPlus -OutFile $nppInstaller -ErrorAction Stop
        Start-Process -FilePath $nppInstaller -ArgumentList "/S" -NoNewWindow -Wait # Silent install argument
        Write-Host "Notepad++ Installed."
    }
    catch {
        Write-Warning "Failed to install Notepad++: $($_.Exception.Message)"
    }
    finally {
        if (Test-Path $nppInstaller) {
            Remove-Item $nppInstaller -Force -ErrorAction SilentlyContinue
        }
    }
}



#-----------------------------------------------------------------------------------------------------------------------
# SECTION 2: System Configuration Functions
#-----------------------------------------------------------------------------------------------------------------------

# Function to Disable Server Manager Startup for All Users (Registry Method)
function Disable-ServerManagerPopupRegistry {
    Write-Host "Disabling Server Manager Popup via Registry..." -ForegroundColor Yellow
    $regPath = "HKLM:\SOFTWARE\Microsoft\ServerManager"
    $regName = "DoNotOpenServerManagerAtLogon"
    try {
        if (!(Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        New-ItemProperty -Path $regPath -Name $regName -Value 1 -PropertyType DWORD -Force
        Write-Host "Server Manager Popup (Registry) Disabled."
    }
    catch {
        Write-Warning "Failed to disable Server Manager Popup (Registry): $($_.Exception.Message)"
    }
}

# Function to Disable Server Manager Startup (Scheduled Task Method)
function Disable-ServerManagerPopupScheduledTask {
    Write-Host "Disabling Server Manager Popup via Scheduled Task..." -ForegroundColor Yellow
    try {
        Get-ScheduledTask -TaskName ServerManager -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction Stop
        Write-Host "Server Manager Popup (Scheduled Task) Disabled."
    }
    catch {
        Write-Warning "Failed to disable Server Manager Popup (Scheduled Task): $($_.Exception.Message). It might not exist or another error occurred."
    }
}

# Function to Disable User Account Control (UAC)
function Disable-UAC {
    Write-Host "Disabling UAC..." -ForegroundColor Yellow
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $regName = "EnableLUA"
    try {
        if (!(Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name $regName -Value 0 -ErrorAction Stop
        Write-Host "UAC Disabled. A restart is required for changes to take full effect."
    }
    catch {
        Write-Warning "Failed to disable UAC: $($_.Exception.Message)"
    }
}

# Function to Disable Print Spooler Service
function Disable-PrintSpooler {
    Write-Host "Disabling Print Spooler Service..." -ForegroundColor Yellow
    $serviceName = "Spooler"
    try {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -ne 'Stopped') {
                Stop-Service -Name $serviceName -Force -ErrorAction Stop
            }
            Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop
            Write-Host "Print Spooler Service Disabled."
        } else {
            Write-Host "Print Spooler Service not found."
        }
    }
    catch {
        Write-Warning "Failed to disable Print Spooler Service: $($_.Exception.Message)"
    }
}

# Function to Disable Windows Firewall
function Disable-Firewall {
    Write-Host "Disabling Windows Firewall..." -ForegroundColor Yellow
    try {
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False -ErrorAction Stop
        Write-Host "Windows Firewall Disabled for All Profiles."
    }
    catch {
        Write-Warning "Failed to disable Windows Firewall: $($_.Exception.Message). Ensure NetSecurity module is available."
    }
}

# Function to Set RDP Sessions to Logoff After 24 Hours
function Set-RDPLogoffPolicy {
    Write-Host "Configuring RDP to Logoff Disconnected Sessions After 24 Hours..." -ForegroundColor Yellow
    $timeLimitMilliseconds = 24 * 60 * 60 * 1000 # 24 hours in milliseconds
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "MaxDisconnectionTime"
    try {
        if (!(Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        New-ItemProperty -Path $regPath -Name $regName -Value $timeLimitMilliseconds -PropertyType DWord -Force -ErrorAction Stop
        Write-Host "RDP Logoff Policy Set to 24 hours."
    }
    catch {
        Write-Warning "Failed to set RDP Logoff Policy: $($_.Exception.Message)"
    }
}

# Function to Set Windows Updates to Manual (Prevent Auto Downloads/Installs)
function Set-WindowsUpdateManual {
    Write-Host "Setting Windows Updates to Manual..." -ForegroundColor Yellow
    $serviceName = "wuauserv"
    $regPathAU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

    try {
        # Configure the service
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            Set-Service -Name $serviceName -StartupType Manual -ErrorAction Stop
            Write-Host "Windows Update service (wuauserv) set to Manual startup."
        } else {
            Write-Host "Windows Update service (wuauserv) not found."
        }

        # Configure registry settings for update behavior
        if (!(Test-Path $regPathAU)) {
            New-Item -Path $regPathAU -Force | Out-Null
        }
        # 1 = Never check for updates (Not recommended for production unless actively managed otherwise)
        # We'll use AUOptions to control behavior instead of completely disabling.
        # New-ItemProperty -Path $regPathAU -Name "NoAutoUpdate" -Value 1 -PropertyType DWORD -Force
        
        # AUOptions:
        # 1: Keep my computer up to date has been disabled in group policy (effectively disables automatic updates)
        # 2: Notify for download and notify for install
        # 3: Auto download and notify for install
        # 4: Auto download and schedule the install
        New-ItemProperty -Path $regPathAU -Name "AUOptions" -Value 2 -PropertyType DWORD -Force -ErrorAction Stop
        Write-Host "Windows Updates configured to 'Notify for download and notify for install'."
    }
    catch {
        Write-Warning "Failed to set Windows Updates to Manual: $($_.Exception.Message)"
    }
}

# Function to Disable IPv6 on all network adapters
function Disable-IPv6Adapters {
    Write-Host "Disabling IPv6 on all network adapters..." -ForegroundColor Yellow
    try {
        Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Disable-NetAdapterBinding -ComponentID ms_tcpip6 -PassThru -ErrorAction Stop
        # Alternative: Get-NetAdapter | ForEach-Object { Disable-NetAdapterBinding -InterfaceAlias $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue }
        Write-Host "IPv6 disabled on network adapters. A restart may be required for changes to fully apply."
    }
    catch {
        Write-Warning "Failed to disable IPv6: $($_.Exception.Message). This might require specific permissions or the NetAdapter module."
    }
}

# Function to Show System/Hidden Files and File Extensions
function Show-HiddenFilesAndExtensions {
    Write-Host "Configuring Explorer to show hidden files, system files, and file extensions..." -ForegroundColor Yellow
    $advancedPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    try {
        Set-ItemProperty -Path $advancedPath -Name Hidden -Value 1 -ErrorAction Stop        # Show hidden files, folders, and drives
        Set-ItemProperty -Path $advancedPath -Name ShowSuperHidden -Value 1 -ErrorAction Stop # Show protected operating system files
        Set-ItemProperty -Path $advancedPath -Name HideFileExt -Value 0 -ErrorAction Stop    # Show file extensions
        Write-Host "Explorer settings updated. May require logoff/login or explorer.exe restart to see all changes."
    }
    catch {
        Write-Warning "Failed to configure Explorer settings: $($_.Exception.Message)"
    }
}

# Function to Disable Internet Explorer Enhanced Security Configuration (IE ESC)
function Disable-IEHardening {
    Write-Host "Disabling Internet Explorer Enhanced Security Configuration (IE ESC)..." -ForegroundColor Yellow
    # For Administrators
    $regPathAdmins = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
    # For Users
    $regPathUsers = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
    $regName = "IsInstalled"
    $regValue = 0

    try {
        if (Test-Path -Path $regPathAdmins) {
            Set-ItemProperty -Path $regPathAdmins -Name $regName -Value $regValue -ErrorAction Stop
            Write-Host "IE ESC for Administrators disabled."
        } else {
            Write-Host "IE ESC registry key for Administrators not found."
        }

        if (Test-Path -Path $regPathUsers) {
            Set-ItemProperty -Path $regPathUsers -Name $regName -Value $regValue -ErrorAction Stop
            Write-Host "IE ESC for Users disabled."
        } else {
            Write-Host "IE ESC registry key for Users not found."
        }
        Write-Host "IE ESC settings updated. Changes typically apply after next logon."
    }
    catch {
        Write-Warning "Failed to disable IE ESC: $($_.Exception.Message)"
    }
}

#-----------------------------------------------------------------------------------------------------------------------
# SECTION 3: Main Execution Block
#-----------------------------------------------------------------------------------------------------------------------

# Ensure script is run as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please re-run as Administrator."
    Write-Warning "Some operations will likely fail."
    # To enforce admin rights, you could uncomment the lines below and exit:
    # Start-Process PowerShell -Verb RunAs -ArgumentList ("-File `"{0}`"" -f $MyInvocation.MyCommand.Definition)
    # Exit
} else {
    Write-Host "Running with Administrator privileges." -ForegroundColor Cyan
}

Write-Host "`nStarting Azure VM Setup Process..." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Install Applications
Write-Host "`n--- Installing Applications ---" -ForegroundColor Blue
Install-Chrome
Install-PsTools
Install-NotepadPlusPlus

Set-TimeZone -Id "Eastern Standard Time"

#############BGINFO################


$downloadUrl = "https://cdfiles-infrastucture.s3.us-east-1.amazonaws.com/AzureBGInfo.zip"
$destinationFolder = "C:\Packages\Plugins\Microsoft.Compute.BGInfo\2.2.5"
$tempZipFileName = "AzureBGInfo.zip"
$tempZipPath = Join-Path -Path $env:TEMP -ChildPath $tempZipFileName # Saves ZIP to user's temporary folder
$bginfoExecutableName = "Bginfo.exe" # Or "Bginfo64.exe" - ensure this matches the file in your ZIP
$bgiFileName = "config.bgi"          # Ensure this matches the .bgi file in your ZIP
$messageFileName = "Message.txt"
$messageText = "Application/Test Server"

# --- Script Logic ---

Write-Host "Starting BGInfo deployment script..."

# 1. Create Destination Folder if it doesn't exist
Write-Host "Ensuring destination folder $destinationFolder exists..."
If (-not (Test-Path -Path $destinationFolder -PathType Container)) {
    Try {
        New-Item -ItemType Directory -Path $destinationFolder -Force -ErrorAction Stop
        Write-Host "Successfully created destination folder: $destinationFolder"
    } Catch {
        Write-Error "Failed to create destination folder $destinationFolder. Error: $($_.Exception.Message)"
        Exit 1
    }
} Else {
    Write-Host "Destination folder $destinationFolder already exists."
}

# 2. Download the ZIP file
Write-Host "Downloading AzureBGInfo.zip from $downloadUrl..."
Try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZipPath -ErrorAction Stop
    Write-Host "Successfully downloaded $tempZipFileName to $tempZipPath."
} Catch {
    Write-Error "Failed to download file from $downloadUrl. Error: $($_.Exception.Message)"
    Write-Warning "Please check the URL and your internet connection."
    Exit 1
}

# 3. Extract the ZIP file
Write-Host "Extracting $tempZipFileName to $destinationFolder..."
Try {
    # Expand-Archive will overwrite existing files if -Force is used.
    Expand-Archive -Path $tempZipPath -DestinationPath $destinationFolder -Force -ErrorAction Stop
    Write-Host "Successfully extracted ZIP content to $destinationFolder."
} Catch {
    Write-Error "Failed to extract $tempZipFileName. Error: $($_.Exception.Message)"
    Write-Warning "Ensure PowerShell version is 5.0 or higher for Expand-Archive."
    # Clean up the downloaded ZIP file even if extraction fails, if desired
    # Remove-Item -Path $tempZipPath -Force -ErrorAction SilentlyContinue
    Exit 1
} Finally {
    # Clean up the downloaded ZIP file after attempting extraction
    If (Test-Path -Path $tempZipPath) {
        Write-Host "Removing temporary ZIP file: $tempZipPath"
        Remove-Item -Path $tempZipPath -Force -ErrorAction SilentlyContinue
    }
}

# Construct full paths to the executable and .bgi file (assuming they are at the root of the ZIP)
$fullBginfoExecutablePath = Join-Path -Path $destinationFolder -ChildPath $bginfoExecutableName
$fullBgiFilePath = Join-Path -Path $destinationFolder -ChildPath $bgiFileName

# Optional: Check if the expected BGInfo executable and .bgi file exist after extraction
If (-not (Test-Path -Path $fullBginfoExecutablePath -PathType Leaf)) {
    Write-Warning "BGInfo executable '$bginfoExecutableName' not found in $destinationFolder after extraction."
    Write-Warning "Please check the contents of your ZIP file and the '\$bginfoExecutableName' variable."
    # Exit 1 # Optionally exit if critical files are missing
}
If (-not (Test-Path -Path $fullBgiFilePath -PathType Leaf)) {
    Write-Warning "BGInfo configuration file '$bgiFileName' not found in $destinationFolder after extraction."
    Write-Warning "Please check the contents of your ZIP file and the '\$bgiFileName' variable."
    # Exit 1 # Optionally exit if critical files are missing
}

# 4. Create Message.txt and Add Line
$fullMessageFilePath = Join-Path -Path $destinationFolder -ChildPath $messageFileName
Write-Host "Creating $fullMessageFilePath and adding text..."
Try {
    Set-Content -Path $fullMessageFilePath -Value $messageText -ErrorAction Stop
    Write-Host "Successfully created $fullMessageFilePath with the specified message."
} Catch {
    Write-Error "Failed to create or write to $fullMessageFilePath. Error: $($_.Exception.Message)"
    Exit 1
}

# 5. Run config.bgi using the extracted BGInfo executable
Write-Host "Attempting to run BGInfo with $fullBgiFilePath..."
Try {
    # Arguments: path to .bgi file, /timer:0, /nolicprompt
    $bginfoArguments = """$fullBgiFilePath"" /timer:0 /nolicprompt"

    Write-Host "Executing: $fullBginfoExecutablePath $bginfoArguments"
    Start-Process -FilePath $fullBginfoExecutablePath -ArgumentList $bginfoArguments -ErrorAction Stop
    Write-Host "BGInfo started with $fullBgiFilePath."
} Catch {
    Write-Error "Failed to run BGInfo. Error: $($_.Exception.Message)"
    Write-Warning "Ensure '$bginfoExecutableName' (from your ZIP) is a valid executable and '$bgiFileName' is a valid BGInfo config file."
}



#############BGINFO END################

# System Configurations
Write-Host "`n--- Applying System Configurations ---" -ForegroundColor Blue
Disable-ServerManagerPopupRegistry      # Registry method for Server Manager popup
Disable-ServerManagerPopupScheduledTask # Scheduled task method for Server Manager popup
Disable-UAC
Disable-PrintSpooler
Disable-Firewall
Set-RDPLogoffPolicy
Set-WindowsUpdateManual
Disable-IPv6Adapters
Show-HiddenFilesAndExtensions
Disable-IEHardening



# --- Start Falcon Agent Installation ---

Write-Host "--- Checking for Falcon Agent ---"
if (Get-Service "CSFalconService" -ErrorAction SilentlyContinue) {
    Write-Host "Falcon Agent already installed, nothing to do."
} else {
    Write-Host "Falcon Agent not installed. Downloading now."
    try {
        Invoke-WebRequest -Uri $falconInstallerURL -OutFile $falconInstallerTempLocation
        Write-Host "Finished downloading Falcon Agent installer."

        Write-Host "Installing Falcon Agent now, this may take a few minutes."
        $args = @("/install","/quiet","/norestart","CID=$CID")
        $installerProcess = Start-Process -FilePath $falconInstallerTempLocation -Wait -PassThru -ArgumentList $args
        Write-Host "Falcon Agent installer returned $($installerProcess.ExitCode)."
    }
    catch {
        Write-Error "Failed to install Falcon Agent."
        exit 1
    }
}

Write-Host " " # Add a blank line for readability


Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "All tasks completed!" -ForegroundColor Cyan
Write-Host "Note: Some changes like UAC disabling or Explorer settings may require a system restart or logoff/login to take full effect." -ForegroundColor Yellow
