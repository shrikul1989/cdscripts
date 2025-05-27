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

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "All tasks completed!" -ForegroundColor Cyan
Write-Host "Note: Some changes like UAC disabling or Explorer settings may require a system restart or logoff/login to take full effect." -ForegroundColor Yellow