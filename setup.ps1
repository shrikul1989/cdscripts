[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$CID,

    [Parameter(Mandatory=$true)]
    [string]$JumpCloudConnectKey,

    [Parameter(Mandatory=$true)]
    [string]$MEURL
)

# Define a log file path for all error logging
$logFile = "c:\Installlog.txt"

# --- Common Setup ---

# Set security protocol for downloads
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Check and create the log file if it doesn't exist
if (-not (Test-Path $logFile)) {
    Write-Host "Creating log file at $logFile"
    New-Item -Path $logFile -ItemType File -Force | Out-Null
}

#-----------------------------------------------------------------------------------------------------------------------
# SECTION 1: Agent Installation Functions
#-----------------------------------------------------------------------------------------------------------------------

# Function to install the Falcon Agent
function Install-FalconAgent {
    Write-Host "--- Checking for Falcon Agent ---"
    if (Get-Service "CSFalconService" -ErrorAction SilentlyContinue) {
        Write-Host "Falcon Agent already installed, nothing to do."
    } else {
        Write-Host "Falcon Agent not installed. Downloading now."
        try {
            $falconInstallerURL = "https://cdfiles-infrastucture.s3.us-east-1.amazonaws.com/CwordStrikeFalcon-Installer.exe"
            $falconInstallerTempLocation = "C:\Windows\Temp\CSFalconAgentInstaller.exe"
            Invoke-WebRequest -Uri $falconInstallerURL -OutFile $falconInstallerTempLocation
            Write-Host "Finished downloading Falcon Agent installer."

            Write-Host "Installing Falcon Agent now, this may take a few minutes."
            $args = @("/install","/quiet","/norestart","CID=$CID")
            $installerProcess = Start-Process -FilePath $falconInstallerTempLocation -Wait -PassThru -ArgumentList $args
            Write-Host "Falcon Agent installer returned $($installerProcess.ExitCode)."
        }
        catch {
            Write-Error "Failed to install Falcon Agent: $($_.Exception.Message)"
            "$(Get-Date) - ERROR: Failed to install Falcon Agent: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
        }
    }
}

# Function to install the JumpCloud Agent
function Install-JumpCloudAgent {
    Write-Host "--- Checking for JumpCloud Agent ---"
    if (Get-Service "JumpCloudService" -ErrorAction SilentlyContinue) {
        Write-Host "JumpCloud Agent already installed, nothing to do."
    } else {
        Write-Host "JumpCloud Agent not installed. Downloading now."
        try {
            $jumpCloudInstallerURL = "https://raw.githubusercontent.com/TheJumpCloud/support/master/scripts/windows/InstallWindowsAgent.ps1"
            $jumpCloudInstallerTempLocation = "C:\Windows\Temp\InstallWindowsAgent.ps1"
            Invoke-WebRequest -Uri $jumpCloudInstallerURL -OutFile $jumpCloudInstallerTempLocation
            Write-Host "Finished downloading JumpCloud Agent installer."

            Write-Host "Installing JumpCloud Agent now, this may take a few minutes."
            # This executes the downloaded script with the provided key
            & $jumpCloudInstallerTempLocation -JumpCloudConnectKey $JumpCloudConnectKey
            Write-Host "JumpCloud Agent installation command executed."
        }
        catch {
            Write-Error "Failed to install JumpCloud Agent: $($_.Exception.Message)"
            "$(Get-Date) - ERROR: Failed to install JumpCloud Agent: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
        }
    }
}

# Function to install the ManageEngine Agent
function Install-ManageEngineAgent {
    Write-Host "--- Checking for ManageEngine Agent ---"
    if (Get-Service "ManageEngineDCAgent" -ErrorAction SilentlyContinue) {
        Write-Host "ManageEngine Agent already installed, nothing to do."
    } else {
        Write-Host "ManageEngine Agent not installed. Downloading now."
        try {
            $manageEngineInstallerTempLocation = "$env:windir\temp\DCAgent.exe"
            Invoke-WebRequest -Uri $MEURL -OutFile $manageEngineInstallerTempLocation
            Write-Host "Finished downloading ManageEngine Agent installer."

            Write-Host "Installing ManageEngine Agent now, this may take a few minutes."
            Start-Process -FilePath $manageEngineInstallerTempLocation -Wait -ArgumentList "/silent"
            Write-Host "ManageEngine Agent installation command executed."
        }
        catch {
            Write-Error "Failed to install ManageEngine Agent: $($_.Exception.Message)"
            "$(Get-Date) - ERROR: Failed to install ManageEngine Agent: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
        }
    }
}

#-----------------------------------------------------------------------------------------------------------------------
# SECTION 2: Software & Configuration Functions
#-----------------------------------------------------------------------------------------------------------------------

# Download URLs - Modify if needed
$urls = @{
    Chrome        = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
    PsTools       = "https://download.sysinternals.com/files/PSTools.zip"
    NotepadPlus   = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.8.1/npp.8.8.1.Installer.x64.exe" # Consider using 'latest' if the version changes often
}

# Define Paths
$DownloadPath = "C:\Temp"
if (!(Test-Path $DownloadPath)) {
    Write-Host "Creating download directory: $DownloadPath"
    New-Item -Path $DownloadPath -ItemType Directory -Force | Out-Null
}

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
        "$(Get-Date) - WARNING: Failed to install Google Chrome: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
    finally {
        if (Test-Path $chromeInstaller) {
            Remove-Item $chromeInstaller -Force -ErrorAction SilentlyContinue
        }
    }
}

function Install-PsTools {
    Write-Host "Installing PsTools..." -ForegroundColor Green
    $psToolsZip = Join-Path -Path $DownloadPath -ChildPath "PSTools.zip"
    $psToolsExtractPath = "C:\Program Files\PSTools"
    try {
        Invoke-WebRequest -Uri $urls.PsTools -OutFile $psToolsZip -ErrorAction Stop
        Expand-Archive -Path $psToolsZip -DestinationPath $psToolsExtractPath -Force
        Write-Host "PsTools extracted to $psToolsExtractPath."
        $shortcutPath = Join-Path -Path $env:Public -ChildPath "Desktop\PsTools.lnk"
        $wshShell = New-Object -ComObject WScript.Shell
        $shortcut = $wshShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $psToolsExtractPath
        $shortcut.Save()
        Write-Host "PsTools Shortcut Created on Public Desktop."
    }
    catch {
        Write-Warning "Failed to install PsTools: $($_.Exception.Message)"
        "$(Get-Date) - WARNING: Failed to install PsTools: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
    finally {
        if (Test-Path $psToolsZip) {
            Remove-Item $psToolsZip -Force -ErrorAction SilentlyContinue
        }
    }
}

function Install-NotepadPlusPlus {
    Write-Host "Installing Notepad++..." -ForegroundColor Green
    $nppInstaller = Join-Path -Path $DownloadPath -ChildPath "nppInstaller.exe"
    try {
        Invoke-WebRequest -Uri $urls.NotepadPlus -OutFile $nppInstaller -ErrorAction Stop
        Start-Process -FilePath $nppInstaller -ArgumentList "/S" -NoNewWindow -Wait
        Write-Host "Notepad++ Installed."
    }
    catch {
        Write-Warning "Failed to install Notepad++: $($_.Exception.Message)"
        "$(Get-Date) - WARNING: Failed to install Notepad++: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
    finally {
        if (Test-Path $nppInstaller) {
            Remove-Item $nppInstaller -Force -ErrorAction SilentlyContinue
        }
    }
}

function Setup-TimeZone {
    Write-Host "Setting TimeZone to Eastern Standard Time..." -ForegroundColor Yellow
    try {
        Set-TimeZone -Id "Eastern Standard Time" -ErrorAction Stop
        Write-Host "Time Zone set successfully."
    }
    catch {
        Write-Warning "Failed to set TimeZone: $($_.Exception.Message)"
        "$(Get-Date) - WARNING: Failed to set TimeZone: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
}

function Setup-BGInfo {
    Write-Host "Starting BGInfo deployment script..."
    $downloadUrl = "https://cdfiles-infrastucture.s3.us-east-1.amazonaws.com/AzureBGInfo.zip"
    $destinationFolder = "C:\Packages\Plugins\Microsoft.Compute.BGInfo\2.2.5"
    $tempZipFileName = "AzureBGInfo.zip"
    $tempZipPath = Join-Path -Path $env:TEMP -ChildPath $tempZipFileName
    $bginfoExecutableName = "Bginfo.exe"
    $bgiFileName = "config.bgi"
    $messageFileName = "Message.txt"
    $messageText = "Application/Test Server"

    try {
        Write-Host "Ensuring destination folder $destinationFolder exists..."
        if (-not (Test-Path -Path $destinationFolder -PathType Container)) {
            New-Item -ItemType Directory -Path $destinationFolder -Force -ErrorAction Stop
        }

        Write-Host "Downloading AzureBGInfo.zip from $downloadUrl..."
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tempZipPath -ErrorAction Stop
        Write-Host "Extracting $tempZipFileName to $destinationFolder..."
        Expand-Archive -Path $tempZipPath -DestinationPath $destinationFolder -Force -ErrorAction Stop
        
        $fullMessageFilePath = Join-Path -Path $destinationFolder -ChildPath $messageFileName
        Set-Content -Path $fullMessageFilePath -Value $messageText -ErrorAction Stop
        
        $fullBginfoExecutablePath = Join-Path -Path $destinationFolder -ChildPath $bginfoExecutableName
        $fullBgiFilePath = Join-Path -Path $destinationFolder -ChildPath $bgiFileName
        $bginfoArguments = """$fullBgiFilePath"" /timer:0 /nolicprompt"
        Start-Process -FilePath $fullBginfoExecutablePath -ArgumentList $bginfoArguments -ErrorAction Stop
        
        Write-Host "BGInfo configured and started successfully."
    } catch {
        Write-Warning "Failed to set up BGInfo: $($_.Exception.Message)"
        "$(Get-Date) - WARNING: Failed to set up BGInfo: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
    finally {
        if (Test-Path -Path $tempZipPath) {
            Remove-Item -Path $tempZipPath -Force -ErrorAction SilentlyContinue
        }
    }
}

#-----------------------------------------------------------------------------------------------------------------------
# SECTION 3: System Configuration Functions
#-----------------------------------------------------------------------------------------------------------------------

# The following functions are from your original script and have been wrapped for clarity.
# Their try/catch blocks have been modified to log errors and continue execution.
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
        "$(Get-Date) - WARNING: Failed to disable Server Manager Popup (Registry): $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
}

function Disable-ServerManagerPopupScheduledTask {
    Write-Host "Disabling Server Manager Popup via Scheduled Task..." -ForegroundColor Yellow
    try {
        Get-ScheduledTask -TaskName ServerManager -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction Stop
        Write-Host "Server Manager Popup (Scheduled Task) Disabled."
    }
    catch {
        Write-Warning "Failed to disable Server Manager Popup (Scheduled Task): $($_.Exception.Message). It might not exist or another error occurred."
        "$(Get-Date) - WARNING: Failed to disable Server Manager Popup (Scheduled Task): $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
}

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
        "$(Get-Date) - WARNING: Failed to disable UAC: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
}

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
        "$(Get-Date) - WARNING: Failed to disable Print Spooler Service: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
}

function Disable-Firewall {
    Write-Host "Disabling Windows Firewall..." -ForegroundColor Yellow
    try {
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False -ErrorAction Stop
        Write-Host "Windows Firewall Disabled for All Profiles."
    }
    catch {
        Write-Warning "Failed to disable Windows Firewall: $($_.Exception.Message). Ensure NetSecurity module is available."
        "$(Get-Date) - WARNING: Failed to disable Windows Firewall: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
}

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
        "$(Get-Date) - WARNING: Failed to set RDP Logoff Policy: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
}

function Set-WindowsUpdateManual {
    Write-Host "Setting Windows Updates to Manual..." -ForegroundColor Yellow
    $serviceName = "wuauserv"
    $regPathAU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

    try {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            Set-Service -Name $serviceName -StartupType Manual -ErrorAction Stop
            Write-Host "Windows Update service (wuauserv) set to Manual startup."
        } else {
            Write-Host "Windows Update service (wuauserv) not found."
        }

        if (!(Test-Path $regPathAU)) {
            New-Item -Path $regPathAU -Force | Out-Null
        }
        New-ItemProperty -Path $regPathAU -Name "AUOptions" -Value 2 -PropertyType DWORD -Force -ErrorAction Stop
        Write-Host "Windows Updates configured to 'Notify for download and notify for install'."
    }
    catch {
        Write-Warning "Failed to set Windows Updates to Manual: $($_.Exception.Message)"
        "$(Get-Date) - WARNING: Failed to set Windows Updates to Manual: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
}

function Disable-IPv6Adapters {
    Write-Host "Disabling IPv6 on all network adapters..." -ForegroundColor Yellow
    try {
        Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Disable-NetAdapterBinding -ComponentID ms_tcpip6 -PassThru -ErrorAction Stop
        Write-Host "IPv6 disabled on network adapters. A restart may be required for changes to fully apply."
    }
    catch {
        Write-Warning "Failed to disable IPv6: $($_.Exception.Message). This might require specific permissions or the NetAdapter module."
        "$(Get-Date) - WARNING: Failed to disable IPv6: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
}

function Show-HiddenFilesAndExtensions {
    Write-Host "Configuring Explorer to show hidden files, system files, and file extensions..." -ForegroundColor Yellow
    $advancedPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    try {
        Set-ItemProperty -Path $advancedPath -Name Hidden -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path $advancedPath -Name ShowSuperHidden -Value 1 -ErrorAction Stop
        Set-ItemProperty -Path $advancedPath -Name HideFileExt -Value 0 -ErrorAction Stop
        Write-Host "Explorer settings updated. May require logoff/login or explorer.exe restart to see all changes."
    }
    catch {
        Write-Warning "Failed to configure Explorer settings: $($_.Exception.Message)"
        "$(Get-Date) - WARNING: Failed to configure Explorer settings: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
}

function Disable-IEHardening {
    Write-Host "Disabling Internet Explorer Enhanced Security Configuration (IE ESC)..." -ForegroundColor Yellow
    $regPathAdmins = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}'
    $regPathUsers = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}'
    $regName = "IsInstalled"
    $regValue = 0

    try {
        if (Test-Path -Path $regPathAdmins) {
            Set-ItemProperty -Path $regPathAdmins -Name $regName -Value $regValue -ErrorAction Stop
            Write-Host "IE ESC for Administrators disabled."
        }
        if (Test-Path -Path $regPathUsers) {
            Set-ItemProperty -Path $regPathUsers -Name $regName -Value $regValue -ErrorAction Stop
            Write-Host "IE ESC for Users disabled."
        }
        Write-Host "IE ESC settings updated. Changes typically apply after next logon."
    }
    catch {
        Write-Warning "Failed to disable IE ESC: $($_.Exception.Message)"
        "$(Get-Date) - WARNING: Failed to disable IE ESC: $($_.Exception.Message)" | Out-File -FilePath $logFile -Append
    }
}


#-----------------------------------------------------------------------------------------------------------------------
# SECTION 4: Main Execution Block
#-----------------------------------------------------------------------------------------------------------------------

# Ensure script is run as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please re-run as Administrator."
    Write-Warning "Some operations will likely fail."
    # The script will continue, but operations may fail.
} else {
    Write-Host "Running with Administrator privileges." -ForegroundColor Cyan
}

Write-Host "`nStarting Azure VM Setup Process..." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# Install Agent Software
Write-Host "`n--- Installing Agents ---" -ForegroundColor Blue
Install-FalconAgent
Write-Host " "
Install-JumpCloudAgent
Write-Host " "
Install-ManageEngineAgent
Write-Host " "

# Install other Applications
Write-Host "`n--- Installing Applications ---" -ForegroundColor Blue
Install-Chrome
Install-PsTools
Install-NotepadPlusPlus
Write-Host " "

# Perform System Configurations
Write-Host "`n--- Applying System Configurations ---" -ForegroundColor Blue
Setup-TimeZone
Setup-BGInfo
Disable-ServerManagerPopupRegistry
Disable-ServerManagerPopupScheduledTask
Disable-UAC
Disable-PrintSpooler
Disable-Firewall
Set-RDPLogoffPolicy
Set-WindowsUpdateManual
Disable-IPv6Adapters
Show-HiddenFilesAndExtensions
Disable-IEHardening
Write-Host " "

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "All tasks completed! Check $logFile for any warnings or errors." -ForegroundColor Cyan
Write-Host "Note: Some changes like UAC disabling or Explorer settings may require a system restart or logoff/login to take full effect." -ForegroundColor Yellow
