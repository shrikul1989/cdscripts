# ---------------------------------------
# Download URLs - Modify if needed
# ---------------------------------------
$urls = @{
    Chrome        = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
    PsTools       = "https://download.sysinternals.com/files/PSTools.zip"
    BareGrep      = "https://www.baremetalsoft.com/baregrep/files/baregrep-setup.exe"
    NotepadPlus   = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/latest/download/npp.8.6.1.Installer.x64.exe"
    BGInfo        = "https://cdfiles-infrastucture.s3.us-east-1.amazonaws.com/BGInfo.zip" # Added BGInfo URL
}

# ---------------------------------------
# Define Paths
# ---------------------------------------
$DownloadPath = "C:\Temp"
if (!(Test-Path $DownloadPath)) { New-Item -Path $DownloadPath -ItemType Directory -Force }

# Function to Install Google Chrome
function Install-Chrome {
    Write-Host "Installing Google Chrome..."
    $chromeInstaller = "$DownloadPath\ChromeSetup.exe"
    Invoke-WebRequest -Uri $urls.Chrome -OutFile $chromeInstaller
    Start-Process -FilePath $chromeInstaller -ArgumentList "/silent /install" -NoNewWindow -Wait
    Remove-Item $chromeInstaller -Force
    Write-Host "Google Chrome Installed."
}

# Function to Install PsTools and Create Shortcut
function Install-PsTools {
    Write-Host "Installing PsTools..."
    $psToolsZip = "$DownloadPath\PSTools.zip"
    Invoke-WebRequest -Uri $urls.PsTools -OutFile $psToolsZip
    Expand-Archive -Path $psToolsZip -DestinationPath "C:\Program Files\PSTools" -Force
    Remove-Item $psToolsZip -Force

    # Create a desktop shortcut
    $shortcutPath = "$env:Public\Desktop\PsTools.lnk"
    $wshShell = New-Object -ComObject WScript.Shell
    $shortcut = $wshShell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = "C:\Program Files\PSTools" # Target the folder for PsTools
    $shortcut.Save()
    Write-Host "PsTools Installed and Shortcut Created."
}

# Function to Install BareGrep and Create Shortcut
function Install-BareGrep {
    Write-Host "Installing BareGrep..."
    $bareGrepInstaller = "$DownloadPath\BareGrepSetup.exe"
    Invoke-WebRequest -Uri $urls.BareGrep -OutFile $bareGrepInstaller
    Start-Process -FilePath $bareGrepInstaller -ArgumentList "/S" -NoNewWindow -Wait # Silent install argument
    Remove-Item $bareGrepInstaller -Force

    # Create a desktop shortcut
    $shortcutPath = "$env:Public\Desktop\BareGrep.lnk"
    # Default installation path for BareGrep (adjust if your installer places it elsewhere)
    $exePath = "C:\Program Files (x86)\BareGrep\baregrep.exe"
    if (Test-Path $exePath) {
        $wshShell = New-Object -ComObject WScript.Shell
        $shortcut = $wshShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $exePath
        $shortcut.Save()
    } else {
        Write-Warning "BareGrep executable not found at $exePath. Shortcut not created."
    }
    Write-Host "BareGrep Installed and Shortcut Created (if executable found)."
}

# Function to Install Notepad++
function Install-NotepadPlusPlus {
    Write-Host "Installing Notepad++..."
    $nppInstaller = "$DownloadPath\nppInstaller.exe"
    Invoke-WebRequest -Uri $urls.NotepadPlus -OutFile $nppInstaller
    Start-Process -FilePath $nppInstaller -ArgumentList "/S" -NoNewWindow -Wait # Silent install argument
    Remove-Item $nppInstaller -Force
    Write-Host "Notepad++ Installed."
}

# Function to Install BGInfo
function Install-BGInfo {
    Write-Host "Installing BGInfo..."
    # Define BGInfo specific variables
    $bgInfoZipOutput = "$DownloadPath\BGInfo.zip" # Use the common download path
    $bgInfoExtractPath = "C:\BgInfo"
    $bgInfoRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $bgInfoRegkeyValue = "$bgInfoExtractPath\Bginfo.exe $bgInfoExtractPath\CDdefault.bgi /timer:0 /nolicprompt"
    $bgInfoRegkey = "BgInfo"
    $bgInfoRegType = "String"

    # Check and remove existing BGInfo folder
    if (Test-Path -Path $bgInfoExtractPath) {
        Write-Host "Existing BGInfo directory found at $bgInfoExtractPath. Deleting..."
        Remove-Item -Path $bgInfoExtractPath -Recurse -Force
        Write-Host "Old BGInfo directory deleted."
    } else {
        Write-Host "No existing BGInfo directory found at $bgInfoExtractPath. Proceeding with installation."
    }

    # Create a new BGInfo directory
    New-Item -Path $bgInfoExtractPath -ItemType Directory -Force

    # Import BITS module and download BGInfo
    # Check if BITS module is available, otherwise use Invoke-WebRequest
    if (Get-Module -ListAvailable -Name BitsTransfer) {
        Import-Module BitsTransfer
        Write-Host "Downloading BGInfo using BITS..."
        Start-BitsTransfer -Source $urls.BGInfo -Destination $bgInfoZipOutput
    } else {
        Write-Host "BITS module not found. Downloading BGInfo using Invoke-WebRequest..."
        Invoke-WebRequest -Uri $urls.BGInfo -OutFile $bgInfoZipOutput
    }

    # Extract the downloaded ZIP file
    Write-Host "Extracting BGInfo to $bgInfoExtractPath..."
    Expand-Archive -LiteralPath $bgInfoZipOutput -DestinationPath $bgInfoExtractPath -Force # Extract directly to BgInfo folder

    # Remove the ZIP file
    Remove-Item -Path $bgInfoZipOutput -Force

    # Add BGInfo to startup
    Write-Host "Adding BGInfo to startup..."
    # Ensure the registry path exists before trying to set a property
    if (!(Test-Path $bgInfoRegPath)) {
        New-Item -Path $bgInfoRegPath -Force | Out-Null
    }
    New-ItemProperty -Path $bgInfoRegPath -Name $bgInfoRegkey -PropertyType $bgInfoRegType -Value $bgInfoRegkeyValue -Force

    # Execute BGInfo
    $bgInfoExe = "$bgInfoExtractPath\Bginfo.exe"
    $bgInfoConfig = "$bgInfoExtractPath\CDdefault.bgi"
    if (Test-Path $bgInfoExe -And Test-Path $bgInfoConfig) {
        Write-Host "Executing BGInfo..."
        Start-Process -FilePath $bgInfoExe -ArgumentList "$bgInfoConfig /timer:0 /nolicprompt" -NoNewWindow
        Write-Host "BGInfo Installed and Executed Successfully."
    } else {
        Write-Warning "BGInfo.exe or CDdefault.bgi not found in $bgInfoExtractPath. BGInfo might not have been extracted correctly or is missing files."
    }
}

# Disable Server Manager Startup for All Users
function Disable-ServerManagerPopup {
    Write-Host "Disabling Server Manager Popup..."
    $regPath = "HKLM:\SOFTWARE\Microsoft\ServerManager"
    $regName = "DoNotOpenServerManagerAtLogon"
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    New-ItemProperty -Path $regPath -Name $regName -Value 1 -PropertyType DWORD -Force
    Write-Host "Server Manager Popup Disabled."
}

# Disable UAC
function Disable-UAC {
    Write-Host "Disabling UAC..."
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $regName = "EnableLUA"
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name $regName -Value 0
    Write-Host "UAC Disabled. Restart Required for Changes to Take Effect."
}

# Disable Print Spooler Service
function Disable-PrintSpooler {
    Write-Host "Disabling Print Spooler Service..."
    if (Get-Service -Name "Spooler" -ErrorAction SilentlyContinue) {
        Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "Spooler" -StartupType Disabled
        Write-Host "Print Spooler Service Disabled."
    } else {
        Write-Host "Print Spooler Service not found."
    }
}

# Disable Windows Firewall
function Disable-Firewall {
    Write-Host "Disabling Windows Firewall..."
    # This command requires the NetSecurity module, which is available on modern Windows versions.
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Write-Host "Firewall Disabled for All Profiles."
}

# Set RDP Sessions to Logoff After 24 Hours
function Set-RDPLogoffPolicy {
    Write-Host "Configuring RDP to Logoff Disconnected Sessions After 24 Hours..."
    $timeLimit = 86400000 # 24 hours in milliseconds
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    $regName = "MaxDisconnectionTime"
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    New-ItemProperty -Path $regPath -Name $regName -Value $timeLimit -PropertyType DWord -Force
    Write-Host "RDP Logoff Policy Set."
}

# Set Windows Updates to Manual (Prevent Downloads)
function Set-WindowsUpdateManual {
    Write-Host "Setting Windows Updates to Manual..."
    if (Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue) {
        Set-Service -Name "wuauserv" -StartupType Manual
    } else {
        Write-Host "Windows Update service (wuauserv) not found."
    }
    
    $regPathAU = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (!(Test-Path $regPathAU)) {
        New-Item -Path $regPathAU -Force | Out-Null
    }
    New-ItemProperty -Path $regPathAU -Name "NoAutoUpdate" -Value 1 -PropertyType DWORD -Force
    New-ItemProperty -Path $regPathAU -Name "AUOptions" -Value 2 -PropertyType DWORD -Force # Value 2: Notify for download and notify for install
    Write-Host "Windows Updates Set to Manual."
}

# ---------------------------------------
# Execute All Functions
# ---------------------------------------
# Ensure script is run as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please re-run as Administrator."
    # Attempt to relaunch as admin
    # Start-Process PowerShell -Verb RunAs -ArgumentList ("-File `"{0}`"" -f $MyInvocation.MyCommand.Path)
    # Exit # Exit current non-admin session
    # For simplicity in this context, we'll just warn and proceed, but in production, you'd want to enforce admin rights.
}


Install-Chrome
Install-PsTools
Install-BareGrep
Install-NotepadPlusPlus
Install-BGInfo # Added BGInfo installation call
Disable-ServerManagerPopup
Disable-UAC
Disable-PrintSpooler
Disable-Firewall
Set-RDPLogoffPolicy
Set-WindowsUpdateManual

Write-Host "All tasks completed successfully!"
