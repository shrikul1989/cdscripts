# ---------------------------------------
# Download URLs - Modify if needed
# ---------------------------------------
$urls = @{
    Chrome       = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
    PsTools      = "https://download.sysinternals.com/files/PSTools.zip"
    BareGrep     = "https://www.baremetalsoft.com/baregrep/files/baregrep-setup.exe"
    NotepadPlus  = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/latest/download/npp.8.6.1.Installer.x64.exe"
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
    $shortcut.TargetPath = "C:\Program Files\PSTools"
    $shortcut.Save()
    Write-Host "PsTools Installed and Shortcut Created."
}

# Function to Install BareGrep and Create Shortcut
function Install-BareGrep {
    Write-Host "Installing BareGrep..."
    $bareGrepInstaller = "$DownloadPath\BareGrepSetup.exe"
    Invoke-WebRequest -Uri $urls.BareGrep -OutFile $bareGrepInstaller
    Start-Process -FilePath $bareGrepInstaller -ArgumentList "/S" -NoNewWindow -Wait
    Remove-Item $bareGrepInstaller -Force

    # Create a desktop shortcut
    $shortcutPath = "$env:Public\Desktop\BareGrep.lnk"
    $exePath = "C:\Program Files (x86)\BareGrep\baregrep.exe"
    if (Test-Path $exePath) {
        $wshShell = New-Object -ComObject WScript.Shell
        $shortcut = $wshShell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $exePath
        $shortcut.Save()
    }
    Write-Host "BareGrep Installed and Shortcut Created."
}

# Function to Install Notepad++
function Install-NotepadPlusPlus {
    Write-Host "Installing Notepad++..."
    $nppInstaller = "$DownloadPath\nppInstaller.exe"
    Invoke-WebRequest -Uri $urls.NotepadPlus -OutFile $nppInstaller
    Start-Process -FilePath $nppInstaller -ArgumentList "/S" -NoNewWindow -Wait
    Remove-Item $nppInstaller -Force
    Write-Host "Notepad++ Installed."
}

# Disable Server Manager Startup for All Users
function Disable-ServerManagerPopup {
    Write-Host "Disabling Server Manager Popup..."
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ServerManager" -Name "DoNotOpenServerManagerAtLogon" -Value 1 -PropertyType DWORD -Force
    Write-Host "Server Manager Popup Disabled."
}

# Disable UAC
function Disable-UAC {
    Write-Host "Disabling UAC..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
    Write-Host "UAC Disabled. Restart Required for Changes to Take Effect."
}

# Disable Print Spooler Service
function Disable-PrintSpooler {
    Write-Host "Disabling Print Spooler Service..."
    Stop-Service -Name "Spooler" -Force
    Set-Service -Name "Spooler" -StartupType Disabled
    Write-Host "Print Spooler Service Disabled."
}

# Disable Windows Firewall
function Disable-Firewall {
    Write-Host "Disabling Windows Firewall..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Write-Host "Firewall Disabled for All Profiles."
}

# Set RDP Sessions to Logoff After 24 Hours
function Set-RDPLogoffPolicy {
    Write-Host "Configuring RDP to Logoff Disconnected Sessions After 24 Hours..."
    $timeLimit = 86400000 # 24 hours in milliseconds
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxDisconnectionTime" -Value $timeLimit -PropertyType DWord -Force
    Write-Host "RDP Logoff Policy Set."
}

# Set Windows Updates to Manual (Prevent Downloads)
function Set-WindowsUpdateManual {
    Write-Host "Setting Windows Updates to Manual..."
    Set-Service -Name "wuauserv" -StartupType Manual
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 2 -PropertyType DWORD -Force
    Write-Host "Windows Updates Set to Manual."
}

# ---------------------------------------
# Execute All Functions
# ---------------------------------------
Install-Chrome
Install-PsTools
Install-BareGrep
Install-NotepadPlusPlus
Disable-ServerManagerPopup
Disable-UAC
Disable-PrintSpooler
Disable-Firewall
Set-RDPLogoffPolicy
Set-WindowsUpdateManual

Write-Host "All tasks completed successfully!"
