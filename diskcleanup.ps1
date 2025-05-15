# PowerShell Script for Disk Cleanup on Windows Server
##################################################################################
#Deletes Temp Files: Clears temporary files from C:\Windows\Temp and the user's temp folders.
#Clears Windows Update Cache: Removes old Windows Update files (C:\Windows\SoftwareDistribution\Download).
#Clears System Logs: Deletes old event logs and logs in C:\Windows\Logs\CBS.
#Removes Old IIS Logs: Cleans up IIS logs (if IIS is installed).
#Deletes Recycle Bin Content: Empties the Recycle Bin for all users.
#Removes Windows Error Reporting Files: Deletes C:\ProgramData\Microsoft\Windows\WER\ReportQueue.
#Cleans Prefetch Files: Deletes prefetch files (C:\Windows\Prefetch).
#Removes Old User Profile Temp Data: Clears temp files in user profiles (C:\Users\*\AppData\Local\Temp).
#Cleans Windows Disk Cleanup Tool Remnants: Runs cleanmgr.exe with automated parameters.


#################################################################################



# Function to delete files from a given folder
function Clear-Folder($Path) {
    if (Test-Path $Path) {
        Write-Host "Cleaning: $Path" -ForegroundColor Cyan
        Get-ChildItem -Path $Path -Recurse -Force | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
    } else {
        Write-Host "Skipping: $Path (Not Found)" -ForegroundColor Yellow
    }
}

# 1. Clear Windows Temp Folder
Clear-Folder "C:\Windows\Temp"

# 2. Clear User Temp Folders
Get-ChildItem "C:\Users\*\AppData\Local\Temp" -Directory | ForEach-Object { Clear-Folder $_.FullName }

# 3. Clear Windows Update Cache
Clear-Folder "C:\Windows\SoftwareDistribution\Download"

# 4. Clear System Logs
Clear-Folder "C:\Windows\Logs\CBS"

# 5. Delete Old IIS Logs (if IIS exists)
if (Test-Path "C:\inetpub\logs\LogFiles") {
    Clear-Folder "C:\inetpub\logs\LogFiles"
}

# 6. Empty the Recycle Bin for all users
$Shell = New-Object -ComObject Shell.Application
$Shell.Namespace(10).Items() | ForEach-Object { $_.InvokeVerb("Delete") }

# 7. Remove Windows Error Reporting Files
Clear-Folder "C:\ProgramData\Microsoft\Windows\WER\ReportQueue"

# 8. Remove Prefetch Files (Safe to Delete)
Clear-Folder "C:\Windows\Prefetch"

# 9. Run Windows Disk Cleanup Tool in Silent Mode
Write-Host "Running Windows Disk Cleanup..." -ForegroundColor Green
Start-Process "cleanmgr.exe" -ArgumentList "/sagerun:1" -NoNewWindow -Wait

Write-Host "Disk Cleanup Completed!" -ForegroundColor Green
