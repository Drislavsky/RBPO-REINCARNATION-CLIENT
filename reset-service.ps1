# Run this script from an elevated PowerShell.
$ErrorActionPreference = "Continue"

Write-Host "Stopping/killing old BMTX processes..."
taskkill /IM BMTX.exe /F 2>$null
taskkill /IM BMTXService.exe /F 2>$null

Write-Host "Trying to stop and delete old BMTXService..."
sc.exe stop BMTXService
Start-Sleep -Seconds 2
sc.exe delete BMTXService

Write-Host "If delete failed with Access denied, remove the stale service key manually and reboot:"
Write-Host 'reg delete "HKLM\SYSTEM\CurrentControlSet\Services\BMTXService" /f'
Write-Host "shutdown /r /t 0"
