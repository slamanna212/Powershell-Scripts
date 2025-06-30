@echo off
echo M365 Proofpoint IP Transport Rule Manager
echo ==========================================
echo.
echo Starting PowerShell GUI Application...
echo.
echo Note: If prompted about execution policy, type 'Y' to continue.
echo.

REM Change to the script directory
cd /d "%~dp0"

REM Run the PowerShell script
powershell.exe -ExecutionPolicy Bypass -File "M365ProofpointIP-GUI.ps1"

echo.
echo Application closed.
pause 