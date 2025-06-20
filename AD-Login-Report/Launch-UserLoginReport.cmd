@echo off
:: User Login Report Generator Launcher
:: This batch file ensures the PowerShell script runs with administrator privileges

title User Login Report Generator - Admin Launcher

:: Check if we're already running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
    echo.
    goto :RunScript
) else (
    echo This tool requires administrator privileges to access the Security Event Log.
    echo Attempting to restart as administrator...
    echo.
    
    :: Try to restart as administrator
    powershell -Command "Start-Process cmd -ArgumentList '/c \"%~f0\"' -Verb RunAs" 2>nul
    if %errorLevel% == 0 (
        echo Administrator prompt should have appeared. If not, please run this batch file as administrator.
        pause
        exit /b
    ) else (
        echo Failed to launch as administrator. Please right-click this batch file and select "Run as administrator".
        pause
        exit /b 1
    )
)

:RunScript
:: Set the PowerShell execution policy for this session
echo Setting PowerShell execution policy for this session...
powershell -Command "Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force" 2>nul

:: Check if the PowerShell script exists in the same directory
set "SCRIPT_PATH=%~dp0UserLoginReport.ps1"
if not exist "%SCRIPT_PATH%" (
    echo ERROR: UserLoginReport.ps1 not found in the same directory as this batch file.
    echo Please ensure both files are in the same folder.
    echo Expected location: %SCRIPT_PATH%
    pause
    exit /b 1
)

echo.
echo ================================================================
echo                   USER LOGIN REPORT GENERATOR
echo ================================================================
echo.
echo This tool will help you identify all IP addresses a user has
echo logged in from by analyzing the Windows Security Event Log.
echo.
echo Attempting to launch GUI mode...
echo.
echo NOTE: During large event log queries, Windows may report the application
echo as "Not Responding". This is normal - please wait for completion.
echo.

:: Try GUI mode first
powershell -ExecutionPolicy Bypass -File "%SCRIPT_PATH%" -GUI 2>nul
set "GUI_RESULT=%errorLevel%"

if %GUI_RESULT% == 0 (
    echo GUI mode completed successfully.
    goto :End
) else (
    echo.
    echo GUI mode is not available on this system.
    echo Falling back to console mode...
    echo.
    echo Available options:
    echo   1. Console Mode (Command Line Interface)
    echo   2. Console Mode with Custom Parameters  
    echo   3. Try GUI Mode Again
    echo   4. Exit
    echo.
)

:ChooseMode
set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" goto :LaunchConsole
if "%choice%"=="2" goto :LaunchConsoleWithParams
if "%choice%"=="3" goto :LaunchGUI
if "%choice%"=="4" goto :Exit
if "%choice%"=="" goto :LaunchConsole

echo Invalid choice. Please enter 1, 2, 3, or 4.
goto :ChooseMode

:LaunchGUI
echo.
echo Launching GUI mode...
echo.
powershell -ExecutionPolicy Bypass -File "%SCRIPT_PATH%" -GUI
if %errorLevel% == 0 (
    echo GUI mode completed successfully.
) else (
    echo GUI mode failed or was cancelled.
    echo.
    echo Would you like to try console mode instead?
    set /p fallback="Enter Y for console mode, or N to exit: "
    if /i "%fallback%"=="Y" goto :LaunchConsole
    if /i "%fallback%"=="YES" goto :LaunchConsole
)
goto :End

:LaunchConsole
echo.
echo Launching console mode...
echo You will be prompted for the username.
echo.
powershell -ExecutionPolicy Bypass -File "%SCRIPT_PATH%" -Console
goto :End

:LaunchConsoleWithParams
echo.
echo Console mode with custom parameters...
echo.
set /p username="Enter username to search for: "
set /p days="Enter number of days to look back (default 30): "
set /p outputpath="Enter CSV output file path (optional, press Enter to skip): "

if "%days%"=="" set days=30

set "params=-Console -Username ""%username%"" -Days %days%"
if not "%outputpath%"=="" set "params=%params% -OutputPath ""%outputpath%"""

echo.
echo Running with parameters: %params%
echo.
powershell -ExecutionPolicy Bypass -File "%SCRIPT_PATH%" %params%
goto :End

:Exit
echo.
echo Exiting...
exit /b 0

:End
echo.
echo ================================================================
echo                        OPERATION COMPLETE
echo ================================================================
echo.
echo The User Login Report Generator has finished.
echo.
set /p restart="Would you like to run the tool again? (Y/N): "
if /i "%restart%"=="Y" goto :RunScript
if /i "%restart%"=="YES" goto :RunScript

echo.
echo Thank you for using the User Login Report Generator!
pause
exit /b 0 