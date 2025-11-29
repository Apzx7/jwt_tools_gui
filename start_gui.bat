@echo off
cd /d "%~dp0"
echo ========================================
echo JWT Tool GUI Launcher
echo ========================================
echo.

echo Checking for Integrated GUI...
echo.

:: Check if integrated GUI exists
if exist "jwt_gui_integrated.py" (
    echo [OK] Integrated GUI (jwt_gui_integrated.py) - All functions integrated
    echo.
    echo Starting Integrated GUI...
    python jwt_gui_integrated.py
) else (
    echo [X] Integrated GUI (jwt_gui_integrated.py) - File not found
    echo.
    echo Error: Integrated GUI file not found!
    echo Please ensure jwt_gui_integrated.py exists in the current directory.
)

echo.
pause