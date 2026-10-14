@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Sentinel - ESET detection dashboard
cd /d "%~dp0"

rem ---------------------------------------------------------------
rem  Sentinel launcher
rem    start.bat            set up (first time) and start
rem    start.bat setup      only set up / update dependencies
rem    start.bat test       set up and run the test suites
rem  Optional: set PORT, HOST, GEODB_PATH or SENTINEL_DB before running.
rem ---------------------------------------------------------------

if not defined PORT set "PORT=5000"
if not defined HOST set "HOST=127.0.0.1"
set "MODE=%~1"

echo.
echo  ==============================================
echo   sentinel.  ESET detection dashboard
echo  ==============================================
echo.

rem --- 1. Find Python 3.10+ -------------------------------------
set "PY="
for %%C in ("py -3" "python" "python3") do (
    if not defined PY (
        %%~C -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
        if !errorlevel! equ 0 set "PY=%%~C"
    )
)
if not defined PY (
    echo  [X] Python 3.10 or newer was not found.
    echo      Install it from https://www.python.org/downloads/
    echo      and tick "Add python.exe to PATH" during setup, then run this file again.
    goto :fail
)
for /f "delims=" %%V in ('%PY% -c "import sys; print(sys.version.split()[0])"') do set "PYVER=%%V"
echo  [OK] Python !PYVER!

rem --- 2. Virtual environment -----------------------------------
set "VENV=%~dp0.venv"
set "VPY=%VENV%\Scripts\python.exe"
if not exist "%VPY%" (
    echo  [..] Creating virtual environment in .venv
    %PY% -m venv "%VENV%"
    if errorlevel 1 (
        echo  [X] Could not create the virtual environment.
        goto :fail
    )
)
echo  [OK] Virtual environment

rem --- 3. Dependencies (only when requirements.txt changed) -----
set "STAMP=%VENV%\requirements.installed"
set "NEED_INSTALL=1"
if exist "%STAMP%" (
    fc /b "requirements.txt" "%STAMP%" >nul 2>&1
    if not errorlevel 1 set "NEED_INSTALL=0"
)
if "%NEED_INSTALL%"=="1" (
    echo  [..] Installing dependencies - this takes a minute the first time
    "%VPY%" -m pip install --disable-pip-version-check -q --upgrade pip
    "%VPY%" -m pip install --disable-pip-version-check -q -r requirements.txt
    if errorlevel 1 (
        echo  [X] Dependency installation failed. Check your internet connection or proxy and try again.
        goto :fail
    )
    copy /y "requirements.txt" "%STAMP%" >nul
)
echo  [OK] Dependencies

rem --- 4. GeoDB ---------------------------------------------------
if defined GEODB_PATH (
    set "GEO=%GEODB_PATH%"
) else (
    set "GEO=%~dp0data\GeoLite2-City.mmdb"
)
if exist "!GEO!" (
    echo  [OK] GeoDB found: !GEO!
) else (
    echo  [i]  No GeoDB at !GEO!
    echo       The dashboard works without it; countries then come only from the CSV.
    echo       To enable IP lookups, put GeoLite2-City.mmdb in the data folder.
)

if /i "%MODE%"=="setup" (
    echo.
    echo  Setup complete. Run start.bat to launch Sentinel.
    goto :done
)

if /i "%MODE%"=="test" (
    echo.
    echo  [..] Running backend tests
    "%VPY%" -m unittest discover -s tests
    set "TESTERR=!errorlevel!"
    where node >nul 2>&1
    if !errorlevel! equ 0 (
        echo  [..] Running frontend tests
        node tests\empty-content.cjs
        if errorlevel 1 set "TESTERR=1"
    ) else (
        echo  [i]  Node.js not found - skipping frontend tests.
    )
    if "!TESTERR!"=="0" (echo. & echo  All tests passed.) else (echo. & echo  [X] Some tests failed.)
    goto :done
)

rem --- 5. Port check ------------------------------------------------
netstat -ano | findstr /r /c:":%PORT% .*LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo  [X] Port %PORT% is already in use - Sentinel may already be running.
    echo      Open http://%HOST%:%PORT% or run:  set PORT=5001 ^& start.bat
    goto :fail
)

rem --- 6. Start ----------------------------------------------------
set "URL=http://%HOST%:%PORT%"
if "%HOST%"=="0.0.0.0" set "URL=http://127.0.0.1:%PORT%"
echo.
echo  Sentinel is starting at %URL%
set "DBSHOW=%~dp0data\sentinel.db"
if defined SENTINEL_DB set "DBSHOW=%SENTINEL_DB%"
echo  Database: !DBSHOW!
echo  Your browser will open automatically. Keep this window open;
echo  press Ctrl+C or close it to stop Sentinel.
echo.
start "" /min powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 2; Start-Process '%URL%'"

if exist "%VENV%\Scripts\waitress-serve.exe" (
    "%VENV%\Scripts\waitress-serve.exe" --listen=%HOST%:%PORT% app:app
) else (
    "%VPY%" app.py
)
goto :done

:fail
echo.
pause
exit /b 1

:done
echo.
if /i not "%MODE%"=="" pause
endlocal
exit /b 0
