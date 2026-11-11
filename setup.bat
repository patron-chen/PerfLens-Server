@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "PYTHONIOENCODING=utf-8"
set "ROOT_DIR=%~dp0"
set "PRIVATE_DIR=%ROOT_DIR%private"
set "CACHE_DIR=%PRIVATE_DIR%\cache"
set "STANDALONE_PYTHON=%PRIVATE_DIR%\python\python.exe"
set "VENV_PYTHON=%PRIVATE_DIR%\activation-venv\Scripts\python.exe"

set "SETUP_PAUSE=1"
set "SETUP_FORCE=0"
set "EXPLICIT_PYTHON="
set "MIRROR_URL="

:parse_args
if "%~1"=="" goto after_args
if /I "%~1"=="-h" goto show_help
if /I "%~1"=="--help" goto show_help
if /I "%~1"=="--no-pause" (
    set "SETUP_PAUSE=0"
    shift
    goto parse_args
)
if /I "%~1"=="--force" (
    set "SETUP_FORCE=1"
    shift
    goto parse_args
)
if /I "%~1"=="--python" (
    set "EXPLICIT_PYTHON=%~2"
    shift
    shift
    goto parse_args
)
if /I "%~1"=="--mirror" (
    set "MIRROR_URL=%~2"
    shift
    shift
    goto parse_args
)
shift
goto parse_args

:after_args
rem 1. Check if user provided an explicit Python interpreter
if defined EXPLICIT_PYTHON (
    set "SETUP_PYTHON=%EXPLICIT_PYTHON%"
    goto verify_python
)

rem 2. Check standalone python if present
if exist "%STANDALONE_PYTHON%" (
    "%STANDALONE_PYTHON%" -B -c "import sys, struct; sys.exit(0 if sys.version_info[:2] == (3, 13) and struct.calcsize('P') == 8 else 1)" >nul 2>&1
    if not errorlevel 1 (
        set "SETUP_PYTHON=%STANDALONE_PYTHON%"
        goto run_setup
    )
)

rem 3. Check py launcher for Python 3.13 64-bit
py.exe -3.13-64 -B -c "pass" >nul 2>&1
if not errorlevel 1 (
    set "SETUP_PYTHON=py.exe"
    set "SETUP_PYTHON_ARGS=-3.13-64"
    goto run_setup
)

rem 4. Check python.exe in PATH
python.exe -B -c "import sys, struct; sys.exit(0 if sys.version_info[:2] == (3, 13) and struct.calcsize('P') == 8 else 1)" >nul 2>&1
if not errorlevel 1 (
    set "SETUP_PYTHON=python.exe"
    goto run_setup
)

rem 5. No working Python 3.13 found. Bootstrap standalone Python 3.13.
echo No Python 3.13 detected on host. Downloading standalone Python runtime...
if not exist "%PRIVATE_DIR%" mkdir "%PRIVATE_DIR%"
if not exist "%CACHE_DIR%" mkdir "%CACHE_DIR%"

set "STANDALONE_URL=https://github.com/astral-sh/python-build-standalone/releases/download/20250115/cpython-3.13.1+20250115-x86_64-pc-windows-msvc-install_only.tar.gz"
set "STANDALONE_SHA256=92021e1151d118db94689a38407248de96d8a2b8ffa9c4ae31b990441fda0aa0"
set "ARCHIVE_FILE=%CACHE_DIR%\cpython-3.13.1-x86_64-pc-windows-msvc.tar.gz"

set "DOWNLOAD_URL=%STANDALONE_URL%"
if defined MIRROR_URL (
    set "DOWNLOAD_URL=%MIRROR_URL%%STANDALONE_URL%"
) else if defined GH_PROXY (
    set "DOWNLOAD_URL=%GH_PROXY%%STANDALONE_URL%"
)

echo Downloading from %DOWNLOAD_URL% ...
curl.exe --fail --location --retry 2 --connect-timeout 15 --max-time 300 --output "%ARCHIVE_FILE%" "%DOWNLOAD_URL%"
if errorlevel 1 (
    >&2 echo ERROR: Failed to download standalone Python.
    set "SETUP_RESULT=1"
    goto finish
)

echo Verifying checksum...
powershell.exe -NoProfile -NonInteractive -Command "$h = (Get-FileHash -Path '%ARCHIVE_FILE%' -Algorithm SHA256).Hash.ToLower(); if ($h -ne '%STANDALONE_SHA256%') { exit 1 }"
if errorlevel 1 (
    >&2 echo ERROR: SHA-256 verification failed for downloaded Python archive.
    if exist "%ARCHIVE_FILE%" del "%ARCHIVE_FILE%"
    set "SETUP_RESULT=1"
    goto finish
)

echo Extracting standalone Python...
tar.exe -xzf "%ARCHIVE_FILE%" -C "%PRIVATE_DIR%"
if errorlevel 1 (
    >&2 echo ERROR: Failed to extract standalone Python.
    set "SETUP_RESULT=1"
    goto finish
)

if not exist "%STANDALONE_PYTHON%" (
    >&2 echo ERROR: Expected Python interpreter not found at %STANDALONE_PYTHON%
    set "SETUP_RESULT=1"
    goto finish
)

set "SETUP_PYTHON=%STANDALONE_PYTHON%"
goto run_setup

:verify_python
"%SETUP_PYTHON%" -B -c "import sys, struct; sys.exit(0 if sys.version_info[:2] == (3, 13) and struct.calcsize('P') == 8 else 1)" >nul 2>&1
if errorlevel 1 (
    >&2 echo ERROR: Specified interpreter '%SETUP_PYTHON%' is not a 64-bit Python 3.13.
    set "SETUP_RESULT=2"
    goto finish
)

:run_setup
pushd "%ROOT_DIR%" || exit /b 1
"%SETUP_PYTHON%" %SETUP_PYTHON_ARGS% -B -m activation_server.setup %*
set "SETUP_RESULT=%ERRORLEVEL%"
popd
goto finish

:show_help
echo Usage: setup.bat [OPTIONS]
echo.
echo Initialize the PerfLens activation server environment on Windows.
echo.
echo Options:
echo   -h, --help             Show this help message
echo   --python ^<path^>       Specify an existing Python 3.13 x64 executable
echo   --mirror ^<url^>        Download mirror URL prefix for GitHub / PyPI
echo   --force                Re-create the virtual environment and reinstall dependencies
echo   --no-pause             Do not pause on exit (for non-interactive execution)
echo.
set "SETUP_RESULT=0"
set "SETUP_PAUSE=0"
goto finish

:finish
if "%SETUP_PAUSE%"=="1" pause
exit /b %SETUP_RESULT%
