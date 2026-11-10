@echo off
setlocal EnableExtensions DisableDelayedExpansion

rem Fill in the admin credentials. Use %% for a literal percent sign.
set "PERFLENS_ADMIN_USERNAME="
set "PERFLENS_ADMIN_PASSWORD="
set "ACTIVATION_HOST=0.0.0.0"
set "ACTIVATION_PORT=8787"
set "ACTIVATION_PYTHON=python.exe"
set "DISTRIBUTION_DIR=distribution"
set "ACTIVATION_TLS_CERTFILE="
set "ACTIVATION_TLS_KEYFILE="
rem Set to 1 to allow HTTP admin on a trusted LAN.
set "PERFLENS_ADMIN_ALLOW_HTTP=0"

if not defined PERFLENS_ADMIN_USERNAME goto missing_credentials
if not defined PERFLENS_ADMIN_PASSWORD goto missing_credentials

pushd "%~dp0" || exit /b 1
set "VENV_DIR=private\activation-venv"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "DATA_DIR=private\activation"

if not exist "%VENV_PYTHON%" (
    "%ACTIVATION_PYTHON%" -m venv "%VENV_DIR%"
    if errorlevel 1 goto finish
)
"%VENV_PYTHON%" -B -m pip install --disable-pip-version-check -r "activation_server\requirements.txt"
if errorlevel 1 goto finish

rem Init reuses the signing key and prints the public key path for packaging.
"%VENV_PYTHON%" -B -m activation_server init --data-dir "%DATA_DIR%"
if errorlevel 1 goto finish
"%VENV_PYTHON%" -B -m activation_server serve --data-dir "%DATA_DIR%" --host "%ACTIVATION_HOST%" --port "%ACTIVATION_PORT%" ^
    --distribution-dir "%DISTRIBUTION_DIR%" ^
    --ssl-certfile "%ACTIVATION_TLS_CERTFILE%" --ssl-keyfile "%ACTIVATION_TLS_KEYFILE%"

:finish
set "DEPLOY_RESULT=%ERRORLEVEL%"
popd
exit /b %DEPLOY_RESULT%

:missing_credentials
>&2 echo Fill in PERFLENS_ADMIN_USERNAME and PERFLENS_ADMIN_PASSWORD in deploy.bat.
exit /b 2
