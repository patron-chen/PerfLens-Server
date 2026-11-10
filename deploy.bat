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

pushd "%~dp0" || exit /b 1
"%ACTIVATION_PYTHON%" -B -m activation_server.windows_deploy %*
set "DEPLOY_RESULT=%ERRORLEVEL%"
popd
exit /b %DEPLOY_RESULT%
