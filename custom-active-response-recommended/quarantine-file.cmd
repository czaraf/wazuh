@echo off
setlocal EnableExtensions

REM Wazuh Active Response wrapper. The PowerShell script is resolved
REM relative to this .cmd file after deployment to active-response\bin.
set "BASE=%~dp0"
set "PS1=%BASE%quarantine-file.ps1"
set "LOG=C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

if not exist "%PS1%" (
  echo %date% %time% quarantine-file.cmd missing PowerShell script: "%PS1%" >> "%LOG%"
  exit /b 2
)

echo %date% %time% quarantine-file.cmd started >> "%LOG%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" (
  echo %date% %time% quarantine-file.cmd failed with errorlevel %RC% >> "%LOG%"
  exit /b %RC%
)

echo %date% %time% quarantine-file.cmd finished >> "%LOG%"
exit /b 0
