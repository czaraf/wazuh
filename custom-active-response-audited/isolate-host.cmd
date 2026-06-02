@echo off
setlocal EnableExtensions

REM Wrapper dla Wazuh Active Response. Plik .ps1 jest szukany obok .cmd,
REM co ulatwia wdrozenie calego folderu do active-response\bin.
set "BASE=%~dp0"
set "PS1=%BASE%isolate-host.ps1"
set "LOG=C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

if not exist "%PS1%" (
  echo %date% %time% isolate-host.cmd missing PowerShell script: "%PS1%" >> "%LOG%"
  exit /b 2
)

echo %date% %time% isolate-host.cmd started >> "%LOG%"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" (
  echo %date% %time% isolate-host.cmd failed with errorlevel %RC% >> "%LOG%"
  exit /b %RC%
)

echo %date% %time% isolate-host.cmd finished >> "%LOG%"
exit /b 0
