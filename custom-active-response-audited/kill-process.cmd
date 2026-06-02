@echo off
setlocal EnableExtensions

REM Wrapper dla Wazuh Active Response. Uzywamy katalogu skryptu,
REM zeby plik .cmd dzialal po skopiowaniu do active-response\bin.
set "BASE=%~dp0"
set "PS1=%BASE%kill-process.ps1"
set "LOG=C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

if not exist "%PS1%" (
  echo %date% %time% kill-process.cmd missing PowerShell script: "%PS1%" >> "%LOG%"
  exit /b 2
)

echo %date% %time% kill-process.cmd started >> "%LOG%"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" (
  echo %date% %time% kill-process.cmd failed with errorlevel %RC% >> "%LOG%"
  exit /b %RC%
)

echo %date% %time% kill-process.cmd finished >> "%LOG%"
exit /b 0
