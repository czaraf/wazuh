@echo off
setlocal EnableExtensions

REM Run this only on a host that has RSAT ActiveDirectory module and rights
REM to disable accounts, typically a defined-agent/admin host.
set "BASE=%~dp0"
set "PS1=%BASE%disable-ad-account.ps1"
set "LOG=C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

if not exist "%PS1%" (
  echo %date% %time% disable-ad-account.cmd missing PowerShell script: "%PS1%" >> "%LOG%"
  exit /b 2
)

echo %date% %time% disable-ad-account.cmd started >> "%LOG%"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" (
  echo %date% %time% disable-ad-account.cmd failed with errorlevel %RC% >> "%LOG%"
  exit /b %RC%
)

echo %date% %time% disable-ad-account.cmd finished >> "%LOG%"
exit /b 0
