@echo off
setlocal

set PS1=C:\Program Files (x86)\ossec-agent\active-response\bin\shutdown-host.ps1
set LOG=C:\Program Files (x86)\ossec-agent\active-response\active-responses.log

echo %date% %time% shutdown-host.cmd started >> "%LOG%"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*

if %errorlevel% neq 0 (
  echo %date% %time% shutdown-host.cmd failed with errorlevel %errorlevel% >> "%LOG%"
  exit /b %errorlevel%
)

echo %date% %time% shutdown-host.cmd finished >> "%LOG%"
exit /b 0