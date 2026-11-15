@echo off
powershell.exe -NoLogo -NoProfile -File "%~dp0Tunnel.ps1" %*
exit /b %ERRORLEVEL%
