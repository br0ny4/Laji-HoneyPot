@echo off
:: Laji-HoneyPot Agent Launcher
:: Use deploy.ps1 for full deployment (PowerShell)
:: This launcher starts the agent directly

set MANAGER_IP=%MANAGER_IP%
if "%MANAGER_IP%"=="" set MANAGER_IP=127.0.0.1
title Laji-HoneyPot Agent
echo Starting Laji-HoneyPot Agent...
echo Manager: %MANAGER_IP%:8443
echo.
honeypot-agent.exe
pause
