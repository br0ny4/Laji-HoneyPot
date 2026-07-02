@echo off
:: Laji-HoneyPot Agent Launcher
:: Use deploy.ps1 for full deployment (PowerShell)
:: This launcher starts the agent directly

title Laji-HoneyPot Agent
echo Starting Laji-HoneyPot Agent...
echo Manager: 10.111.31.103:8443
echo.
honeypot-agent.exe
pause
