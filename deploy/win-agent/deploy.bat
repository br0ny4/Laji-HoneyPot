@echo off
chcp 65001 >nul
title Laji-HoneyPot Agent Deploy — Windows 11

echo ==========================================
echo   Laji-HoneyPot Agent 部署脚本
echo   管理端: 10.111.31.103:8443
echo   本机:   10.111.29.4 (Windows 11)
echo ==========================================
echo.

:: 1. 检查 config.yaml
if not exist "config.yaml" (
    echo [ERROR] config.yaml 不存在！请确保与 honeypot-agent.exe 放在同一目录。
    pause
    exit /b 1
)
echo [OK] config.yaml 已就绪

:: 2. 检查二进制
if not exist "honeypot-agent.exe" (
    echo [ERROR] honeypot-agent.exe 不存在！
    pause
    exit /b 1
)
echo [OK] honeypot-agent.exe 已就绪

:: 3. 创建数据目录
if not exist "data" mkdir data
echo [OK] data 目录已创建

:: 4. 创建日志目录
if not exist "logs" mkdir logs
echo [OK] logs 目录已创建

echo.
echo ==========================================
echo   启动 Agent ...
echo   管理端 API: http://10.111.31.103:8080
echo   集群监听:   10.111.31.103:8443
echo   本机陷阱:   http://10.111.29.4:8081
echo ==========================================
echo.

:: 5. 启动 Agent
honeypot-agent.exe

pause
