@echo off
chcp 65001 >nul
title GhostProfile - Anti-Detect Browser & Multi-Account Manager (Port 4120)
echo ====================================================================
echo   🎭 Đang khởi động GhostProfile Anti-Detect Browser (Cổng 4120)...
echo   👉 Giao diện quản lý sẽ tự động mở tại: http://localhost:4120
echo ====================================================================
cd /d "%~dp0"
start "" "http://localhost:4120"
node server.js
pause
