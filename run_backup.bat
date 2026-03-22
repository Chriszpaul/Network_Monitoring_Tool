@echo off

REM Start from project root
start "App1" cmd /k "python -m streamlit run frontend\dashboard.py"
start "App2" cmd /k "python -m backend.live_capture"

echo Press any key to stop system...
pause >nul

echo Stopping system...

echo stop > stop.signal

timeout /t 2 >nul

taskkill /FI "WINDOWTITLE eq App1" /F
taskkill /FI "WINDOWTITLE eq App2" /F
del stop.signal
del alerts.db
echo System stopped.
pause