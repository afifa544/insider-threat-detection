@echo off
echo =======================================================
echo STARTING INSIDER THREAT DETECTION SYSTEM
echo =======================================================

echo.
echo [1] Starting API Server on port 8000...
start cmd /k "python -m uvicorn api_server:app --host 0.0.0.0 --port 8000 --reload"

timeout /t 5 /nobreak > nul

echo.
echo [2] Starting Dashboard on port 8501...
start cmd /k "streamlit run complete_insider_threat_detection.py --server.port 8501"

echo.
echo =======================================================
echo SYSTEM STARTED SUCCESSFULLY!
echo.
echo API Server:     http://localhost:8000
echo API Docs:       http://localhost:8000/docs
echo Dashboard:      http://localhost:8501
echo.
echo Login Credentials:
echo Username: admin
echo Password: admin123
echo =======================================================
echo.
echo Press any key to open dashboard in browser...
pause > nul

start http://localhost:8501
start http://localhost:8000/docs

echo.
echo Both browser tabs should open automatically!
echo.
echo To stop the system, close both command windows.
pause