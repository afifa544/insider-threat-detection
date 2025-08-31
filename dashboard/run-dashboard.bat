@echo off
echo Setting up Insider Threat Dashboard
echo.

echo Checking for data files...
python create_json.py

echo.
echo Starting Dashboard...
echo Please wait while the dashboard loads...
timeout /t 2 /nobreak >nul

streamlit run dashboard/lightweight_app.py