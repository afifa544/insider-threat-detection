@echo off
echo [ Insider Threat Detection System ]
echo ===================================
echo.
echo Step 1: Generating realistic risk data...
python create_json.py
echo.
echo Step 2: Starting dashboard...
echo Dashboard will open in your browser automatically...
timeout /t 3 /nobreak >nul
streamlit run dashboard/lightweight_app.py
pauses