@echo off
title Web Security Scanner Launcher
echo ========================================================
echo   Launching Web Application Security Scanner Ecosystem
echo ========================================================
echo.

d:
cd d:\SEM-2\PythonProject

echo [1/2] Launching FastAPI Backend Server (Port 8000)...
start "FastAPI Scanner Backend" cmd /k "d: && cd d:\SEM-2\PythonProject && uvicorn app.main:app --reload --port 8000"

echo [2/2] Launching Streamlit Dashboard UI (Port 8501)...
start "Streamlit Security Dashboard" cmd /k "d: && cd d:\SEM-2\PythonProject && streamlit run frontend/dashboard.py --server.headless true"

echo.
echo ========================================================
echo   SUCCESS! Scanner ecosystem is starting up.
echo   
echo   - Streamlit Dashboard: http://localhost:8501
echo   - FastAPI Swagger Docs: http://127.0.0.1:8000/docs
echo ========================================================
echo.
pause
