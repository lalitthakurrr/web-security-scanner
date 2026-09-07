@echo off
d:
cd d:\SEM-2\PythonProject
echo Starting FastAPI Backend Server on http://127.0.0.1:8000 ...
uvicorn app.main:app --reload --port 8000
pause
