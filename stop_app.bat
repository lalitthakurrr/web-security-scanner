@echo off
title Stop Web Security Scanner
echo Stopping Scanner backend and frontend processes...
taskkill /F /IM uvicorn.exe 2>nul
taskkill /F /IM streamlit.exe 2>nul
echo Done! All scanner servers stopped.
pause
