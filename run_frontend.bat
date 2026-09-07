@echo off
d:
cd d:\SEM-2\PythonProject
echo Starting Streamlit Dashboard on http://localhost:8501 ...
streamlit run frontend/dashboard.py --server.headless true
pause
