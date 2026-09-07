@echo off
d:
cd d:\SEM-2\PythonProject
echo Starting Vulnerable Test Target Server on http://127.0.0.1:8888 ...
python tests/mock_target_app.py
pause
