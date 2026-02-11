@echo off
call .venv\Scripts\activate.bat
python -m agent.web_daemon config/agent.yaml

