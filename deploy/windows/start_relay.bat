@echo off
call .venv\Scripts\activate.bat
python -m relay.main config/relay.yaml

