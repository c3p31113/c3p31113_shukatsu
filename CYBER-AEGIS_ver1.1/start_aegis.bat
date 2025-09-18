@echo off
TITLE CYBER-AEGIS Core Services

echo Starting CYBER-AEGIS background services...
start "AEGIS Services" /min python -m service.runner

echo Waiting for services to initialize...
timeout /t 5 /nobreak > nul

echo Starting CYBER-AEGIS Dashboard...
python -m dashboard.main

echo Dashboard closed. Shutting down services.
taskkill /f /fi "WINDOWTITLE eq AEGIS Services" > nul 2>&1