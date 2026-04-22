@echo off
echo Starting Password Vault...

:: Start backend in a new terminal window
start "Backend" cmd /k "venv\Scripts\activate && uvicorn backend.api.auth:app --reload"

:: Start frontend in a new terminal window
start "Frontend" cmd /k "cd Password_Vault_Frontend && npm start"

echo Both servers are launching in separate windows.
echo   Backend:  http://127.0.0.1:8000
echo   Frontend: http://localhost:3000
