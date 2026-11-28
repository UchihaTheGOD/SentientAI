@echo off
REM SentientAI development task runner. Usage: run ^<task^> [args]
setlocal
cd /d "%~dp0"

REM Python resolution: prefer .venv, then venv, then the system Python
REM on PATH. No virtual environment is required -- dependencies are
REM installed into the main Python (see INSTALL.md).
set "PY=.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

set "CMD=%~1"
REM Double-clicking run.bat (no argument) starts the server. Use
REM "run.bat help" to see the task list instead.
if "%CMD%"=="" set "CMD=start"

if /i "%CMD%"=="start"       goto :start
if /i "%CMD%"=="test"        goto :test
if /i "%CMD%"=="status"      goto :status
if /i "%CMD%"=="export"      goto :export
if /i "%CMD%"=="export-eval" goto :exporteval
if /i "%CMD%"=="backfill"    goto :backfill
goto :help

:start
echo [run] Starting SentientAI at http://127.0.0.1:8000  (Ctrl+C to stop)
"%PY%" run.py
if errorlevel 1 (
    echo.
    echo [run] The server stopped with an error. See the message above.
    echo [run] If Python was not found, install Python 3.11/3.12 and tick "Add Python to PATH" during setup.
    echo [run] Press any key to close this window.
    pause
)
exit /b 0

:test
"%PY%" -m pytest %2 %3 %4 %5 %6
exit /b %errorlevel%

:status
"%PY%" -m app.cli training-status
exit /b %errorlevel%

:export
if not exist data mkdir data
"%PY%" -m app.cli export-training --out data\training_data.jsonl
exit /b %errorlevel%

:exporteval
if not exist data mkdir data
"%PY%" -m app.cli export-eval --out data\eval_data.jsonl
exit /b %errorlevel%

:backfill
"%PY%" -m app.cli score-backfill %2
exit /b %errorlevel%

:help
echo SentientAI development tasks:
echo   run                       Start the app (same as: run start)
echo   run start               Start the app (http://127.0.0.1:8000)
echo   run test [args]         Run the pytest suite (extra args passed through)
echo   run status              Show training-pipeline counts
echo   run export              Export approved train split to data\training_data.jsonl
echo   run export-eval         Export approved eval split to data\eval_data.jsonl
echo   run backfill [--apply]  Band scored-but-unbanded candidates (dry run without --apply)
exit /b 0
