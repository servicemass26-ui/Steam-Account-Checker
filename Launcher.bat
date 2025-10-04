@echo off
if exist "%~n0.exe" (
    echo Running built EXE...
    "%~n0.exe"
) else (
    echo Running script with Python...
    python steam_checker.py
)
pause
