@echo off
setlocal

REM This env variable is used to force the stdout and stderr streams to be unbuffered in python.
REM By default we set this variable to true, because buffering sometimes causes very long output hanging => bad UX.
REM Users can override this variable and set it to false if unbuffered output causes any issues, but python output may
REM start hanging again.
if not defined PYTHONUNBUFFERED (
    set PYTHONUNBUFFERED=TRUE
)

for /f "delims=" %%i in ('echo %cd%') do set WORKDIR=%%i

set SCRIPT_DIR=%~dp0

REM todo support symlinks
cd /d %SCRIPT_DIR%\.. || exit /b 1

python -m kubemarine %* -w %WORKDIR%
