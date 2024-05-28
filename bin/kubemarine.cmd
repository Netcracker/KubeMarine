@echo off
setlocal

REM This env variable is used to force the stdout and stderr streams to be unbuffered in python.
REM By default we set this variable to true, because buffering sometimes causes very long output hanging => bad UX.
REM Users can override this variable and set it to false if unbuffered output causes any issues, but python output may
REM start hanging again.
if not defined PYTHONUNBUFFERED (
    set PYTHONUNBUFFERED=TRUE
)

REM This env variable is used to ensure that possible redirect of stdout to files will use utf-8 encoding.
if not defined PYTHONIOENCODING (
    set PYTHONIOENCODING=utf-8
)

REM See pyproject.toml
_kubemarine %*
