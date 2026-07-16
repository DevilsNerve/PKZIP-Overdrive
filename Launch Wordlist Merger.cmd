@echo off
setlocal
cd /d "%~dp0"
set "LOG=%~dp0wordlist_merger_crash.log"

>"%LOG%" echo [%date% %time%] Launching Wordlist Merger
>>"%LOG%" echo Python launcher: py -3
>>"%LOG%" echo.

py -3 "%~dp0wordlist_merger_gpu.py" >>"%LOG%" 2>&1
if errorlevel 1 goto crashed

endlocal
exit /b 0

:crashed
set "EXIT_CODE=%ERRORLEVEL%"
>>"%LOG%" echo.
>>"%LOG%" echo Launcher detected exit code %EXIT_CODE%.
echo.
echo Wordlist Merger failed with exit code %EXIT_CODE%.
echo Crash log: "%LOG%"
echo.
type "%LOG%"
echo.
pause
endlocal
exit /b %EXIT_CODE%
