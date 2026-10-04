@echo off
cd /d %~d0\
modtests.exe > result.txt 2>&1
echo DONE %ERRORLEVEL% >> result.txt
