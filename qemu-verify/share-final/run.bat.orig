@echo off
set D=%~d0
echo ALIVE > %D%\alive.txt
echo GUEST-STEP: boot-ok %DATE% %TIME% > %D%\result.txt
echo GUEST-STEP: running tests >> %D%\result.txt
%D%\modtests.exe >> %D%\result.txt 2>&1
echo GUEST-EXIT: %ERRORLEVEL% >> %D%\result.txt
echo GUEST-STEP: done %DATE% %TIME% >> %D%\result.txt
