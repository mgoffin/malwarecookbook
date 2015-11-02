REM 
REM Usage: install_svc.bat <SERVICENAME> <DLLPATH>
REM

@echo off
set SERVICENAME=%1
set BINPATH=%2

sc create "%SERVICENAME%" binPath= "%SystemRoot%\system32\svchost.exe -k %SERVICENAME%" type= share start= auto
reg add "HKLM\System\CurrentControlSet\Services\%SERVICENAME%\Parameters" /v ServiceDll /t REG_EXPAND_SZ /d "%BINPATH%" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SvcHost" /v %SERVICENAME% /t REG_MULTI_SZ /d "%SERVICENAME%\0" /f
sc start %SERVICENAME%

