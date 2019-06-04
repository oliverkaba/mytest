@echo off
rem File
rem Frame CMD to trigger PS and bypass PS restrictions
rem
rem
rem Config

rem set Config=LPT-ConfOC.xml
rem set Config=LPT-ConfML.xml
rem set Config=LPT-ConfGSc.xml
rem set Config=LPT-ConfKRi.xml
rem set Config=LPT-ConfGS.xml
rem set Config=LPT-ConfTS.xml
rem set Config=LPT-ConfTM.xml
rem set Config=LPT-ConfBS.xml

set Config=LPT-ConfAK.xml

cd %~dp0

PowerShell.exe -ExecutionPolicy Bypass -File %~dp0Config_LPT.ps1 -Debug -configfile %Config%