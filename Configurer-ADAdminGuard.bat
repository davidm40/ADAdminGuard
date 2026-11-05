@echo off
rem Lance le configurateur ADAdminGuard dans une console elevee.
rem Fichier en ASCII sans accent : cmd.exe lit les .bat dans la page de code OEM.

setlocal

rem fltmc ne repond qu'en administrateur : sert de test d'elevation
fltmc >nul 2>&1
if errorlevel 1 (
    echo Elevation des droits en cours...
    rem Chemin passe par variable d'environnement : espaces, accents et apostrophes sans souci de guillemets
    set "ADAG_SELF=%~f0"
    powershell.exe -NoProfile -Command "Start-Process -FilePath $env:ADAG_SELF -Verb RunAs"
    if errorlevel 1 (
        echo Elevation refusee ou impossible : le configurateur n'a pas ete lance.
        pause
    )
    exit /b
)

powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Show-ADAdminGuardConfig.ps1"
if errorlevel 1 (
    echo.
    echo Le configurateur s'est arrete sur une erreur. Voir le message ci-dessus.
    pause
)
endlocal
