@echo off
cd /d "%~dp0"
py -3 -m reverselab serve
if errorlevel 1 (
  echo.
  echo Falha ao iniciar. Confirme que o Python esta instalado.
  pause
)
