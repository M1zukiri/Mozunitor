Option Explicit
' Silent launcher for Mozunitor: uses the folder containing this script.
Dim fso, sh, dir
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = dir
sh.Run "pythonw.exe """ & dir & "pp.py""", 0, False
