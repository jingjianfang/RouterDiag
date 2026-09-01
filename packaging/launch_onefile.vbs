Option Explicit

Dim shell, fso, baseDir, payload, runtimeDir, runtimeName
Dim psCmd, rc, exePath

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

baseDir = fso.GetParentFolderName(WScript.ScriptFullName)
payload = fso.BuildPath(baseDir, "payload.zip")
runtimeName = "FourFaith_RouterDiag_v1.2_" & Replace(fso.GetTempName, ".tmp", "")
runtimeDir = fso.BuildPath(shell.ExpandEnvironmentStrings("%TEMP%"), runtimeName)

On Error Resume Next
fso.CreateFolder runtimeDir
If Err.Number <> 0 Then
    MsgBox "Unable to create the temporary runtime directory:" & vbCrLf & runtimeDir, 16, "FourFaith RouterDiag"
    WScript.Quit 10
End If
Err.Clear
On Error GoTo 0

psCmd = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -Command " & Chr(34) & _
        "$ErrorActionPreference='Stop'; Expand-Archive -LiteralPath '" & Replace(payload, "'", "''") & _
        "' -DestinationPath '" & Replace(runtimeDir, "'", "''") & "' -Force" & Chr(34)

rc = shell.Run(psCmd, 0, True)
If rc <> 0 Then
    On Error Resume Next
    fso.DeleteFolder runtimeDir, True
    On Error GoTo 0
    MsgBox "Unable to extract the runtime package. Windows PowerShell is required.", 16, "FourFaith RouterDiag"
    WScript.Quit 11
End If

exePath = fso.BuildPath(runtimeDir, "WanDiagTool.exe")
If Not fso.FileExists(exePath) Then
    On Error Resume Next
    fso.DeleteFolder runtimeDir, True
    On Error GoTo 0
    MsgBox "WanDiagTool.exe is missing from the one-file package.", 16, "FourFaith RouterDiag"
    WScript.Quit 12
End If

shell.CurrentDirectory = runtimeDir
rc = shell.Run(Chr(34) & exePath & Chr(34), 1, True)
shell.CurrentDirectory = shell.ExpandEnvironmentStrings("%TEMP%")

On Error Resume Next
fso.DeleteFolder runtimeDir, True
On Error GoTo 0

WScript.Quit rc
