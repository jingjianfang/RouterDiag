@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

set "APP_NAME=WanDiagTool"
set "APP_VERSION=1.2"
set "FINAL_NAME=FourFaith_RouterDiag_v1.2.exe"
set "BUILD_DIR=%CD%\out\build\release-onefile-lite"
set "DIST_DIR=%CD%\dist"
set "STAGE_DIR=%DIST_DIR%\FourFaith_RouterDiag_v1.2_lite_runtime"
set "PACK_WORK=%DIST_DIR%\_onefile_lite_work"
set "FINAL_EXE=%DIST_DIR%\%FINAL_NAME%"
set "HASH_FILE=%DIST_DIR%\FourFaith_RouterDiag_v1.2_SHA256.txt"

if not "%~1"=="" set "QT_DIR=%~1"
if not defined QT_DIR (
    for /f "delims=" %%D in ('dir /b /ad /o-n "C:\Qt" 2^>nul') do (
        if not defined QT_DIR if exist "C:\Qt\%%D\msvc2022_64\bin\windeployqt.exe" set "QT_DIR=C:\Qt\%%D\msvc2022_64"
    )
)
if not defined QT_DIR set "QT_DIR=C:\Qt\6.8.3\msvc2022_64"

if not exist "%QT_DIR%\bin\windeployqt.exe" (
    echo [ERROR] Qt not found: %QT_DIR%
    echo Usage: package_onefile_release_lite.bat [Qt msvc2022_64 directory]
    echo        The script also auto-scans C:\Qt\*\msvc2022_64 when no argument is supplied.
    exit /b 2
)

if defined VSINSTALLDIR goto :vs_ready
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [ERROR] vswhere.exe not found. Install Visual Studio 2022 with C++ desktop workload.
    exit /b 3
)
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath`) do set "VSINSTALL=%%I"
if not defined VSINSTALL (
    echo [ERROR] Visual Studio 2022 C++ installation not found.
    exit /b 4
)
call "%VSINSTALL%\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 (
    echo [ERROR] Failed to initialize Visual Studio x64 environment.
    exit /b 5
)
:vs_ready

where cmake.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] cmake.exe not found.
    exit /b 6
)

if not exist "%SystemRoot%\System32\iexpress.exe" (
    echo [ERROR] Windows IExpress is not available on this machine.
    exit /b 7
)

if exist "%STAGE_DIR%" rmdir /s /q "%STAGE_DIR%"
if exist "%PACK_WORK%" rmdir /s /q "%PACK_WORK%"
if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"
mkdir "%STAGE_DIR%"
mkdir "%PACK_WORK%"
if exist "%FINAL_EXE%" del /q "%FINAL_EXE%"
if exist "%HASH_FILE%" del /q "%HASH_FILE%"

echo [1/8] Configure Release x64 lite tree...
cmake -S . -B "%BUILD_DIR%" -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="%QT_DIR%" -DBUILD_TESTING=OFF
if errorlevel 1 goto :fail

echo [2/8] Build WanDiagTool Release...
cmake --build "%BUILD_DIR%" --config Release --target WanDiagTool
if errorlevel 1 goto :fail

set "BUILT_EXE=%BUILD_DIR%\Release\WanDiagTool.exe"
if not exist "%BUILT_EXE%" (
    echo [ERROR] Release executable not found: %BUILT_EXE%
    goto :fail
)
copy /y "%BUILT_EXE%" "%STAGE_DIR%\WanDiagTool.exe" >nul
if errorlevel 1 goto :fail

echo [3/8] Deploy Qt runtime...
rem Let windeployqt discover the correct Qt dependency set first; the next
rem step removes only optional payload that this application does not use.
"%QT_DIR%\bin\windeployqt.exe" --release --compiler-runtime --no-translations --dir "%STAGE_DIR%" "%STAGE_DIR%\WanDiagTool.exe"
if errorlevel 1 goto :fail

rem Deploy the MSVC CRT app-locally. Target Windows 10/11 already provides UCRT.
rem Keeping CRT DLLs beside the EXE avoids requiring VC++ Redistributable setup.
set "CRT_DIR="
if defined VCToolsRedistDir (
    for /d %%D in ("%VCToolsRedistDir%x64\Microsoft.VC*.CRT") do if not defined CRT_DIR set "CRT_DIR=%%~fD"
)
if not defined CRT_DIR (
    echo [ERROR] VCToolsRedistDir is unavailable; cannot bundle MSVC runtime DLLs.
    goto :fail
)
copy /y "%CRT_DIR%\*.dll" "%STAGE_DIR%\" >nul
if errorlevel 1 goto :fail

echo [4/8] Prune optional runtime payload...
rem This tool currently uses Qt Core/Gui/Network/SerialPort/Widgets, QTcpSocket/QSerialPort and plain
rem local UI resources. It does not use SVG, external GIF/JPEG plugins, TLS,
rem Qt network-information backends, touch input plugins, OpenGL software
rem fallback or D3D shader compilation. Those files are therefore omitted from
rem the field package. Keep the Windows style plugin when Qt deploys it.
if exist "%STAGE_DIR%\vc_redist.x64.exe" del /q "%STAGE_DIR%\vc_redist.x64.exe"
if exist "%STAGE_DIR%\opengl32sw.dll" del /q "%STAGE_DIR%\opengl32sw.dll"
if exist "%STAGE_DIR%\d3dcompiler_47.dll" del /q "%STAGE_DIR%\d3dcompiler_47.dll"
if exist "%STAGE_DIR%\dxcompiler.dll" del /q "%STAGE_DIR%\dxcompiler.dll"
if exist "%STAGE_DIR%\dxil.dll" del /q "%STAGE_DIR%\dxil.dll"
if exist "%STAGE_DIR%\Qt6Svg.dll" del /q "%STAGE_DIR%\Qt6Svg.dll"
if exist "%STAGE_DIR%\Qt6SvgWidgets.dll" del /q "%STAGE_DIR%\Qt6SvgWidgets.dll"

for %%D in (generic iconengines imageformats networkinformation tls) do (
    if exist "%STAGE_DIR%\%%D" rmdir /s /q "%STAGE_DIR%\%%D"
)

rem Preserve qmodernwindowsstyle.dll: it is small and keeps the native Windows
rem appearance stable on Qt 6.8.x instead of trading UI quality for tiny savings.
if exist "%STAGE_DIR%\styles\qmodernwindowsstyle.dll" echo     keep: styles\qmodernwindowsstyle.dll

echo [5/8] Verify minimal field runtime...
for %%F in (WanDiagTool.exe Qt6Core.dll Qt6Gui.dll Qt6Network.dll Qt6SerialPort.dll Qt6Widgets.dll msvcp140.dll vcruntime140.dll) do (
    if not exist "%STAGE_DIR%\%%F" (
        echo [ERROR] Missing required runtime file: %%F
        goto :fail
    )
)
if not exist "%STAGE_DIR%\platforms\qwindows.dll" (
    echo [ERROR] Missing Qt platform plugin: platforms\qwindows.dll
    goto :fail
)

for %%F in (vc_redist.x64.exe opengl32sw.dll d3dcompiler_47.dll dxcompiler.dll dxil.dll Qt6Svg.dll Qt6SvgWidgets.dll) do (
    if exist "%STAGE_DIR%\%%F" (
        echo [ERROR] Optional payload was not pruned: %%F
        goto :fail
    )
)
for %%D in (generic iconengines imageformats networkinformation tls) do (
    if exist "%STAGE_DIR%\%%D" (
        echo [ERROR] Optional plugin directory was not pruned: %%D
        goto :fail
    )
)

powershell.exe -NoProfile -NonInteractive -Command "$n=(Get-ChildItem -LiteralPath '%STAGE_DIR%' -Recurse -File | Measure-Object Length -Sum).Sum; Write-Host ('    minimal runtime: {0:N1} MB' -f ($n/1MB))"
if errorlevel 1 goto :fail

echo [6/8] Create compressed payload...
copy /y "%CD%\packaging\launch_onefile.vbs" "%PACK_WORK%\launch.vbs" >nul
if errorlevel 1 goto :fail
powershell.exe -NoProfile -NonInteractive -Command "Compress-Archive -Path '%STAGE_DIR%\*' -DestinationPath '%PACK_WORK%\payload.zip' -CompressionLevel Optimal -Force"
if errorlevel 1 goto :fail
if not exist "%PACK_WORK%\payload.zip" goto :fail
powershell.exe -NoProfile -NonInteractive -Command "$n=(Get-Item -LiteralPath '%PACK_WORK%\payload.zip').Length; Write-Host ('    compressed payload: {0:N1} MB' -f ($n/1MB))"
if errorlevel 1 goto :fail

echo [7/8] Build single-file field EXE...
powershell.exe -NoProfile -NonInteractive -Command "$t=Get-Content -Raw -LiteralPath '%CD%\packaging\onefile.sed.in'; $t=$t.Replace('@TARGET@','%FINAL_EXE%').Replace('@SOURCE@','%PACK_WORK%'); Set-Content -LiteralPath '%PACK_WORK%\onefile.sed' -Value $t -Encoding ASCII"
if errorlevel 1 goto :fail
pushd "%PACK_WORK%"
"%SystemRoot%\System32\iexpress.exe" /N onefile.sed
set "IEXPRESS_RC=%ERRORLEVEL%"
popd
if not "%IEXPRESS_RC%"=="0" goto :fail
if not exist "%FINAL_EXE%" (
    echo [ERROR] IExpress did not create %FINAL_EXE%
    goto :fail
)

echo     Apply product icon to final one-file wrapper...
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%CD%\packaging\set_exe_icon.ps1" -ExePath "%FINAL_EXE%" -IcoPath "%CD%\resources\fourfaith_routerdiag.ico"
if errorlevel 1 goto :fail

echo [8/8] Write SHA256 and clean temporary files...
certutil -hashfile "%FINAL_EXE%" SHA256 > "%HASH_FILE%"
if errorlevel 1 goto :fail
powershell.exe -NoProfile -NonInteractive -Command "$n=(Get-Item -LiteralPath '%FINAL_EXE%').Length; Write-Host ('    final EXE: {0:N1} MB' -f ($n/1MB))"
if errorlevel 1 goto :fail
rmdir /s /q "%PACK_WORK%"
rmdir /s /q "%STAGE_DIR%"

echo.
echo ============================================================
echo Lite field release created successfully:
echo   %FINAL_EXE%
echo.
echo Send only this EXE to field users.
echo Target: Windows 10/11 x64. No Qt or Visual Studio installation needed.
echo ============================================================
exit /b 0

:fail
echo.
echo [ERROR] Lite packaging failed. Temporary files were kept for diagnosis:
echo   %STAGE_DIR%
echo   %PACK_WORK%
exit /b 1
