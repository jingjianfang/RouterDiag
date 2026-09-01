@echo off
setlocal
cd /d "%~dp0"
echo [1/4] Cleaning build...
if exist build rmdir /s /q build
if not exist build mkdir build
cd build
echo [2/4] Configuring Release x64...
cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release || exit /b 1
echo [3/4] Building...
cmake --build . --config Release || exit /b 1
cd ..
echo [4/4] EXE location:
echo build\Release\WanDiagTool.exe
echo.
echo If Qt is installed, run windeployqt on the EXE to collect Qt DLLs.
pause
