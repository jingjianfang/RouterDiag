@echo off
setlocal

if "%QT_DIR%"=="" set "QT_DIR=C:\Qt\6.8.3\msvc2022_64"
set "PATH=%QT_DIR%\bin;%PATH%"

echo [1/4] Configure VS2022 x64 Debug tree...
cmake -S . -B out\build\debug -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="%QT_DIR%"
if errorlevel 1 exit /b %errorlevel%

echo [2/4] Build all targets...
cmake --build out\build\debug --config Debug
if errorlevel 1 exit /b %errorlevel%

echo [3/4] Run full CTest suite...
ctest --test-dir out\build\debug -C Debug --output-on-failure
if errorlevel 1 exit /b %errorlevel%

echo [4/4] Static safety checks...
findstr /S /N /I /C:"nvram set" /C:"nvram commit" diagnostic\*.cpp diagnostic\*.h >nul
if not errorlevel 1 (
  echo ERROR: automatic diagnostic code still contains NVRAM write commands.
  findstr /S /N /I /C:"nvram set" /C:"nvram commit" diagnostic\*.cpp diagnostic\*.h
  exit /b 2
)

echo.
echo Verification completed. Launch with:
echo   out\build\debug\Debug\WanDiagTool.exe
endlocal
