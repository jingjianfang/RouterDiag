@echo off
setlocal
if "%QT_DIR%"=="" (
  echo Please set QT_DIR first, for example:
  echo   set QT_DIR=C:\Qt\6.8.0\msvc2022_64
  exit /b 1
)
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_PREFIX_PATH="%QT_DIR%" -DBUILD_TESTING=ON
if errorlevel 1 exit /b %errorlevel%
cmake --build build --config Release
if errorlevel 1 exit /b %errorlevel%
echo.
echo Build finished. Run tests with:
echo   ctest --test-dir build -C Release --output-on-failure
