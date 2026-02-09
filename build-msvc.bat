@echo off
REM FPS Overlay MSVC Build Script
REM Builds the project using Visual Studio Build Tools

setlocal

REM Find vcvars64.bat
set "VCVARS="
if exist "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
)

if "%VCVARS%"=="" (
    echo ERROR: Could not find Visual Studio vcvars64.bat
    echo Please install Visual Studio Build Tools with C++ workload
    exit /b 1
)

echo Setting up Visual Studio environment...
call "%VCVARS%"

echo.
echo Building FPS Overlay (Release x64)...
echo.

REM Build using MSBuild
msbuild FPSOverlay.vcxproj /p:Configuration=Release /p:Platform=x64 /m /verbosity:minimal

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED!
    exit /b 1
)

echo.
echo Build successful!
echo.

REM Copy required DLLs to build folder
echo Copying required DLLs...
if exist "libs\lhwm\lhwm-wrapper.dll" (
    copy /Y "libs\lhwm\lhwm-wrapper.dll" "build\" >nul
    echo   - lhwm-wrapper.dll copied
)
if exist "libs\lhwm\LibreHardwareMonitorLib.dll" (
    copy /Y "libs\lhwm\LibreHardwareMonitorLib.dll" "build\" >nul
    echo   - LibreHardwareMonitorLib.dll copied
)

REM Clean up intermediate files (obj folder)
echo Cleaning up intermediate files...
if exist "build\obj" (
    rmdir /S /Q "build\obj" >nul 2>&1
    echo   - obj folder removed
)

echo.
echo ========================================
echo   Build complete!
echo   Output: build\overlay.exe
echo ========================================
echo.
echo Required files in build folder:
echo   - overlay.exe
echo   - lhwm-wrapper.dll (for LHWM support)
echo   - LibreHardwareMonitorLib.dll (for LHWM support)
echo.
echo Run as Administrator for full functionality.

endlocal
