@echo off
rem SPDX-License-Identifier: AGPL-3.0-only
setlocal
set "BUILD_TEMP=C:\Users\Public\wordlist-nvcc-temp"

set "NVCC="
if defined CUDA_PATH if exist "%CUDA_PATH%\bin\nvcc.exe" set "NVCC=%CUDA_PATH%\bin\nvcc.exe"
if not defined NVCC for /f "delims=" %%F in ('where nvcc.exe 2^>nul') do if not defined NVCC set "NVCC=%%F"
if not defined NVCC for /f "delims=" %%V in ('dir /b /ad /o-n "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v*" 2^>nul') do if not defined NVCC if exist "C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\%%V\bin\nvcc.exe" set "NVCC=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\%%V\bin\nvcc.exe"

set "VCVARS="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" for /f "usebackq delims=" %%V in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do if exist "%%V\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%%V\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "C:\Program Files\Microsoft Visual Studio\2022\Preview\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Preview\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

if not defined VCVARS (
    echo ERROR: Visual Studio x64 build environment was not found.
    exit /b 1
)
if not defined NVCC (
    echo ERROR: CUDA nvcc compiler was not found.
    exit /b 1
)

if not exist "%BUILD_TEMP%" mkdir "%BUILD_TEMP%"
set "TEMP=%BUILD_TEMP%"
set "TMP=%BUILD_TEMP%"

call "%VCVARS%" >nul
if errorlevel 1 (
    echo ERROR: Visual Studio environment setup failed.
    exit /b 1
)

echo Compiling the RTX 2080 Ti helper...
"%NVCC%" -O3 -arch=sm_75 -shared -o "%~dp0wordlist_gpu_hash.dll" "%~dp0wordlist_gpu_hash.cu"
if errorlevel 1 (
    echo ERROR: CUDA compilation failed.
    exit /b 1
)

echo Built: %~dp0wordlist_gpu_hash.dll
endlocal
