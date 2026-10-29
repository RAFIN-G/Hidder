@rem SPDX-FileCopyrightText: 2026 ModSeeker
@rem SPDX-License-Identifier: AGPL-3.0-or-later

@echo off
echo ===============================================
echo Compiling Vault with OLLVM-16 (obfuscated)
echo Portable MSVC 14.29 + ollvm-16 clang-cl
echo ===============================================
echo.
cd /d "%~dp0"

if defined HIDDER_CLANG_CL (set "CLANG_CL=%HIDDER_CLANG_CL%") else (set "CLANG_CL=%~dp0..\..\clang-cl.exe")
if defined HIDDER_VCTOOLS (set "VCTOOLS=%HIDDER_VCTOOLS%") else (set "VCTOOLS=%~dp0..\..\msvc-portable\msvc\VC\Tools\MSVC\14.29.30133")
if defined HIDDER_WINSDK (set "WINSDK=%HIDDER_WINSDK%") else (set "WINSDK=%~dp0..\..\msvc-portable\msvc\Windows Kits\10")
if defined HIDDER_WINSDK_VER (set "WINSDK_VER=%HIDDER_WINSDK_VER%") else (set "WINSDK_VER=10.0.22621.0")
if defined HIDDER_OPENSSL_DIR (set "OPENSSL_DIR=%HIDDER_OPENSSL_DIR%") else (set "OPENSSL_DIR=C:\Program Files\OpenSSL-Win64")
if defined HIDDER_JDK_DIR (set "JDK_DIR=%HIDDER_JDK_DIR%") else if defined JAVA_HOME (set "JDK_DIR=%JAVA_HOME%") else (set "JDK_DIR=C:\Program Files\Zulu\zulu-25")
set "JAVA_HOME=%JDK_DIR%"
if not defined HIDDER_PRIVATE_INPUT_DIR set "HIDDER_PRIVATE_INPUT_DIR=%~dp0."
set "GRADLE_OFFLINE="
if defined HIDDER_OFFLINE set "GRADLE_OFFLINE=--offline"

if not exist "%CLANG_CL%" (
    echo [ERROR] clang-cl.exe not found at "%CLANG_CL%"
    if not defined HIDDER_NONINTERACTIVE pause
    exit /b 1
)

if not exist "%HIDDER_PRIVATE_INPUT_DIR%\client_keys.generated.inc" (
    echo [ERROR] client_keys.generated.inc is missing.
    echo Run ..\..\ModSeeker\Tools\StartCustomBuild.ps1 -InitializeKeysOnly first.
    if not defined HIDDER_NONINTERACTIVE pause
    exit /b 1
)

call "..\gradlew.bat" -p .. generateClassFingerprints %GRADLE_OFFLINE% --no-build-cache --rerun-tasks --console=plain
if %errorlevel% neq 0 (
    echo [ERROR] Class fingerprint generation failed.
    if not defined HIDDER_NONINTERACTIVE pause
    exit /b %errorlevel%
)

if not exist "..\build\generated\native\class_fingerprints.generated.inc" (
    echo [ERROR] Class fingerprint header is missing.
    if not defined HIDDER_NONINTERACTIVE pause
    exit /b 1
)

if not exist "..\build\generated\native\client_report_key.generated.inc" (
    echo [ERROR] Client report-key identity header is missing.
    if not defined HIDDER_NONINTERACTIVE pause
    exit /b 1
)

set "OBF=-mllvm -fla -mllvm -bcf -mllvm -bcf_prob=40 -mllvm -sub -mllvm -sub_loop=2 -mllvm -split -mllvm -split_num=3"

echo Compiling with obfuscation...
"%CLANG_CL%" /c /EHsc /MT /O2 /Fomod_inflate.obj mod_inflate.cpp ^
    -vctoolsdir "%VCTOOLS%" ^
    -winsdkdir "%WINSDK%" ^
    -winsdkversion %WINSDK_VER%

if %errorlevel% neq 0 (
    echo [ERROR] Metadata inflater compilation failed.
    if not defined HIDDER_NONINTERACTIVE pause
    exit /b %errorlevel%
)

"%CLANG_CL%" /c /EHsc /MT /O2 /wd4996 /Fohidder_vault.obj hidder_vault.cpp %OBF% ^
    -vctoolsdir "%VCTOOLS%" ^
    -winsdkdir "%WINSDK%" ^
    -winsdkversion %WINSDK_VER% ^
    /I"%JDK_DIR%\include" ^
    /I"%JDK_DIR%\include\win32" ^
    /I"%OPENSSL_DIR%\include" ^
    /I"%HIDDER_PRIVATE_INPUT_DIR%" ^
    /I"..\build\generated\native"

if %errorlevel% neq 0 (
    echo [ERROR] Vault compilation failed.
    if not defined HIDDER_NONINTERACTIVE pause
    exit /b %errorlevel%
)

"%CLANG_CL%" /LD /Fe:hidder_vault.dll hidder_vault.obj mod_inflate.obj ^
    -vctoolsdir "%VCTOOLS%" ^
    -winsdkdir "%WINSDK%" ^
    -winsdkversion %WINSDK_VER% ^
    /link ^
    /LIBPATH:"%OPENSSL_DIR%\lib\VC\x64\MT" ^
    libcrypto_static.lib ^
    ws2_32.lib ^
    advapi32.lib ^
    crypt32.lib ^
    user32.lib ^
    bcrypt.lib ^
    /DEPENDENTLOADFLAG:0x800

if %errorlevel% neq 0 (
    echo.
    echo ===============================================
    echo Compilation Failed!
    echo ===============================================
    if not defined HIDDER_NONINTERACTIVE pause
    exit /b %errorlevel%
)

echo.
echo ===============================================
echo Compilation Success (obfuscated)!
echo ===============================================
echo.
echo Copying hidder_vault.dll to resources...
copy /Y hidder_vault.dll "..\src\main\resources\hidder_vault.dll"

if %errorlevel% neq 0 (
    echo [ERROR] Vault resource copy failed.
    if not defined HIDDER_NONINTERACTIVE pause
    exit /b %errorlevel%
)

copy /Y "..\build\generated\native\class_fingerprints.generated.sha256" "..\src\main\resources\native-class-fingerprints.sha256"

if %errorlevel% neq 0 (
    echo [ERROR] Fingerprint identity copy failed.
    if not defined HIDDER_NONINTERACTIVE pause
    exit /b %errorlevel%
)

echo.
echo Done! Vault copied to resources folder.
if not defined HIDDER_NONINTERACTIVE pause
