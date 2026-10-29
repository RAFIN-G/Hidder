@rem SPDX-FileCopyrightText: 2026 ModSeeker
@rem SPDX-License-Identifier: AGPL-3.0-or-later

@echo off
echo ===============================================
echo Compiling Vault with OpenSSL
echo ===============================================
echo.
cd /d "%~dp0"

if defined HIDDER_MSVC_DIR (set "MSVC_DIR=%HIDDER_MSVC_DIR%") else (set "MSVC_DIR=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.44.35207")
set "CL_EXE=%MSVC_DIR%\bin\Hostx64\x64\cl.exe"
set "LINK_EXE=%MSVC_DIR%\bin\Hostx64\x64\link.exe"

if defined HIDDER_WINSDK (set "WINSDK=%HIDDER_WINSDK%") else (set "WINSDK=C:\Program Files (x86)\Windows Kits\10")
if defined HIDDER_WINSDK_VER (set "WINSDK_VER=%HIDDER_WINSDK_VER%") else (set "WINSDK_VER=10.0.22621.0")

if defined HIDDER_OPENSSL_DIR (set "OPENSSL_DIR=%HIDDER_OPENSSL_DIR%") else (set "OPENSSL_DIR=C:\Program Files\OpenSSL-Win64")

if defined HIDDER_JDK_DIR (set "JDK_DIR=%HIDDER_JDK_DIR%") else if defined JAVA_HOME (set "JDK_DIR=%JAVA_HOME%") else (set "JDK_DIR=C:\Program Files\Zulu\zulu-25")
set "JAVA_HOME=%JDK_DIR%"
if not defined HIDDER_PRIVATE_INPUT_DIR set "HIDDER_PRIVATE_INPUT_DIR=%~dp0."
set "GRADLE_OFFLINE="
if defined HIDDER_OFFLINE set "GRADLE_OFFLINE=--offline"

set "INCLUDE=%MSVC_DIR%\include;%WINSDK%\Include\%WINSDK_VER%\ucrt;%WINSDK%\Include\%WINSDK_VER%\um;%WINSDK%\Include\%WINSDK_VER%\shared"

set "LIB=%MSVC_DIR%\lib\x64;%WINSDK%\Lib\%WINSDK_VER%\ucrt\x64;%WINSDK%\Lib\%WINSDK_VER%\um\x64"

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

echo Compiling...
"%CL_EXE%" /LD /EHsc /MT /Fe:hidder_vault.dll hidder_vault.cpp mod_inflate.cpp ^
    /I"%JDK_DIR%\include" ^
    /I"%JDK_DIR%\include\win32" ^
    /I"%OPENSSL_DIR%\include" ^
    /I"%HIDDER_PRIVATE_INPUT_DIR%" ^
    /I"..\build\generated\native" ^
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
echo Compilation Success!
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
