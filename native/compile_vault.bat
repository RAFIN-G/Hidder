@echo off
echo ===============================================
echo Compiling Vault with OpenSSL
echo ===============================================
echo.
:: Ensure we are in the script's directory
cd /d "%~dp0"

:: Visual Studio paths
set "MSVC_DIR=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.44.35207"
set "CL_EXE=%MSVC_DIR%\bin\Hostx64\x64\cl.exe"
set "LINK_EXE=%MSVC_DIR%\bin\Hostx64\x64\link.exe"

:: Windows SDK paths
set "WINSDK=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

:: OpenSSL paths
set "OPENSSL_DIR=C:\Program Files\OpenSSL-Win64"

:: JDK paths
set "JDK_DIR=C:\Program Files\Java\jdk-21"

:: Set up INCLUDE paths
set "INCLUDE=%MSVC_DIR%\include;%WINSDK%\Include\%WINSDK_VER%\ucrt;%WINSDK%\Include\%WINSDK_VER%\um;%WINSDK%\Include\%WINSDK_VER%\shared"

:: Set up LIB paths
set "LIB=%MSVC_DIR%\lib\x64;%WINSDK%\Lib\%WINSDK_VER%\ucrt\x64;%WINSDK%\Lib\%WINSDK_VER%\um\x64"

echo Compiling...
"%CL_EXE%" /LD /EHsc /MD /Fe:hidder_vault.dll hidder_vault.cpp ^
    /I"%JDK_DIR%\include" ^
    /I"%JDK_DIR%\include\win32" ^
    /I"%OPENSSL_DIR%\include" ^
    /link ^
    /LIBPATH:"%OPENSSL_DIR%\lib\VC\x64\MD" ^
    libcrypto.lib ^
    libssl.lib

if %errorlevel% neq 0 (
    echo.
    echo ===============================================
    echo Compilation Failed!
    echo ===============================================
    pause
    exit /b %errorlevel%
)

echo.
echo ===============================================
echo Compilation Success!
echo ===============================================
echo.
echo Copying hidder_vault.dll to resources...
copy /Y hidder_vault.dll "..\src\main\resources\hidder_vault.dll"

echo.
echo Copying OpenSSL runtime DLL to resources...
copy /Y "%OPENSSL_DIR%\bin\libcrypto-3-x64.dll" "..\src\main\resources\libcrypto-3-x64.dll"

echo.
echo Done! Both DLLs copied to resources folder.
pause
