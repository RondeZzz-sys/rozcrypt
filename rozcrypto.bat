@echo off
set "BASE_DIR=%~dp0"
cd /d "%BASE_DIR%"
set "VC_VARS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VC_VARS%" (
    echo [!] vcvars64.bat not found. Check the path.
    pause
    exit /b
)
call "%VC_VARS%"
echo [BUILD] Compiling...
echo [PATH] Source file: "%BASE_DIR%roz_crypto.c"
cl.exe /O1 /W3 /MT /GS- /DNDEBUG /Fe:"%BASE_DIR%roz_crypt.exe" "%BASE_DIR%roz_crypto.c" ^
user32.lib shell32.lib gdi32.lib comctl32.lib uxtheme.lib wininet.lib advapi32.lib ^
/link /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF
if %errorlevel% equ 0 (
    echo [OK] Build successful!
    echo [FILE] Output: "%BASE_DIR%roz_crypt.exe"
) else (
    echo [!] Compilation failed. Make sure the source file is named roz_crypto.c
)
pause