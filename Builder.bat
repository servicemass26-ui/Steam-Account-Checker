@echo off
set SCRIPT_NAME=steam_checker.py
set ICON=icon.ico

echo ==========================================
echo  Building %SCRIPT_NAME% with Nuitka (CLI + Icon)
echo ==========================================

python -m nuitka ^
 --standalone ^
 --onefile ^
 --include-module=httpx ^
 --include-module=bs4 ^
 --include-module=bs4.builder._htmlparser ^
 --include-module=Crypto ^
 --include-module=Crypto.PublicKey ^
 --include-module=Crypto.Cipher ^
 --include-module=Crypto.Util ^
 --windows-icon-from-ico=%ICON% ^
 --jobs=12 ^
 --output-dir=. ^
 %SCRIPT_NAME%

echo ==========================================
echo  Build complete! EXE: %~nSCRIPT_NAME%.exe
echo ==========================================
pause
