@echo off
echo ========================================
echo Compilation de l'application en .exe
echo ========================================
echo.

REM Mise à jour de pip
echo Mise a jour de pip...
python -m pip install --upgrade pip

echo.
echo Installation des dependances...
python -m pip install PyQt6 PyQt6-WebEngine pyinstaller

echo.
echo ========================================
echo Creation de l'executable...
echo ========================================
echo.

REM Compilation avec PyInstaller
pyinstaller --onefile --windowed --name "MonApplicationWeb" --add-data "page.html;." web_viewer.py

echo.
echo ========================================
echo Compilation terminee!
echo ========================================
echo.
echo Le fichier .exe se trouve dans le dossier "dist"
echo.
pause
