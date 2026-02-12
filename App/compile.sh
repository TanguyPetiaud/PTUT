#!/bin/bash

echo "========================================"
echo "Compilation de l'application"
echo "========================================"
echo ""

# Installation des dépendances
echo "Installation des dépendances..."
pip install -r requirements.txt

echo ""
echo "========================================"
echo "Création de l'exécutable..."
echo "========================================"
echo ""

# Compilation avec PyInstaller
pyinstaller --onefile --windowed --name "MonApplicationWeb" --add-data "page.html:." web_viewer.py

echo ""
echo "========================================"
echo "Compilation terminée!"
echo "========================================"
echo ""
echo "Le fichier exécutable se trouve dans le dossier 'dist'"
echo ""
