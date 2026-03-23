# Application Web Viewer - Guide d'utilisation

## 📋 Description
Cette application vous permet d'ouvrir une page HTML personnalisée dans une fenêtre dédiée. Vous pouvez facilement modifier le contenu de la page en éditant le fichier HTML.

## 🚀 Installation et Compilation

### Prérequis
- Python 3.8 ou supérieur installé sur votre système
- Windows (pour créer le fichier .exe)

### Étapes pour créer le fichier .exe

1. **Installer Python** (si ce n'est pas déjà fait)
   - Téléchargez depuis https://www.python.org/downloads/
   - Cochez "Add Python to PATH" lors de l'installation

2. **Exécuter le script de compilation**
   - Double-cliquez sur `compile.bat`
   - Le script va:
     * Installer les dépendances nécessaires
     * Compiler l'application en fichier .exe
     * Créer un dossier `dist` avec votre application

3. **Récupérer votre application**
   - Allez dans le dossier `dist`
   - Vous y trouverez `MonApplicationWeb.exe`
   - Copiez ce fichier où vous voulez

## 📝 Personnalisation de la page HTML

### Modifier la page
1. Ouvrez le fichier `page.html` avec un éditeur de texte (Notepad++, VSCode, etc.)
2. Modifiez le contenu HTML, CSS et JavaScript selon vos besoins
3. Sauvegardez le fichier
4. Relancez l'application pour voir les changements

### Exemples de modifications

#### Changer le titre
```html
<h1>Votre nouveau titre ici</h1>
```

#### Changer les couleurs
```css
background: linear-gradient(135deg, #FF6B6B 0%, #4ECDC4 100%);
```

#### Ajouter une image
```html
<img src="mon_image.jpg" alt="Description">
```

## 📦 Distribution de votre application

Une fois compilée, vous pouvez distribuer votre application de deux façons:

### Option 1: Application avec page HTML séparée (Recommandé)
- Distribuez `MonApplicationWeb.exe` ET `page.html` dans le même dossier
- L'utilisateur peut modifier `page.html` pour personnaliser l'affichage
- Plus flexible

### Option 2: Application standalone
- Si vous recompilez avec `--onefile` après avoir modifié la page
- La page HTML sera intégrée dans l'exe
- Moins flexible mais plus simple à distribuer

## 🛠️ Compilation manuelle (alternative)

Si vous préférez compiler manuellement:

```bash
# Installer les dépendances
pip install -r requirements.txt

# Compiler l'application
pyinstaller --onefile --windowed --name "MonApplicationWeb" --add-data "page.html;." web_viewer.py
```

## 💡 Conseils

- **Tester avant de distribuer**: Testez toujours votre .exe avant de le distribuer
- **Antivirus**: Certains antivirus peuvent signaler les exe PyInstaller comme suspects (faux positif). C'est normal.
- **Taille du fichier**: Le fichier .exe fait environ 50-80 Mo à cause des dépendances Qt
- **JavaScript**: Toutes les fonctionnalités JavaScript modernes sont supportées
- **Ressources locales**: Vous pouvez ajouter des images, CSS et JS externes dans le même dossier

## 🔧 Dépannage

### L'application ne se lance pas
- Vérifiez que Python est bien installé
- Réinstallez les dépendances: `pip install -r requirements.txt`

### La page HTML ne s'affiche pas
- Vérifiez que `page.html` est dans le même dossier que le .exe
- Vérifiez qu'il n'y a pas d'erreurs dans votre code HTML

### Erreur lors de la compilation
- Assurez-vous d'avoir les droits administrateur
- Vérifiez que votre antivirus ne bloque pas PyInstaller

## 📧 Support

Pour toute question ou problème, n'hésitez pas à consulter:
- Documentation PyQt6: https://www.riverbankcomputing.com/software/pyqt/
- Documentation PyInstaller: https://pyinstaller.org/

## 📄 Licence

Ce projet est libre d'utilisation pour vos projets personnels et commerciaux.

---

Bonne création! 🎨
