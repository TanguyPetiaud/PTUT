import sys
import os
from PyQt6.QtWidgets import QApplication, QMainWindow
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import QUrl

class WebViewer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Mon Application Web")
        self.setGeometry(100, 100, 1200, 800)
        
        # Créer le navigateur web
        self.browser = QWebEngineView()
        
        # Charger la page HTML
        html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "page.html")
        
        if os.path.exists(html_path):
            self.browser.setUrl(QUrl.fromLocalFile(html_path))
        else:
            # Page par défaut si page.html n'existe pas
            self.browser.setHtml("""
                <html>
                <head>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            height: 100vh;
                            margin: 0;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        }
                        .container {
                            text-align: center;
                            color: white;
                        }
                        h1 {
                            font-size: 3em;
                            margin-bottom: 20px;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>Bienvenue!</h1>
                        <p>Créez un fichier "page.html" dans le même dossier que l'application pour personnaliser cette page.</p>
                    </div>
                </body>
                </html>
            """)
        
        self.setCentralWidget(self.browser)

def main():
    app = QApplication(sys.argv)
    window = WebViewer()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
