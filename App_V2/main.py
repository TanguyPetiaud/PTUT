import sys, os, shutil, traceback
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs, unquote
from PyQt6.QtWidgets import QApplication, QMainWindow, QMessageBox, QFileDialog
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEnginePage
from PyQt6.QtCore import QUrl

# Imports locaux depuis tes propres fichiers
from utils import app_dir, get_working_xml
from parser import get_dashboard_data
from ui_template import get_ui, get_css_js
from engine import save_rule_xml, save_interface_xml, perform_migration

class CustomPage(QWebEnginePage):
    def __init__(self, window): 
        super().__init__(window)
        self.window = window

    def acceptNavigationRequest(self, url, _type, isMain):
        if url.scheme() == "netmorph":
            parsed = urlparse(url.toString())
            qs = parse_qs(parsed.query)
            data = {k: unquote(v[0]) for k, v in qs.items()}
            
            if parsed.netloc == "import": 
                self.window.import_file()
            elif parsed.netloc == "add_rule": 
                try:
                    save_rule_xml(data)
                    QMessageBox.information(self.window, "SUCCÈS", f"Règle ajoutée !")
                    self.window.refresh_view()
                except Exception as e:
                    QMessageBox.critical(self.window, "ERREUR", traceback.format_exc())
            elif parsed.netloc == "add_if": 
                try:
                    save_interface_xml(data)
                    QMessageBox.information(self.window, "SUCCÈS", "Interface ajoutée.")
                    self.window.refresh_view()
                except Exception as e:
                    QMessageBox.critical(self.window, "ERREUR", str(e))
            elif parsed.netloc == "migrate": 
                self.window.exec_migration()
            return False
        return True


class WebViewer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NETMORPH - Enterprise Firewall Manager")
        self.setGeometry(100, 100, 1350, 850)
        self.browser = QWebEngineView()
        self.browser.setPage(CustomPage(self))
        self.setCentralWidget(self.browser)
        self.refresh_view()

    def refresh_view(self):
        xml_path = get_working_xml()
        data = get_dashboard_data(xml_path) if xml_path else None
        html_content = get_ui(data)
        css_js = get_css_js()
        
        base_url = QUrl.fromLocalFile(app_dir() + "/")
        self.browser.setHtml(f"<html><head>{css_js}</head><body>{html_content}</body></html>", base_url)

    def import_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Importer XML (WG ou pfSense)", "", "XML (*.xml)")
        if path:
            try:
                tree = ET.parse(path)
                root = tree.getroot()
                if root.tag not in ["profile", "pfsense"]: 
                    return QMessageBox.warning(self, "Erreur", "Fichier non reconnu.")
                shutil.copy(path, os.path.join(app_dir(), "firewall.xml"))
                mod_f = os.path.join(app_dir(), "firewall_modifie.xml")
                if os.path.exists(mod_f): os.remove(mod_f)
                self.refresh_view()
            except Exception as e: 
                QMessageBox.critical(self, "Erreur", str(e))

    def exec_migration(self):
        QMessageBox.information(self, "Assistant Migration", "1. Ouvrez la config SOURCE (le vieux routeur)\n2. Ouvrez la config CIBLE (le nouveau routeur vierge)")
        src_path, _ = QFileDialog.getOpenFileName(self, "1. Config SOURCE", "", "XML (*.xml)")
        if not src_path: return
        tgt_path, _ = QFileDialog.getOpenFileName(self, "2. Config CIBLE", "", "XML (*.xml)")
        if not tgt_path: return
        
        try:
            migrated_count = perform_migration(src_path, tgt_path)
            QMessageBox.information(self, "MIGRATION RÉUSSIE", f"Fusion terminée ! {migrated_count} règles intelligemment traduites.")
            self.refresh_view()
        except ValueError as ve:
            QMessageBox.warning(self, "Erreur de Migration", str(ve))
        except Exception as e:
            QMessageBox.critical(self, "Erreur Fatale", traceback.format_exc())


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = WebViewer()
    w.show()
    sys.exit(app.exec())