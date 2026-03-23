"""
main.py — Point d'entrée NETMORPH
===================================
Lance la fenêtre principale PyQt6 avec un QWebEngineView.
Toute l'interaction UI passe par le schéma d'URL custom "netmorph://".

URLs disponibles :
  netmorph://import         — importe un fichier WG ou pfSense
  netmorph://export         — exporte le XML modifié
  netmorph://add_rule       — injecte une règle (params QueryString)
  netmorph://add_if         — injecte une interface (params QueryString)
  netmorph://pick_source    — étape 1 migration : sélectionne + détecte la source
  netmorph://migrate        — étape 2 migration : sélectionne la cible + lance la fusion
  netmorph://reset_mig      — réinitialise l'état de migration
"""

import sys
import os
import shutil
import traceback
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs, unquote

from PyQt6.QtWidgets import QApplication, QMainWindow, QMessageBox, QFileDialog
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEnginePage
from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QIcon

from utils import app_dir, get_working_xml
from parser import get_dashboard_data
from ui_template import get_ui, get_css, get_js
from engine import save_rule_xml, save_interface_xml, perform_migration, delete_rule_xml
from audit import run_audit


class CustomPage(QWebEnginePage):
    """
    Intercepte les navigations vers netmorph:// pour les traduire
    en appels Python sans quitter la page courante.
    """

    def __init__(self, window):
        super().__init__(window)
        self.window = window

    def acceptNavigationRequest(self, url, _type, isMain):
        if url.scheme() != "netmorph":
            return True  # Laisser passer les URLs normales (ressources locales, etc.)

        parsed = urlparse(url.toString())
        qs     = parse_qs(parsed.query)
        data   = {k: unquote(v[0]) for k, v in qs.items()}
        action = parsed.netloc

        if action == "import":
            self.window.import_file()

        elif action == "add_rule":
            try:
                save_rule_xml(data)
                QMessageBox.information(self.window, "✅ Succès", "Règle ajoutée avec succès !")
                self.window.refresh_view()
            except Exception:
                QMessageBox.critical(self.window, "❌ Erreur", traceback.format_exc())

        elif action == "add_if":
            try:
                save_interface_xml(data)
                QMessageBox.information(self.window, "✅ Succès", "Interface ajoutée avec succès !")
                self.window.refresh_view()
            except Exception as e:
                QMessageBox.critical(self.window, "❌ Erreur", str(e))

        elif action == "pick_source":
            self.window.pick_migration_source()

        elif action == "migrate":
            # Le paramètre "dest" vient du dropdown UI (ex: "pfSense" ou "WatchGuard")
            dest = data.get("dest", "").strip()
            self.window.exec_migration(dest)

        elif action == "reset_mig":
            self.window.reset_migration()

        elif action == "delete_rule":
            try:
                idx = int(data.get("index", "-1"))
                delete_rule_xml(idx)
                self.window.refresh_view()
            except Exception as e:
                QMessageBox.critical(self.window, "❌ Erreur", str(e))

        elif action == "export":
            self.window.export_file()

        return False  # Bloquer la navigation — on a traité l'action nous-mêmes


class WebViewer(QMainWindow):
    """Fenêtre principale de NETMORPH."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("NETMORPH — Enterprise Firewall Manager")
        self.setGeometry(100, 100, 1400, 860)

        # Icône de la fenêtre (barre de titre + taskbar)
        icon_path = os.path.join(app_dir(), "netmorph.ico")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        # État de la migration en cours (réinitialisé après chaque migration réussie)
        self.mig_src      = None   # Chemin absolu du fichier source
        self.mig_src_type = None   # "WatchGuard" ou "pfSense"
        self.mig_src_name = None   # Nom de fichier (pour affichage UI)

        self.browser = QWebEngineView()
        self.browser.setPage(CustomPage(self))
        self.setCentralWidget(self.browser)
        self.refresh_view()

    # ──────────────────────────────────────────────────────────────────────────
    # RAFRAICHISSEMENT DE L'UI
    # ──────────────────────────────────────────────────────────────────────────

    def refresh_view(self):
        """Regénère et affiche le HTML complet depuis parser + ui_template."""
        xml_path = get_working_xml()
        data     = get_dashboard_data(xml_path) if xml_path else None

        # Audit de sécurité (None si aucun fichier chargé)
        try:
            audit_results = run_audit(xml_path) if xml_path else None
        except Exception:
            audit_results = None

        # État de migration transmis à l'UI pour afficher le wizard
        mig_state = {
            "src_path": self.mig_src,
            "src_type": self.mig_src_type,
            "src_name": self.mig_src_name,
        }

        html_content = get_ui(data, mig_state, audit_results=audit_results)
        css  = get_css()
        js   = get_js()

        base_url = QUrl.fromLocalFile(app_dir() + "/")
        self.browser.setHtml(
            f"<html><head>{css}</head><body>{html_content}{js}</body></html>",
            base_url
        )

    # ──────────────────────────────────────────────────────────────────────────
    # IMPORT / EXPORT
    # ──────────────────────────────────────────────────────────────────────────

    def import_file(self):
        """Ouvre un fichier WatchGuard ou pfSense et l'active comme configuration courante."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Importer une configuration (WatchGuard ou pfSense)", "", "XML (*.xml)"
        )
        if not path:
            return
        try:
            root = ET.parse(path).getroot()
            if root.tag not in ("profile", "pfsense"):
                return QMessageBox.warning(
                    self, "Fichier non reconnu",
                    "Ce fichier n'est ni un XML WatchGuard (<profile>) ni pfSense (<pfsense>)."
                )
            shutil.copy(path, os.path.join(app_dir(), "firewall.xml"))
            mod_f = os.path.join(app_dir(), "firewall_modifie.xml")
            if os.path.exists(mod_f):
                os.remove(mod_f)
            self.refresh_view()
        except Exception as e:
            QMessageBox.critical(self, "Erreur d'import", str(e))

    def export_file(self):
        """Exporte le XML actif (modifié ou non) vers un chemin choisi par l'utilisateur."""
        src = get_working_xml()
        if not src:
            return QMessageBox.warning(self, "Export impossible", "Aucune configuration chargée.")

        dest, _ = QFileDialog.getSaveFileName(
            self, "Exporter la configuration", "firewall_netmorph.xml", "XML (*.xml)"
        )
        if not dest:
            return
        try:
            shutil.copy(src, dest)
            QMessageBox.information(
                self, "✅ Export réussi",
                f"Fichier exporté :\n{dest}\n\n"
                "• WatchGuard  → System > Backup/Restore > Restore\n"
                "• pfSense     → Diagnostics > Backup & Restore > Restore"
            )
        except Exception as e:
            QMessageBox.critical(self, "Erreur export", str(e))

    # ──────────────────────────────────────────────────────────────────────────
    # WIZARD DE MIGRATION
    # ──────────────────────────────────────────────────────────────────────────

    def pick_migration_source(self):
        """
        Étape 1 du wizard : sélectionne le fichier source, détecte son type
        (WatchGuard ou pfSense) et met à jour l'UI pour montrer la cible compatible.
        """
        path, _ = QFileDialog.getOpenFileName(
            self, "Étape 1 — Fichier SOURCE (WatchGuard ou pfSense)", "", "XML (*.xml)"
        )
        if not path:
            return
        try:
            root = ET.parse(path).getroot()
            if root.tag == "profile":
                detected = "WatchGuard"
            elif root.tag == "pfsense":
                detected = "pfSense"
            else:
                return QMessageBox.warning(
                    self, "Fichier non reconnu",
                    "Ce fichier n'est ni WatchGuard ni pfSense."
                )
            self.mig_src      = path
            self.mig_src_type = detected
            self.mig_src_name = os.path.basename(path)
            self.refresh_view()
        except Exception as e:
            QMessageBox.critical(self, "Erreur de lecture", str(e))

    def exec_migration(self, dest_type: str):
        """
        Étape 2 du wizard : utilise le template de la marque sélectionnée dans le
        dropdown UI, sans dialog fichier. Les templates sont dans le dossier template/.

        Templates disponibles :
          template/Template_Firebox.xml   → WatchGuard
          template/Template_pfsense.xml   → pfSense

        Args:
            dest_type : "WatchGuard" ou "pfSense" (vient du dropdown HTML)
        """
        if not self.mig_src:
            return QMessageBox.warning(
                self, "Étape manquante",
                "Sélectionnez d'abord le fichier source (étape 1)."
            )
        if not dest_type:
            return QMessageBox.warning(
                self, "Destination manquante",
                "Choisissez une marque de destination dans le menu déroulant."
            )

        # Correspondance marque → fichier template
        TEMPLATE_MAP = {
            "WatchGuard": os.path.join(app_dir(), "template", "Template_Firebox.xml"),
            "pfSense":    os.path.join(app_dir(), "template", "Template_pfsense.xml"),
        }
        tgt_path = TEMPLATE_MAP.get(dest_type)
        if not tgt_path:
            return QMessageBox.warning(self, "Marque inconnue", f"Destination '{dest_type}' non supportée.")
        if not os.path.exists(tgt_path):
            return QMessageBox.critical(
                self, "Template introuvable",
                f"Le template {dest_type} est absent :\n{tgt_path}\n\n"
                "Vérifiez que le dossier template/ contient bien les fichiers Template_Firebox.xml et Template_pfsense.xml."
            )

        # Vérification de compatibilité source ≠ destination
        opposite = "pfSense" if self.mig_src_type == "WatchGuard" else "WatchGuard"
        if dest_type == self.mig_src_type:
            return QMessageBox.warning(
                self, "Migration impossible",
                f"La source et la destination sont toutes les deux {self.mig_src_type}.\n"
                f"Choisissez {opposite} comme destination."
            )

        # Lancement de la migration avec le template
        try:
            report = perform_migration(self.mig_src, tgt_path)

            src_type_done     = self.mig_src_type
            self.mig_src      = None
            self.mig_src_type = None
            self.mig_src_name = None

            # ── Construction du rapport de migration ──
            lines = [f"Direction : {src_type_done} → {dest_type}", ""]
            lines.append(f"✅  {report['count']} règle(s) migrée(s)")
            if report["vlans"]:
                lines.append(f"🔌  {len(report['vlans'])} VLAN(s) migré(s)")
            if report["aliases"]:
                lines.append(f"📋  {len(report['aliases'])} alias créé(s)")
            if report["skipped"]:
                lines.append(f"⏭  {len(report['skipped'])} règle(s) système ignorée(s)")
            if report["warnings"]:
                lines.append("\n⚠ Avertissements :")
                for w in report["warnings"][:5]:
                    lines.append(f"  • {w}")
            if report["rules"]:
                lines.append("\nRègles migrées :")
                for r in report["rules"][:12]:
                    lines.append(f"  • {r}")
                if len(report["rules"]) > 12:
                    lines.append(f"  … et {len(report['rules']) - 12} autre(s)")
            lines.append(f"\nExportez puis importez dans {dest_type}.")

            QMessageBox.information(self, "🚀 Migration réussie", "\n".join(lines))
            self.refresh_view()

        except ValueError as ve:
            QMessageBox.warning(self, "Erreur de migration", str(ve))
        except Exception:
            QMessageBox.critical(self, "❌ Erreur fatale", traceback.format_exc())

    def reset_migration(self):
        """Réinitialise le wizard de migration (bouton Annuler dans l'UI)."""
        self.mig_src      = None
        self.mig_src_type = None
        self.mig_src_name = None
        self.refresh_view()


# =============================================================================
if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Icône au niveau application (taskbar Windows + alt-tab)
    icon_path = os.path.join(app_dir(), "netmorph.ico")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    w = WebViewer()
    w.show()
    sys.exit(app.exec())
