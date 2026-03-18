import sys, os, html, xml.etree.ElementTree as ET
import re, copy, shutil, traceback
from urllib.parse import urlparse, parse_qs, unquote
from PyQt6.QtWidgets import QApplication, QMainWindow, QMessageBox, QFileDialog
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEnginePage
from PyQt6.QtCore import QUrl

# --- UTILITAIRES ---
def app_dir():
    if getattr(sys, "frozen", False): return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def get_working_xml():
    mod_path = os.path.join(app_dir(), "firewall_modifie.xml")
    base_path = os.path.join(app_dir(), "firewall.xml")
    return mod_path if os.path.exists(mod_path) else (base_path if os.path.exists(base_path) else None)

def safe_text(elem, tag):
    if elem is None: return ""
    c = elem.find(tag)
    return (c.text or "").strip() if c is not None else ""

# 🔥 RÉSOLUTION PROFONDE (Extraction des vraies IPs cachées dans WG) 🔥
def resolve_wg_alias(root, alias_name):
    visited = set(); current = alias_name
    base_networks = ["Any-Trusted", "Any-External", "Any-Optional", "Any", "Firebox", "Any-BOVPN"]
    
    while current not in base_networks and current not in visited:
        visited.add(current)
        found_next = False
        
        # 1. Fouille des alias normaux
        for al in root.findall(".//alias-list/alias"):
            if safe_text(al, "name") == current:
                mem = al.find(".//alias-member-list/alias-member/alias-name")
                if mem is not None and mem.text:
                    current = mem.text; found_next = True; break
                mem_ip = al.find(".//alias-member-list/alias-member/address")
                if mem_ip is not None and mem_ip.text and mem_ip.text != "Any":
                    return mem_ip.text # On a trouvé une vraie IP !
        if found_next: continue
        
        # 2. Fouille des groupes (SNAT/DNAT)
        for ag in root.findall(".//address-group-list/address-group"):
            if safe_text(ag, "name") == current:
                ip = safe_text(ag, ".//host-ip-addr")
                if ip: return ip
                net = safe_text(ag, ".//ip-network-addr")
                if net: return net
        break
        
    if current.endswith(".snat"): current = current.replace(".snat", "")
    return current

# --- MOTEUR D'EXTRACTION ---
def get_dashboard_data(xml_path):
    tree = ET.parse(xml_path); root = tree.getroot()
    is_wg = (root.tag == "profile")
    data = {"is_wg": is_wg, "fw_type": "WatchGuard Fireware" if is_wg else "pfSense"}
    
    if is_wg:
        data["sys"] = {
            "hostname": safe_text(root.find(".//device-conf"), "system-name") or "FireboxV",
            "model": safe_text(root.find(".//device-conf"), "for-model") or "WatchGuard"
        }
        interfaces = []
        for itf in root.findall(".//interface-list/interface"):
            name = safe_text(itf, "name")
            if name in ["Any", "Firebox", "Any-External", "Any-Trusted", "Any-Optional", "Any-BOVPN"]: continue
            ip = "N/A"
            phys, vlan = itf.find(".//physical-if"), itf.find(".//vlan-if")
            if phys is not None: ip = safe_text(phys, "ip") or "DHCP"
            elif vlan is not None: ip = safe_text(vlan, "ip") or "N/A"
            if name: interfaces.append({"name": name, "ip": ip})
        data["itf"] = interfaces

        policies = []
        for pol in root.findall(".//abs-policy-list/abs-policy"):
            if safe_text(pol, "property") == "32": continue
            act = safe_text(pol, "firewall").lower()
            policies.append({
                "name": safe_text(pol, "name"),
                "action": "Allowed" if act in ["1", "allow", "proxy", "allowed"] else "Denied",
                "service": safe_text(pol, "service"),
                "from": ", ".join([resolve_wg_alias(root, a.text) for a in pol.findall(".//from-alias-list/alias")]),
                "to": ", ".join([resolve_wg_alias(root, a.text) for a in pol.findall(".//to-alias-list/alias")])
            })
        data["pol"] = policies

        all_found = set(["Any", "Any-Trusted", "Any-External", "Any-Optional", "Firebox"])
        for al in root.findall(".//alias-list/alias/name"):
            if al.text and not al.text.endswith(".from") and not al.text.endswith(".to"): all_found.add(al.text)
        data["aliases"] = sorted(list(all_found))

    else:
        data["sys"] = {
            "hostname": safe_text(root.find("system"), "hostname") or "pfSense",
            "model": safe_text(root.find("system"), "domain") or "local"
        }
        interfaces = []
        itfs_node = root.find("interfaces")
        if itfs_node is not None:
            for itf in itfs_node:
                name = safe_text(itf, "descr") or itf.tag.upper()
                ip = safe_text(itf, "ipaddr") or "DHCP"
                interfaces.append({"name": f"{name} ({safe_text(itf, 'if')})", "ip": ip})
        data["itf"] = interfaces

        policies = []
        for pol in root.findall(".//filter/rule"):
            src = "any"; dst = "any"
            if pol.find("source/any") is None: src = safe_text(pol, "source/network") or safe_text(pol, "source/address") or "custom"
            if pol.find("destination/any") is None: dst = safe_text(pol, "destination/network") or safe_text(pol, "destination/address") or "custom"
            port = safe_text(pol, "destination/port")
            svc_display = (safe_text(pol, "protocol") or "ANY").upper()
            if port: svc_display += f" (Port {port})"

            policies.append({
                "name": safe_text(pol, "descr") or "Règle Anonyme",
                "action": "Allowed" if safe_text(pol, "type").lower() == "pass" else "Denied",
                "service": svc_display,
                "from": src, "to": dst
            })
        data["pol"] = policies

        all_found = set(["any", "wan", "lan", "wanip", "lanip"])
        for al in root.findall(".//aliases/alias/name"):
            if al.text: all_found.add(al.text)
        data["aliases"] = sorted(list(all_found))

    return data

# --- TEMPLATE HTML GX STYLE ---
def get_ui(data=None):
    if not data:
        return """
        <div class="welcome-screen">
            <div class="gx-card" style="max-width:550px; text-align:center;">
                <img src="logo.png" alt="NETMORPH" style="max-width:80%; margin-bottom: 20px; filter: drop-shadow(0 0 10px #00e5ff);" onerror="this.outerHTML='<h1 class=\\'neon-text\\' style=\\'font-size: 2.8em; margin-bottom: 5px;\\'>&lt;NETMORPH&gt;</h1>'">
                <p style="color:var(--cyan-neon); font-weight:bold; letter-spacing: 2px;">DUAL ENGINE : WATCHGUARD & PFSENSE</p>
                <p style="color:var(--text-muted); margin-bottom:30px; font-size:13px;">Outil de configuration et de migration Firewall.</p>
                <button class="gx-btn" onclick="window.location.href='netmorph://import'">📂 CHARGER UNE CONFIGURATION</button>
            </div>
        </div>"""

    alias_opts = "".join([f'<option value="{a}">{a}</option>' for a in data['aliases']])
    itf_rows = "".join([f"<tr><td><span class='highlight'>{i['name']}</span></td><td>{i['ip']}</td></tr>" for i in data['itf']])
    pol_rows = "".join([f"<tr><td>{p['name']}</td><td><span class='badge-{p['action'].lower()}'>{p['action']}</span></td><td>{p['service']}</td><td class='dim'>{p['from']} &rarr; {p['to']}</td></tr>" for p in data['pol'][-15:]])

    sys_name = f"{data['sys']['hostname']} ({data['sys']['model']})" if data['is_wg'] else f"{data['sys']['hostname']}.{data['sys']['model']}"

    return f"""
    <div class="layout">
        <div class="sidebar">
            <div style="padding: 25px 20px; text-align: center; border-bottom: 1px solid #333;">
                <img src="logo.png" alt="NETMORPH" style="max-width:100%; filter: drop-shadow(0 0 5px #00e5ff);" onerror="this.outerHTML='<div class=\\'logo\\'>&lt;NETMORPH&gt;</div>'">
            </div>
            <div class="nav-item active" id="nav-dash" onclick="tab('dash')"><i>📊</i> Tableau de bord</div>
            <div class="nav-item" id="nav-gen" onclick="tab('gen')"><i>🛡️</i> Éditeur Rapide</div>
            <div class="nav-item" id="nav-mig" onclick="tab('mig')"><i>🔄</i> Migrateur Intelligent</div>
            <div style="flex-grow: 1;"></div>
            <div class="sys-info">
                <span style="color:var(--cyan-neon); font-weight:bold;">{data['fw_type']}</span><br>
                <span>{sys_name}</span><br>
                <span class="dim">{len(data['aliases'])} Objets détectés</span>
            </div>
        </div>

        <div class="content">
            <div id="section-dash" class="scroll-area">
                <h2 class="section-title">Analyse : {data['fw_type']}</h2>
                <div class="grid-2">
                    <div class="gx-card"><div class="card-header">Topologie</div><table><thead><tr><th>Interface</th><th>Routage IP</th></tr></thead><tbody>{itf_rows}</tbody></table></div>
                    <div class="gx-card"><div class="card-header">Politiques (Top 15)</div><table><thead><tr><th>Règle</th><th>Action</th><th>Service</th><th>Flux</th></tr></thead><tbody>{pol_rows}</tbody></table></div>
                </div>
            </div>

            <div id="section-gen" class="scroll-area" style="display:none;">
                <h2 class="section-title">Injection Classique : {data['fw_type']}</h2>
                <div class="grid-2">
                    <div class="gx-card glow-red">
                        <div class="card-header">Nouvelle Règle</div>
                        <input type="text" id="rl-n" class="gx-input" placeholder="Nom (ex: ALLOW_SRV)">
                        <input type="text" id="rl-s" class="gx-input" placeholder="Port/Service (ex: 80, HTTPS, DNS)">
                        <div style="display:flex; gap:15px;">
                            <select id="rl-src" class="gx-input" style="flex:1">{alias_opts}</select>
                            <select id="rl-dst" class="gx-input" style="flex:1">{alias_opts}</select>
                        </div>
                        <select id="rl-a" class="gx-input"><option value="allow">Autoriser</option><option value="deny">Bloquer</option></select>
                        <button class="gx-btn" style="width:100%;" onclick="runRl()">CRÉER RÈGLE</button>
                    </div>
                    <div class="gx-card glow-cyan">
                        <div class="card-header">Nouvelle Interface</div>
                        <input type="text" id="if-n" class="gx-input" placeholder="Nom (ex: DMZ)">
                        <input type="text" id="if-i" class="gx-input" placeholder="IP (ex: 10.0.50.1)">
                        <button class="gx-btn btn-cyan" style="width:100%;" onclick="runIf()">CRÉER INTERFACE</button>
                    </div>
                </div>
            </div>

            <div id="section-mig" class="scroll-area" style="display:none;">
                <h2 class="section-title">Migrateur Cross-Vendor (Semantique)</h2>
                <div class="gx-card glow-purple" style="max-width:800px;">
                    <div class="card-header">⚙️ Processus de Fusion & NAT Intelligence</div>
                    <p style="color:var(--text-muted); line-height:1.6; margin-bottom: 25px;">
                        L'outil de migration NETMORPH ne fait pas que copier, il <b>traduit</b> !<br>
                        ✔ <b>Réseaux :</b> <i>Any-External</i> devient <i>ANY</i>, <i>Any-Trusted</i> devient <i>LAN</i>.<br>
                        ✔ <b>Services :</b> <i>HTTP-Proxy</i> est converti en <i>TCP port 80</i> pour pfSense.<br>
                        ✔ <b>Port Forwarding :</b> Les redirections DNAT de WatchGuard génèrent automatiquement les règles NAT correspondantes dans pfSense !<br><br>
                        Les règles de base inutiles sont ignorées pour garder une configuration propre.
                    </p>
                    <button class="gx-btn" style="width:100%; background: linear-gradient(90deg, #9d00ff, #ff007f); font-size:16px;" onclick="window.location.href='netmorph://migrate'">
                        🚀 DÉMARRER LA MIGRATION
                    </button>
                </div>
            </div>
        </div>
    </div>
    """

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
        
        css = """<style>
            :root { --bg-main:#0a0a0f; --bg-panel:#13131c; --bg-card:#1c1c28; --red-neon:#fa194f; --purple-neon:#9d00ff; --cyan-neon:#00e5ff; --text-main:#e0e0e0; --text-muted:#8888a0; }
            body { margin:0; font-family:'Segoe UI', sans-serif; background:var(--bg-main); color:var(--text-main); }
            .logo { font-size: 22px; font-weight: 900; color: white; letter-spacing: 2px; text-shadow: 0 0 10px var(--cyan-neon); }
            .section-title { font-size: 22px; font-weight: 300; letter-spacing: 1px; margin-bottom: 25px; border-left: 4px solid var(--red-neon); padding-left: 15px; }
            .card-header { font-size: 16px; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 20px; color: white; }
            label { display: block; font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 8px; text-transform: uppercase; }
            .layout { display: flex; height: 100vh; }
            .sidebar { width: 260px; background: var(--bg-panel); display: flex; flex-direction: column; border-right: 1px solid #2a2a3a; }
            .content { flex: 1; padding: 40px; overflow-y: auto; background: radial-gradient(circle at top right, #1a1a2e, var(--bg-main)); }
            .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; }
            .nav-item { padding: 18px 25px; cursor: pointer; font-size: 15px; font-weight: 500; color: var(--text-muted); border-left: 3px solid transparent; transition: 0.3s; }
            .nav-item:hover { background: rgba(250, 25, 79, 0.05); color: white; }
            .nav-item.active { background: linear-gradient(90deg, rgba(250, 25, 79, 0.15) 0%, transparent 100%); color: var(--red-neon); border-left: 3px solid var(--red-neon); text-shadow: 0 0 8px rgba(250, 25, 79, 0.5); }
            .sys-info { padding: 20px; font-size: 12px; background: #0a0a0f; border-top: 1px solid #2a2a3a; line-height: 1.6; }
            .gx-card { background: var(--bg-card); padding: 30px; border-radius: 8px; border: 1px solid #333; position: relative; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
            .gx-card::before { content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 2px; background: #333; transition: 0.3s; }
            .gx-card:hover::before { background: var(--purple-neon); box-shadow: 0 0 15px var(--purple-neon); }
            .glow-red:hover::before { background: var(--red-neon); box-shadow: 0 0 15px var(--red-neon); }
            .glow-cyan:hover::before { background: var(--cyan-neon); box-shadow: 0 0 15px var(--cyan-neon); }
            .glow-purple:hover::before { background: var(--purple-neon); box-shadow: 0 0 15px var(--purple-neon); }
            .gx-input { width: 100%; background: #0a0a0f; border: 1px solid #333; color: white; padding: 14px; font-size: 14px; border-radius: 4px; box-sizing: border-box; margin-bottom: 20px; outline: none; transition: 0.3s; }
            .gx-input:focus { border-color: var(--red-neon); box-shadow: 0 0 10px rgba(250, 25, 79, 0.3); }
            select.gx-input { cursor: pointer; appearance: none; background-image: url("data:image/svg+xml;charset=US-ASCII,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%22292.4%22%20height%3D%22292.4%22%3E%3Cpath%20fill%3D%22%23fa194f%22%20d%3D%22M287%2069.4a17.6%2017.6%200%200%200-13-5.4H18.4c-5%200-9.3%201.8-12.9%205.4A17.6%2017.6%200%200%200%200%2082.2c0%205%201.8%209.3%205.4%2012.9l128%20127.9c3.6%203.6%207.8%205.4%2012.8%205.4s9.2-1.8%2012.8-5.4L287%2095c3.5-3.5%205.4-7.8%205.4-12.8%200-5-1.9-9.2-5.5-12.8z%22%2F%3E%3C%2Fsvg%3E"); background-repeat: no-repeat; background-position: right 15px top 50%; background-size: 12px auto; }
            .gx-btn { background: linear-gradient(90deg, var(--red-neon), var(--purple-neon)); border: none; padding: 15px; color: white; font-weight: bold; letter-spacing: 1px; border-radius: 4px; cursor: pointer; transition: 0.3s; text-transform: uppercase; font-size: 14px; box-shadow: 0 4px 15px rgba(250, 25, 79, 0.3); }
            .gx-btn:hover { box-shadow: 0 0 20px rgba(157, 0, 255, 0.6); filter: brightness(1.2); transform: translateY(-1px); }
            .btn-cyan { background: linear-gradient(90deg, #0088ff, var(--cyan-neon)); box-shadow: 0 4px 15px rgba(0, 229, 255, 0.2); }
            .btn-cyan:hover { box-shadow: 0 0 20px rgba(0, 229, 255, 0.5); }
            table { width: 100%; border-collapse: collapse; font-size: 13px; }
            th { text-align: left; padding: 12px; color: var(--text-muted); border-bottom: 1px solid #333; font-weight: 600; text-transform: uppercase; font-size: 11px; }
            td { padding: 12px; border-bottom: 1px solid #2a2a3a; }
            tr:hover td { background: rgba(255,255,255,0.02); }
            .highlight { color: var(--cyan-neon); font-weight: bold; }
            .badge-allowed { color: #00ff88; text-shadow: 0 0 5px #00ff88; font-weight: bold; }
            .badge-denied { color: #ff3366; text-shadow: 0 0 5px #ff3366; font-weight: bold; }
            .dim { color: var(--text-muted); }
            .welcome-screen { height:100vh; display:flex; align-items:center; justify-content:center; background: radial-gradient(circle at center, #1a1a2e, var(--bg-main)); }
        </style>"""

        js = """<script>
            function tab(t) {
                document.getElementById('section-dash').style.display = (t=='dash'?'block':'none');
                document.getElementById('section-gen').style.display = (t=='gen'?'block':'none');
                document.getElementById('section-mig').style.display = (t=='mig'?'block':'none');
                document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
                document.getElementById('nav-'+t).classList.add('active');
            }
            function runRl() {
                const n = document.getElementById('rl-n').value;
                const s = document.getElementById('rl-s').value;
                if(!n || !s) return alert('Complétez les champs requis.');
                window.location.href = `netmorph://add_rule?name=${encodeURIComponent(n)}&action=${document.getElementById('rl-a').value}&service=${encodeURIComponent(s)}&from=${encodeURIComponent(document.getElementById('rl-src').value)}&to=${encodeURIComponent(document.getElementById('rl-dst').value)}`;
            }
            function runIf() {
                const n = document.getElementById('if-n').value;
                const i = document.getElementById('if-i').value;
                if(!n || !i) return alert('Complétez les champs requis.');
                window.location.href = `netmorph://add_if?name=${encodeURIComponent(n)}&ip=${encodeURIComponent(i)}`;
            }
        </script>"""
        
        base_url = QUrl.fromLocalFile(app_dir() + "/")
        self.browser.setHtml(f"<html><head>{css}</head><body>{get_ui(data)}{js}</body></html>", base_url)

    def import_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Importer XML (WG ou pfSense)", "", "XML (*.xml)")
        if path:
            try:
                tree = ET.parse(path)
                root = tree.getroot()
                if root.tag not in ["profile", "pfsense"]: return QMessageBox.warning(self, "Erreur", "Fichier non reconnu.")
                shutil.copy(path, os.path.join(app_dir(), "firewall.xml"))
                mod_f = os.path.join(app_dir(), "firewall_modifie.xml")
                if os.path.exists(mod_f): os.remove(mod_f)
                self.refresh_view()
            except Exception as e: QMessageBox.critical(self, "Erreur", str(e))

    def save_rule_xml(self, data):
        xml_path = get_working_xml(); out_path = os.path.join(app_dir(), "firewall_modifie.xml")
        try:
            tree = ET.parse(xml_path); root = tree.getroot()
            if root.tag == "profile":
                self.wg_inject_rule(root, data.get("name"), data.get("action"), data.get("service"), data.get("from"), data.get("to"))
            elif root.tag == "pfsense":
                self.pfsense_inject_rule(root, data.get("name"), data.get("action"), data.get("service"), data.get("from"), data.get("to"))
            tree.write(out_path, encoding="utf-8", xml_declaration=True)
            QMessageBox.information(self, "SUCCÈS", f"Règle ajoutée !")
            self.refresh_view()
        except Exception as e: QMessageBox.critical(self, "ERREUR", traceback.format_exc())

    def save_interface_xml(self, data):
        xml_path = get_working_xml(); out_path = os.path.join(app_dir(), "firewall_modifie.xml")
        try:
            tree = ET.parse(xml_path); root = tree.getroot()
            i_name = data.get("name"); i_ip = data.get("ip")
            if root.tag == "profile":
                itf_list = root.find("interface-list")
                new_itf = ET.Element("interface")
                ET.SubElement(new_itf, "name").text = i_name
                ET.SubElement(new_itf, "property").text = "0"
                vif = ET.SubElement(ET.SubElement(ET.SubElement(new_itf, "if-item-list"), "item"), "vlan-if")
                v_num = re.search(r'\d+', i_name).group(0) if re.search(r'\d+', i_name) else "99"
                ET.SubElement(vif, "vlan-id").text = v_num; ET.SubElement(vif, "ip").text = i_ip
                ET.SubElement(vif, "netmask").text = "255.255.255.0"
                itf_list.append(new_itf)
            elif root.tag == "pfsense":
                itfs_node = root.find("interfaces")
                opt_count = sum(1 for child in itfs_node if child.tag.startswith("opt")) + 1
                new_itf = ET.Element(f"opt{opt_count}")
                ET.SubElement(new_itf, "descr").text = i_name
                ET.SubElement(new_itf, "if").text = f"vlan{opt_count}"
                ET.SubElement(new_itf, "enable")
                ET.SubElement(new_itf, "ipaddr").text = i_ip
                ET.SubElement(new_itf, "subnet").text = "24"
                itfs_node.append(new_itf)
            tree.write(out_path, encoding="utf-8", xml_declaration=True)
            QMessageBox.information(self, "SUCCÈS", "Interface ajoutée.")
            self.refresh_view()
        except Exception as e: QMessageBox.critical(self, "ERREUR", str(e))

    # --- SOUS-MOTEURS D'INJECTION ---
    def wg_inject_rule(self, wg_root, name, action, service, src, dst):
        abs_list = wg_root.find("abs-policy-list"); pol_list = wg_root.find("policy-list"); alias_list = wg_root.find("alias-list")
        internal_id = f"{name}-00"

        new_abs = copy.deepcopy(abs_list.find("abs-policy"))
        new_abs.find("name").text = name
        new_abs.find("service").text = service
        new_abs.find("firewall").text = "Allow" if action == "allow" else "Block"
        if new_abs.find("property") is not None: new_abs.find("property").text = "0"
        if new_abs.find("traffic-type") is not None: new_abs.find("traffic-type").text = "1"
        if new_abs.find("policy-nat") is not None: new_abs.find("policy-nat").text = ""

        for p_link in new_abs.findall(".//policy-list/policy"): p_link.text = internal_id
        
        eng_tmp = pol_list.find("policy")
        new_eng = copy.deepcopy(eng_tmp)
        new_eng.find("name").text = internal_id
        new_eng.find("service").text = service
        new_eng.find("firewall").text = "1" if action == "allow" else "2"
        if new_eng.find("property") is not None: new_eng.find("property").text = "0"

        f_alias = f"{name}.1.from"; t_alias = f"{name}.1.to"
        if alias_list is not None:
            for suffix_name, target_val in [(f_alias, src), (t_alias, dst)]:
                new_alias = ET.Element("alias")
                ET.SubElement(new_alias, "name").text = suffix_name
                ET.SubElement(new_alias, "property").text = "16"
                mem = ET.SubElement(ET.SubElement(new_alias, "alias-member-list"), "alias-member")
                ET.SubElement(mem, "type").text = "2" 
                ET.SubElement(mem, "alias-name").text = target_val
                alias_list.append(new_alias)

        for part in [new_abs, new_eng]:
            for tag, target_alias in [("from-alias-list", f_alias), ("to-alias-list", t_alias)]:
                elem = part.find(tag)
                if elem is not None:
                    for c in list(elem): elem.remove(c)
                    ET.SubElement(elem, "alias").text = target_alias

        abs_list.append(new_abs); pol_list.append(new_eng)

    def pfsense_inject_rule(self, pfs_root, name, action, service, src, dst):
        filter_node = pfs_root.find("filter")
        if filter_node is None: filter_node = ET.SubElement(pfs_root, "filter")

        new_rule = ET.Element("rule")
        ET.SubElement(new_rule, "type").text = "pass" if action == "allow" else "block"
        ET.SubElement(new_rule, "interface").text = "lan" 
        ET.SubElement(new_rule, "ipprotocol").text = "inet"
        
        service_in = service.lower()
        pf_proto = "tcp"; pf_port = ""
        
        wg_svc_to_pf = {
            "http": ("tcp", "80"), "https": ("tcp", "443"), "http-proxy": ("tcp", "80"), "https-proxy": ("tcp", "443"),
            "ftp": ("tcp", "21"), "ftp-proxy": ("tcp", "21"), "dns": ("tcp/udp", "53"), "dns-proxy": ("tcp/udp", "53"),
            "ping": ("icmp", ""), "tcp-udp": ("tcp/udp", ""), "any": ("any", "")
        }

        if service_in in wg_svc_to_pf:
            pf_proto, pf_port = wg_svc_to_pf[service_in]
        elif service_in.isdigit():
            pf_proto = "tcp/udp"; pf_port = service_in
        else:
            pf_proto = "tcp"; pf_port = service_in

        ET.SubElement(new_rule, "protocol").text = pf_proto
        
        for tag_name, val in [("source", src.lower()), ("destination", dst.lower())]:
            node = ET.SubElement(new_rule, tag_name)
            if val == "any": 
                ET.SubElement(node, "any")
            elif val in ["wan", "lan", "wanip"] or val.startswith("opt"): 
                ET.SubElement(node, "network").text = val
            else: 
                ET.SubElement(node, "address").text = val
            
            # 🔥 Fix du Port pfSense (Ne met pas de port si c'est ICMP ou ANY)
            if tag_name == "destination" and pf_port and pf_proto not in ["icmp", "any"]:
                ET.SubElement(node, "port").text = pf_port

        ET.SubElement(new_rule, "descr").text = name
        filter_node.append(new_rule)

    # 🔥 NOUVEAU : CRÉATEUR DE NAT PORT FORWARDING POUR PFSENSE 🔥
    def pfsense_inject_nat_rule(self, pfs_root, descr, proto, ext_port, int_port, target_ip):
        nat_node = pfs_root.find("nat")
        if nat_node is None:
            nat_node = ET.SubElement(pfs_root, "nat")
        
        rule = ET.Element("rule")
        ET.SubElement(ET.SubElement(rule, "source"), "any")
        
        dest = ET.SubElement(rule, "destination")
        ET.SubElement(dest, "network").text = "wanip"
        if ext_port: ET.SubElement(dest, "port").text = ext_port
        
        ET.SubElement(rule, "ipprotocol").text = "inet"
        ET.SubElement(rule, "protocol").text = proto
        ET.SubElement(rule, "target").text = target_ip
        if int_port: ET.SubElement(rule, "local-port").text = int_port
        
        ET.SubElement(rule, "interface").text = "wan"
        ET.SubElement(rule, "descr").text = descr
        
        nat_node.append(rule)

    # 🔥 LE CONVERTISSEUR SÉMANTIQUE COMPLET 🔥
    def exec_migration(self):
        QMessageBox.information(self, "Assistant Migration", "1. Ouvrez la config SOURCE (le vieux routeur)\n2. Ouvrez la config CIBLE (le nouveau routeur, qui gardera ses règles de base)")
        
        src_path, _ = QFileDialog.getOpenFileName(self, "1. Config SOURCE", "", "XML (*.xml)")
        if not src_path: return
        tgt_path, _ = QFileDialog.getOpenFileName(self, "2. Config CIBLE", "", "XML (*.xml)")
        if not tgt_path: return
        
        try:
            t_src = ET.parse(src_path); r_src = t_src.getroot()
            t_tgt = ET.parse(tgt_path); r_tgt = t_tgt.getroot()
            migrated_count = 0
            
            # --- WATCHGUARD vers PFSENSE ---
            if r_src.tag == "profile" and r_tgt.tag == "pfsense":
                # 🔥 Fix des réseaux : Any-External devient ANY pour autoriser tout internet
                alias_map = {"Any-Trusted": "lan", "Any-External": "any", "Any-Optional": "opt1", "Any": "any", "Firebox": "wanip"}
                
                ignored_wg_rules = [
                    "watchguard certificate portal", "watchguard web ui", "watchguard",
                    "unhandled internal packet", "unhandled external packet", "allow-ike-to-firebox",
                    "ping", "dns", "outgoing"
                ]

                for pol in r_src.findall(".//abs-policy-list/abs-policy"):
                    if safe_text(pol, "property") == "32": continue
                    name = safe_text(pol, "name")
                    if name.lower() in ignored_wg_rules: continue 
                    
                    act = "allow" if safe_text(pol, "firewall").lower() in ["1", "allow", "proxy", "allowed"] else "deny"
                    svc = safe_text(pol, "service")
                    
                    # RÉSOLUTION PROFONDE DES SOURCES/DESTINATIONS
                    raw_src = safe_text(pol, "from-alias-list/alias")
                    resolved_src = resolve_wg_alias(r_src, raw_src)
                    pf_src = alias_map.get(resolved_src, resolved_src)
                    
                    raw_dst = safe_text(pol, "to-alias-list/alias")
                    resolved_dst = resolve_wg_alias(r_src, raw_dst)
                    pf_dst = alias_map.get(resolved_dst, resolved_dst)
                    
                    # 🔥 DÉTECTION DU PORT FORWARDING (NAT) 🔥
                    pnat = safe_text(pol, "policy-nat")
                    nat_target_ip = None
                    
                    if pnat:
                        # On va fouiller dans les règles de NAT WatchGuard
                        for nat in r_src.findall(".//nat-list/nat"):
                            if safe_text(nat, "name") == pnat:
                                mem = nat.find(".//nat-item/member")
                                if mem is not None:
                                    internal_alias = safe_text(mem, "addr-name")
                                    # On obtient la vraie IP (ex: 192.168.2.1)
                                    nat_target_ip = resolve_wg_alias(r_src, internal_alias)
                                    # Pour pfSense, la règle Firewall doit cibler l'IP interne
                                    pf_dst = nat_target_ip 
                                break

                    # Injection de la règle Firewall
                    self.pfsense_inject_rule(r_tgt, f"[MIG_WG] {name}", act, svc, pf_src, pf_dst)
                    
                    # Injection de la règle NAT si présente
                    if pnat and nat_target_ip:
                        pf_proto = "tcp"
                        pf_port = "443" if "https" in svc.lower() else ("80" if "http" in svc.lower() else "")
                        self.pfsense_inject_nat_rule(r_tgt, f"NAT: {name}", pf_proto, pf_port, pf_port, nat_target_ip)

                    migrated_count += 1
            
            # --- PFSENSE vers WATCHGUARD ---
            elif r_src.tag == "pfsense" and r_tgt.tag == "profile":
                alias_map = {"lan": "Any-Trusted", "wan": "Any-External", "opt1": "Any-Optional", "any": "Any", "wanip": "Firebox", "lanip": "Firebox"}
                for pf_rule in r_src.findall(".//filter/rule"):
                    name = safe_text(pf_rule, "descr")
                    if name in ["Anti-Lockout Rule", "Default allow LAN to any rule", "Default allow LAN IPv6 to any rule"] or not name: continue
                    
                    act = "allow" if safe_text(pf_rule, "type").lower() == "pass" else "block"
                    proto = safe_text(pf_rule, "protocol").lower()
                    port = safe_text(pf_rule, "destination/port")
                    
                    svc = "Any"
                    if proto == "icmp": svc = "Ping"
                    elif port == "80": svc = "HTTP"
                    elif port == "443": svc = "HTTPS"
                    elif port == "53": svc = "DNS"
                    elif port == "21": svc = "FTP"
                    elif proto == "tcp": svc = "TCP"
                    
                    src = "any"
                    if pf_rule.find("source/network") is not None: src = safe_text(pf_rule, "source/network")
                    elif pf_rule.find("source/address") is not None: src = safe_text(pf_rule, "source/address")
                    
                    dst = "any"
                    if pf_rule.find("destination/network") is not None: dst = safe_text(pf_rule, "destination/network")
                    elif pf_rule.find("destination/address") is not None: dst = safe_text(pf_rule, "destination/address")
                    
                    wg_src = alias_map.get(src.lower(), src)
                    wg_dst = alias_map.get(dst.lower(), dst)
                    
                    clean_name = f"MIG_{name}"[:25]
                    self.wg_inject_rule(r_tgt, clean_name, act, svc, wg_src, wg_dst)
                    migrated_count += 1
            else:
                return QMessageBox.warning(self, "Erreur", "La migration nécessite un fichier Source et un fichier Cible de marques différentes.")

            out_path = os.path.join(app_dir(), "firewall_modifie.xml")
            t_tgt.write(out_path, encoding="utf-8", xml_declaration=True)
            shutil.copy(out_path, os.path.join(app_dir(), "firewall.xml"))
            QMessageBox.information(self, "MIGRATION RÉUSSIE", f"Fusion terminée ! {migrated_count} règles intelligemment traduites.")
            self.refresh_view()
            
        except Exception as e:
            QMessageBox.critical(self, "Erreur Fatale", traceback.format_exc())

class CustomPage(QWebEnginePage):
    def __init__(self, window): super().__init__(window); self.window = window
    def acceptNavigationRequest(self, url, _type, isMain):
        if url.scheme() == "netmorph":
            parsed = urlparse(url.toString()); qs = parse_qs(parsed.query)
            data = {k: unquote(v[0]) for k, v in qs.items()}
            if parsed.netloc == "import": self.window.import_file()
            elif parsed.netloc == "add_rule": self.window.save_rule_xml(data)
            elif parsed.netloc == "add_if": self.window.save_interface_xml(data)
            elif parsed.netloc == "migrate": self.window.exec_migration()
            return False
        return True

if __name__ == "__main__":
    app = QApplication(sys.argv); w = WebViewer(); w.show(); sys.exit(app.exec())