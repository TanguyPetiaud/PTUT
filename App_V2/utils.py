import sys, os

def app_dir():
    """Retourne le dossier où s'exécute l'application."""
    if getattr(sys, "frozen", False): return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def get_working_xml():
    """Trouve le fichier XML actuellement utilisé par l'application."""
    mod_path = os.path.join(app_dir(), "firewall_modifie.xml")
    base_path = os.path.join(app_dir(), "firewall.xml")
    return mod_path if os.path.exists(mod_path) else (base_path if os.path.exists(base_path) else None)

def safe_text(elem, tag):
    """Extrait le texte d'une balise XML sans crasher si elle n'existe pas."""
    if elem is None: return ""
    c = elem.find(tag)
    return (c.text or "").strip() if c is not None else ""

def resolve_wg_alias(root, alias_name):
    """Fouille récursivement dans les alias WatchGuard pour trouver la vraie IP ou le vrai Réseau."""
    visited = set()
    def dive(name):
        if name in visited: return []
        visited.add(name)
        base_nets = ["Any-Trusted", "Any-External", "Any-Optional", "Any", "Firebox", "Any-BOVPN"]
        if name in base_nets: return [name]
        
        res = []
        for al in root.findall(".//alias-list/alias"):
            if safe_text(al, "name") == name:
                for mem in al.findall(".//alias-member-list/alias-member/alias-name"):
                    if mem.text: res.extend(dive(mem.text))
                for mem_ip in al.findall(".//alias-member-list/alias-member/address"):
                    if mem_ip.text and mem_ip.text != "Any": res.append(mem_ip.text)
        
        for ag in root.findall(".//address-group-list/address-group"):
            if safe_text(ag, "name") == name:
                ip = safe_text(ag, ".//host-ip-addr")
                if ip: res.append(ip)
                net = safe_text(ag, ".//ip-network-addr")
                if net: res.append(net)
        
        if not res: res = [name.replace(".snat", "")]
        return res

    results = list(set(dive(alias_name)))
    if "Any" in results or ("Any-External" in results and "Any-Trusted" in results): return "any"
    if "Any-External" in results: return "wan"
    if "Any-Trusted" in results: return "lan"
    if results: return results[0]
    return alias_name