import xml.etree.ElementTree as ET
from utils import safe_text, resolve_wg_alias

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