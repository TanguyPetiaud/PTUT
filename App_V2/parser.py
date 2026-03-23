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
            ip = "N/A"; if_dev = ""
            phys, vlan = itf.find(".//physical-if"), itf.find(".//vlan-if")
            if phys is not None:
                ip     = safe_text(phys, "ip") or "DHCP"
                if_dev = safe_text(phys, "if-dev-name")   # ex: eth0, eth1
            elif vlan is not None:
                ip     = safe_text(vlan, "ip") or "N/A"
                if_dev = safe_text(vlan, "if-dev-name")   # ex: vlan10
            if name: interfaces.append({"name": name, "ip": ip, "if_dev": if_dev, "if_key": name})
        data["itf"] = interfaces

        # Construire un index nat-name → détails pour affichage rapide
        nat_index = {}
        for nat in root.findall(".//nat-list/nat"):
            nat_name = safe_text(nat, "name") or ""
            nat_type = safe_text(nat, "type")
            if nat_type == "7":
                mem = nat.find(".//nat-item/member")
                if mem is not None:
                    ext_port = safe_text(mem, "port") or ""
                    int_alias = safe_text(mem, "addr-name") or ""
                    int_ip = resolve_wg_alias(root, int_alias)
                    nat_index[nat_name] = f"{int_ip}:{ext_port}" if ext_port else int_ip

        policies = []
        for pol in root.findall(".//abs-policy-list/abs-policy"):
            if safe_text(pol, "property") == "32": continue
            act = safe_text(pol, "firewall").lower()
            pol_nat = safe_text(pol, "policy-nat") or ""
            nat_label = nat_index.get(pol_nat, pol_nat) if pol_nat else ""
            policies.append({
                "name": safe_text(pol, "name"),
                "action": "Allowed" if act in ["1", "allow", "proxy", "allowed"] else "Denied",
                "service": safe_text(pol, "service"),
                "from": ", ".join([resolve_wg_alias(root, a.text) for a in pol.findall(".//from-alias-list/alias")]),
                "to": ", ".join([resolve_wg_alias(root, a.text) for a in pol.findall(".//to-alias-list/alias")]),
                "nat": nat_label,
            })
        data["pol"] = policies

        # ── NAT WatchGuard ──
        nat_rules = []
        for nat in root.findall(".//nat-list/nat"):
            nat_type = safe_text(nat, "type")
            nat_prop = safe_text(nat, "property")
            nat_name = safe_text(nat, "name") or ""
            # type=3 = Dynamic NAT (masquerade), type=7 = SNAT/port forwarding
            # property=4 = NAT système (Dynamic-NAT built-in), on l'affiche quand même
            if nat_type == "7":
                # SNAT : port forwarding
                mem = nat.find(".//nat-item/member")
                if mem is not None:
                    ext_port  = safe_text(mem, "port") or "—"
                    int_alias = safe_text(mem, "addr-name") or "—"
                    ext_alias = safe_text(mem, "ext-addr-name") or "Firebox"
                    # Résoudre l'alias interne vers l'IP réelle
                    int_ip = resolve_wg_alias(root, int_alias)
                    nat_rules.append({
                        "name": nat_name,
                        "type": "SNAT",
                        "ext": f"{ext_alias}:{ext_port}",
                        "int": int_ip,
                    })
            elif nat_type == "3":
                nat_rules.append({
                    "name": nat_name,
                    "type": "Dynamic NAT",
                    "ext": "Firebox (WAN)",
                    "int": "Tout le trafic sortant",
                })
        data["nat"] = nat_rules

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
                name   = safe_text(itf, "descr") or itf.tag.upper()
                ip     = safe_text(itf, "ipaddr") or "DHCP"
                if_dev = safe_text(itf, "if")              # ex: em0, xn1, em1.100
                if_key = itf.tag                           # clé XML pfSense : "lan", "wan", "opt1"…
                interfaces.append({"name": name, "ip": ip, "if_dev": if_dev, "if_key": if_key})
        data["itf"] = interfaces

        policies = []
        for idx, pol in enumerate(root.findall(".//filter/rule")):
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
                "from": src, "to": dst,
                "nat": "",
                "idx": idx,
                "interface": (safe_text(pol, "interface") or "").upper(),
            })
        data["pol"] = policies

        # ── NAT pfSense ──
        nat_rules = []
        nat_node = root.find("nat")
        if nat_node is not None:
            for rule in nat_node.findall("rule"):
                descr     = safe_text(rule, "descr") or "NAT"
                proto     = (safe_text(rule, "protocol") or "tcp").upper()
                ext_port  = safe_text(rule, "destination/port") or "—"
                int_ip    = safe_text(rule, "target") or "—"
                int_port  = safe_text(rule, "local-port") or ext_port
                iface     = safe_text(rule, "interface") or "wan"
                nat_rules.append({
                    "name": descr,
                    "type": "Port Forward",
                    "ext": f"{iface.upper()}:{ext_port} ({proto})",
                    "int": f"{int_ip}:{int_port}",
                })
        data["nat"] = nat_rules

        all_found = set(["any", "wan", "lan", "wanip", "lanip"])
        for al in root.findall(".//aliases/alias/name"):
            if al.text: all_found.add(al.text)
        data["aliases"] = sorted(list(all_found))

    return data