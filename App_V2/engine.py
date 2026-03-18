import copy, re, os, shutil
import xml.etree.ElementTree as ET
from utils import safe_text, resolve_wg_alias, app_dir, get_working_xml


# AI ahh comments

# =====================================================================
# 🛠️ OUTILS DE TRADUCTION (SENS WG -> PF)
# =====================================================================

def netmask_to_cidr(netmask):
    """Convertit un masque (ex: 255.255.255.0) en CIDR (ex: 24)"""
    try:
        return sum(bin(int(x)).count('1') for x in netmask.split('.'))
    except:
        return 32

def wg_get_service_details(wg_root, svc_name):
    """Trouve le protocole et le port d'un Service WatchGuard pour pfSense"""
    for svc in wg_root.findall(".//service-list/service"):
        if safe_text(svc, "name") == svc_name:
            item = svc.find(".//service-item/member")
            if item is not None:
                proto_num = safe_text(item, "protocol")
                port = safe_text(item, "server-port")
                if proto_num == "6": proto = "tcp"
                elif proto_num == "17": proto = "udp"
                elif proto_num == "1": proto = "icmp"
                else: proto = "tcp"
                return proto, port
    return "tcp", ""

def resolve_wg_alias_deep(wg_root, alias_name):
    """Fouille récursivement pour extraire la VRAIE IP (ex: REDIRECTION.snat -> 14.0.0.1)"""
    std_map = {"Any": "any", "Any-External": "any", "Any-Trusted": "lan", "Firebox": "wanip"}
    if alias_name in std_map: return std_map[alias_name]

    # Check Alias-list
    for al in wg_root.findall(".//alias-list/alias"):
        if safe_text(al, "name") == alias_name:
            mem = al.find(".//alias-member-list/alias-member")
            if mem is not None:
                if safe_text(mem, "type") == "2": return resolve_wg_alias_deep(wg_root, safe_text(mem, "alias-name"))
                if safe_text(mem, "type") == "1":
                    addr = safe_text(mem, "address")
                    if addr and addr != "Firebox": return resolve_wg_alias_deep(wg_root, addr)

    # Check Address-group-list (Le coeur de l'IP)
    for ag in wg_root.findall(".//address-group-list/address-group"):
        if safe_text(ag, "name") == alias_name:
            mem = ag.find(".//addr-group-member/member")
            if mem is not None:
                ip = safe_text(mem, "host-ip-addr") or safe_text(mem, "ip-network-addr")
                if ip: return ip
    return alias_name

# =====================================================================
# 🛡️ TES FONCTIONS (NE PAS TOUCHER - PF -> WG)
# =====================================================================

def cidr_to_netmask(cidr):
    cidr = int(cidr)
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"

def ensure_wg_ip_alias(root, ip_str):
    ag_list = root.find("address-group-list")
    alias_list = root.find("alias-list")
    if ag_list is None or alias_list is None: return
    exists_ag = any(safe_text(ag, "name") == ip_str for ag in ag_list.findall("address-group"))
    if not exists_ag:
        ag = ET.SubElement(ag_list, "address-group")
        ET.SubElement(ag, "name").text = ip_str
        ET.SubElement(ag, "property").text = "16"
        mem = ET.SubElement(ET.SubElement(ag, "addr-group-member"), "member")
        if "/" in ip_str:
            ip_part, cidr_part = ip_str.split("/")
            ET.SubElement(mem, "type").text = "2"
            ET.SubElement(mem, "ip-network-addr").text = ip_part
            ET.SubElement(mem, "ip-mask").text = cidr_to_netmask(cidr_part)
        else:
            ET.SubElement(mem, "type").text = "1"
            ET.SubElement(mem, "host-ip-addr").text = ip_str
    exists_al = any(safe_text(al, "name") == ip_str for al in alias_list.findall("alias"))
    if not exists_al:
        new_al = ET.SubElement(alias_list, "alias")
        ET.SubElement(new_al, "name").text = ip_str
        ET.SubElement(new_al, "property").text = "16"
        al_mem = ET.SubElement(ET.SubElement(new_al, "alias-member-list"), "alias-member")
        ET.SubElement(al_mem, "type").text = "1"
        ET.SubElement(al_mem, "user").text = "Any"
        ET.SubElement(al_mem, "address").text = ip_str
        ET.SubElement(al_mem, "interface").text = "Any"

def ensure_wg_custom_service(wg_root, proto, port):
    svc_list = wg_root.find("service-list")
    if svc_list is None: svc_list = ET.SubElement(wg_root, "service-list")
    proto_upper = "TCP" if proto == "tcp" else ("UDP" if proto == "udp" else "ANY")
    svc_name = f"{proto_upper}-{port}"
    if any(safe_text(svc, "name") == svc_name for svc in svc_list.findall("service")): return svc_name
    new_svc = ET.SubElement(svc_list, "service")
    ET.SubElement(new_svc, "name").text = svc_name
    ET.SubElement(new_svc, "description").text = f"Migrated Custom Service {proto_upper} {port}"
    ET.SubElement(new_svc, "property").text = "2"
    ET.SubElement(new_svc, "proxy-type")
    svc_item = ET.SubElement(new_svc, "service-item")
    mem = ET.SubElement(svc_item, "member")
    ET.SubElement(mem, "type").text = "1"
    proto_num = "6" if proto == "tcp" else ("17" if proto == "udp" else "0")
    ET.SubElement(mem, "protocol").text = proto_num
    ET.SubElement(mem, "server-port").text = str(port)
    ET.SubElement(new_svc, "idle-timeout").text = "0"
    return svc_name

def wg_inject_nat_rule(wg_root, nat_name, target_ip, ext_port, int_port, ext_alias="Firebox"):
    ag_list = wg_root.find("address-group-list")
    if ag_list is None: ag_list = ET.SubElement(wg_root, "address-group-list")
    alias_list = wg_root.find("alias-list")
    if alias_list is None: alias_list = ET.SubElement(wg_root, "alias-list")
    nat_list = wg_root.find("nat-list")
    if nat_list is None: nat_list = ET.SubElement(wg_root, "nat-list")
    ag_name = f"{nat_name}.1.snat"; wrapper_name = f"{nat_name}.snat"
    if not any(safe_text(ag, "name") == ag_name for ag in ag_list.findall("address-group")):
        ag = ET.SubElement(ag_list, "address-group")
        ET.SubElement(ag, "name").text = ag_name
        ET.SubElement(ag, "property").text = "16"
        mem = ET.SubElement(ET.SubElement(ag, "addr-group-member"), "member")
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target_ip):
            ET.SubElement(mem, "type").text = "1"
            ET.SubElement(mem, "host-ip-addr").text = target_ip
        else:
            ET.SubElement(mem, "type").text = "2"
            ET.SubElement(mem, "alias-name").text = target_ip
    if not any(safe_text(nt, "name") == nat_name for nt in nat_list.findall("nat")):
        new_nat = ET.SubElement(nat_list, "nat")
        ET.SubElement(new_nat, "name").text = nat_name
        ET.SubElement(new_nat, "property").text = "0"
        ET.SubElement(new_nat, "type").text = "7"
        nat_item = ET.SubElement(new_nat, "nat-item")
        item_mem = ET.SubElement(nat_item, "member")
        if ext_port:
            ET.SubElement(item_mem, "addr-type").text = "4"
            ET.SubElement(item_mem, "port").text = str(ext_port)
        else:
            ET.SubElement(item_mem, "addr-type").text = "1"
        ET.SubElement(item_mem, "addr-name").text = ag_name
        ET.SubElement(item_mem, "ext-addr-name").text = ext_alias
        ET.SubElement(item_mem, "interface").text = "External"
    if not any(safe_text(al, "name") == wrapper_name for al in alias_list.findall("alias")):
        new_al = ET.SubElement(alias_list, "alias")
        ET.SubElement(new_al, "name").text = wrapper_name
        ET.SubElement(new_al, "property").text = "32"
        al_mem = ET.SubElement(ET.SubElement(new_al, "alias-member-list"), "alias-member")
        ET.SubElement(al_mem, "type").text = "1"; ET.SubElement(al_mem, "user").text = "Any"
        ET.SubElement(al_mem, "address").text = ext_alias; ET.SubElement(al_mem, "interface").text = "External"
    return wrapper_name

def wg_inject_rule(wg_root, name, action, service, src, dst, pnat=None, is_snat=False):
    abs_list = wg_root.find("abs-policy-list"); pol_list = wg_root.find("policy-list"); alias_list = wg_root.find("alias-list")
    internal_id = f"{name}-00"
    new_abs = copy.deepcopy(abs_list.find("abs-policy"))
    new_abs.find("name").text = name; new_abs.find("service").text = service
    new_abs.find("firewall").text = "Allow" if action == "allow" else "Block"
    pnat_node = new_abs.find("policy-nat")
    if pnat_node is None: pnat_node = ET.SubElement(new_abs, "policy-nat")
    pnat_node.text = pnat if pnat else ""
    for node_name in ["from-alias-list", "to-alias-list"]:
        node = new_abs.find(node_name)
        if node is not None: node.clear()
    for p_link in new_abs.findall(".//policy-list/policy"): p_link.text = internal_id
    eng_tmp = pol_list.find("policy")
    new_eng = copy.deepcopy(eng_tmp)
    new_eng.find("name").text = internal_id; new_eng.find("service").text = service
    new_eng.find("firewall").text = "1" if action == "allow" else "2"
    for node_name in ["from-alias-list", "to-alias-list"]:
        node_eng = new_eng.find(node_name)
        if node_eng is not None: node_eng.clear()
    for node in [new_abs, new_eng]:
        sp_en = node.find("source-port-enabled")
        if sp_en is not None: sp_en.text = "0"
        sp_list = node.find("source-port-list")
        if sp_list is not None: sp_list.clear()
    f_alias = f"{name}.1.from"
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$', src): ensure_wg_ip_alias(wg_root, src)
    if alias_list is not None:
        new_alias_src = ET.Element("alias")
        ET.SubElement(new_alias_src, "name").text = f_alias
        ET.SubElement(new_alias_src, "property").text = "16"
        mem = ET.SubElement(ET.SubElement(new_alias_src, "alias-member-list"), "alias-member")
        ET.SubElement(mem, "type").text = "2"; ET.SubElement(mem, "alias-name").text = src
        alias_list.append(new_alias_src)
    ET.SubElement(new_abs.find("from-alias-list"), "alias").text = f_alias
    ET.SubElement(new_eng.find("from-alias-list"), "alias").text = f_alias
    if is_snat:
        ET.SubElement(new_abs.find("to-alias-list"), "alias").text = dst
        ET.SubElement(new_eng.find("to-alias-list"), "alias").text = dst
    else:
        t_alias = f"{name}.1.to"
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$', dst): ensure_wg_ip_alias(wg_root, dst)
        if alias_list is not None:
            new_alias_dst = ET.Element("alias")
            ET.SubElement(new_alias_dst, "name").text = t_alias; ET.SubElement(new_alias_dst, "property").text = "16"
            mem_dst = ET.SubElement(ET.SubElement(new_alias_dst, "alias-member-list"), "alias-member")
            ET.SubElement(mem_dst, "type").text = "2"; ET.SubElement(mem_dst, "alias-name").text = dst
            alias_list.append(new_alias_dst)
        ET.SubElement(new_abs.find("to-alias-list"), "alias").text = t_alias
        ET.SubElement(new_eng.find("to-alias-list"), "alias").text = t_alias
    abs_list.append(new_abs); pol_list.append(new_eng)

# =====================================================================
# 🌍 INJECTEURS POUR PFSENSE (WG -> PF)
# =====================================================================

def pfsense_inject_nat_rule(pfs_root, descr, proto, ext_port, target_ip, target_port):
    nat_node = pfs_root.find("nat")
    if nat_node is None: nat_node = ET.SubElement(pfs_root, "nat")
    rule = ET.Element("rule")
    ET.SubElement(ET.SubElement(rule, "source"), "any")
    dest = ET.SubElement(rule, "destination")
    ET.SubElement(dest, "network").text = "wanip"
    if ext_port: ET.SubElement(dest, "port").text = ext_port
    ET.SubElement(rule, "protocol").text = proto
    ET.SubElement(rule, "target").text = target_ip
    if target_port: ET.SubElement(rule, "local-port").text = target_port
    ET.SubElement(rule, "interface").text = "wan"
    ET.SubElement(rule, "descr").text = descr
    nat_node.append(rule)

def pfsense_inject_rule(pfs_root, name, action, interface, proto, src, dst, dst_port):
    filter_node = pfs_root.find("filter")
    if filter_node is None: filter_node = ET.SubElement(pfs_root, "filter")
    rule = ET.Element("rule")
    ET.SubElement(rule, "type").text = "pass" if action == "allow" else "block"
    ET.SubElement(rule, "interface").text = interface
    ET.SubElement(rule, "protocol").text = proto
    for tag, val in [("source", src), ("destination", dst)]:
        node = ET.SubElement(rule, tag)
        if val == "any": ET.SubElement(node, "any")
        elif val in ["wan", "lan", "wanip", "lanip"]: ET.SubElement(node, "network").text = val
        else: ET.SubElement(node, "address").text = val
        if tag == "destination" and dst_port and proto != "icmp": ET.SubElement(node, "port").text = dst_port
    ET.SubElement(rule, "descr").text = name
    filter_node.append(rule)

# =====================================================================
# ⚙️ MOTEUR DE MIGRATION
# =====================================================================

def perform_migration(src_path, tgt_path):
    t_src = ET.parse(src_path); r_src = t_src.getroot()
    t_tgt = ET.parse(tgt_path); r_tgt = t_tgt.getroot()
    migrated_count = 0
    
    # 🔄 WATCHGUARD --> PFSENSE
    if r_src.tag == "profile" and r_tgt.tag == "pfsense":
        ignored = ["watchguard certificate portal", "unhandled internal packet", "unhandled external packet", "allow-ike-to-firebox", "outgoing"]
        for pol in r_src.findall(".//abs-policy-list/abs-policy"):
            if safe_text(pol, "property") == "32" or safe_text(pol, "enabled") == "false": continue
            name = safe_text(pol, "name")
            if name.lower() in ignored: continue
            
            act = "allow" if safe_text(pol, "firewall").lower() in ["1", "allow", "proxy"] else "block"
            proto, port = wg_get_service_details(r_src, safe_text(pol, "service"))
            pf_src = resolve_wg_alias_deep(r_src, safe_text(pol, "from-alias-list/alias"))
            pf_dst = resolve_wg_alias_deep(r_src, safe_text(pol, "to-alias-list/alias"))
            pnat = safe_text(pol, "policy-nat")
            
            if pnat:
                for nat in r_src.findall(".//nat-list/nat"):
                    if safe_text(nat, "name") == pnat:
                        mem = nat.find(".//nat-item/member")
                        if mem is not None:
                            real_ip = resolve_wg_alias_deep(r_src, safe_text(mem, "addr-name"))
                            t_port = safe_text(mem, "port") or port
                            pfsense_inject_nat_rule(r_tgt, f"NAT_{name}", proto, port, real_ip, t_port)
                            pf_dst = real_ip; port = t_port
                        break
            pfsense_inject_rule(r_tgt, f"[MIG] {name}", act, "wan" if pf_src=="any" else "lan", proto, pf_src, pf_dst, port)
            migrated_count += 1

    # 🔄 PFSENSE --> WATCHGUARD (TES RÈGLES QUI MARCHENT)
    elif r_src.tag == "pfsense" and r_tgt.tag == "profile":
        alias_map = {"lan": "Any-Trusted", "wan": "Any-External", "any": "Any", "wanip": "Firebox", "(self)": "Firebox"}
        pf_nats_map = {}
        pf_nats = r_src.find("nat")
        if pf_nats is not None:
            for pf_nat in pf_nats.findall("rule"):
                target_ip = safe_text(pf_nat, "target")
                ext_port = safe_text(pf_nat, "destination/port")
                int_port = safe_text(pf_nat, "local-port") or ext_port
                if target_ip: pf_nats_map[target_ip.lower()] = {"ext_port": ext_port, "int_port": int_port}
        
        for pf_rule in r_src.findall(".//filter/rule"):
            if safe_text(pf_rule, "descr") in ["Anti-Lockout Rule", "Default allow LAN to any rule"]: continue
            act = "allow" if safe_text(pf_rule, "type").lower() == "pass" else "block"
            proto = safe_text(pf_rule, "protocol").lower()
            dst_port = safe_text(pf_rule, "destination/port")
            dst_addr = safe_text(pf_rule, "destination/address") or safe_text(pf_rule, "destination/network") or "any"
            
            svc = ensure_wg_custom_service(r_tgt, proto, dst_port) if dst_port not in ["80","443","22","53"] else ("HTTPS" if dst_port=="443" else "HTTP")
            wg_src = alias_map.get(safe_text(pf_rule, "source/network") or "any", "Any")
            wg_dst = alias_map.get(dst_addr.lower(), dst_addr)
            
            pnat = None; is_snat = False
            if dst_addr.lower() in pf_nats_map:
                n_info = pf_nats_map[dst_addr.lower()]
                sn_name = f"SNAT_{dst_port}"
                wg_dst = wg_inject_nat_rule(r_tgt, sn_name, dst_addr, n_info["ext_port"], n_info["int_port"])
                pnat = sn_name; is_snat = True

            wg_inject_rule(r_tgt, f"MIG_{migrated_count}", act, svc, wg_src, wg_dst, pnat=pnat, is_snat=is_snat)
            migrated_count += 1

    # Fin et sauvegarde
    out_path = os.path.join(app_dir(), "firewall_modifie.xml")
    t_tgt.write(out_path, encoding="utf-8", xml_declaration=True)
    shutil.copy(out_path, os.path.join(app_dir(), "firewall.xml"))
    return migrated_count