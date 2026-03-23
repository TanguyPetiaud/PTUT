"""
engine.py — NETMORPH Migration & Injection Engine
===================================================
Ce module est le cœur de NETMORPH. Il expose trois capacités principales :

  1. Migration bidirectionnelle  : WatchGuard ↔ pfSense (perform_migration)
  2. Injection manuelle de règles: ajout d'une policy dans le XML actif (save_rule_xml)
  3. Gestion des interfaces       : ajout d'interface physique ou VLAN (save_interface_xml)

Architecture XML attendue
--------------------------
  WatchGuard : racine <profile>
    ├── abs-policy-list / abs-policy   (politique haut niveau)
    ├── policy-list    / policy         (moteur de règle interne)
    ├── nat-list       / nat            (SNAT type 7, Dynamic NAT type 3)
    ├── alias-list     / alias
    ├── address-group-list / address-group
    ├── service-list   / service
    └── interface-list / interface

  pfSense : racine <pfsense>
    ├── filter / rule   (règles de filtrage)
    ├── nat    / rule   (port-forwarding)
    ├── interfaces      (WAN, LAN, OPT…)
    └── vlans  / vlan

Règles WatchGuard — propriétés importantes
-------------------------------------------
  <property>32</property>  → règle système/cachée (invisible dans la Web UI)
  <property>0</property>   → règle utilisateur normale (visible)
  <enable>1</enable>       → obligatoire sur la policy moteur pour que WG l'accepte
  <enabled>true</enabled>  → obligatoire sur l'abs-policy pour qu'elle soit active
"""

import copy
import re
import os
import shutil
import xml.etree.ElementTree as ET

import google.generativeai as genai

from utils import safe_text, resolve_wg_alias, app_dir, get_working_xml


# =============================================================================
# CONFIGURATION IA — GEMINI SELF-HEALING
# =============================================================================
# Clé API Gemini chargée depuis la variable d'environnement GEMINI_API_KEY.
# Pour l'activer : créez un fichier .env à la racine du projet contenant :
#   GEMINI_API_KEY=votre_cle_generee_sur_aistudio.google.com
# Sans clé, l'auto-réparation XML est désactivée — l'app fonctionne normalement.
import os as _os
try:
    from dotenv import load_dotenv as _load_dotenv
    _load_dotenv()
except ImportError:
    pass  # python-dotenv optionnel

GEMINI_API_KEY = _os.environ.get("GEMINI_API_KEY", "")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    ai_model = genai.GenerativeModel("gemini-1.5-flash")
else:
    ai_model = None


# =============================================================================
# LINTERS XML — VALIDATION AVANT ÉCRITURE
# =============================================================================

def watchguard_xml_linter(xml_string: str) -> tuple[bool, str]:
    """
    Valide un XML WatchGuard Fireware 12.x avant injection.

    WatchGuard 12.x refuse la balise <source-port> et <source-port-enabled>
    dans les policies — elles ne sont tolérées que dans les services.
    Si elles sont présentes, le firewall renvoie une erreur 400 au save.

    Returns:
        (True, "OK")            si le XML est valide
        (False, message_erreur) sinon
    """
    if "<source-port>" in xml_string or "<source-port-enabled>" in xml_string:
        error_msg = (
            "Error 400: Element 'source-port' or 'source-port-enabled' is not "
            "expected in WG version 12.x. Expected is strictly ( port )."
        )
        return False, error_msg
    return True, "OK"


def pfsense_xml_linter(xml_string: str) -> tuple[bool, str]:
    """
    Valide un XML pfSense avant injection.

    Chaque balise <rule> dans pfSense doit obligatoirement contenir
    <ipprotocol> (ex: inet ou inet6). Sans elle, pfSense ignore la règle
    au boot et génère une erreur dans /var/log/filter.log.

    Returns:
        (True, "OK")            si le XML est valide
        (False, message_erreur) sinon
    """
    if "<rule>" in xml_string and "<ipprotocol>" not in xml_string:
        return False, "Validation Error: Every <rule> must contain an <ipprotocol> tag (e.g., inet or inet6)."
    return True, "OK"


def ask_ai_to_repair(xml_str: str, error_msg: str, target_os: str) -> str:
    """
    Envoie le XML en erreur à Gemini pour auto-correction.

    Si aucune clé API n'est configurée, renvoie le XML tel quel
    (la sauvegarde se fera quand même, mais sans correction).

    Args:
        xml_str    : contenu XML brut à corriger
        error_msg  : message d'erreur retourné par le linter
        target_os  : "WatchGuard" ou "pfSense" (contextualise le prompt IA)

    Returns:
        XML corrigé (str) ou xml_str inchangé si l'IA échoue
    """
    if not ai_model:
        return xml_str

    print(f"\n[NETMORPH AI] 🚨 Erreur détectée pour {target_os.upper()} : {error_msg}")
    print("[NETMORPH AI] 🤖 Envoi à Gemini pour auto-correction...")

    system_prompt = (
        f"Tu es un expert DevSecOps spécialisé en XML {target_os.upper()}. "
        "Corrige ce fichier XML pour résoudre l'erreur indiquée. "
        "Ne renvoie QUE le code XML complet et corrigé, sans balises markdown."
    )
    user_prompt = f"ERREUR: {error_msg}\n\nXML A CORRIGER:\n{xml_str}"

    try:
        response = ai_model.generate_content([system_prompt, user_prompt])
        repaired_xml = response.text.strip()

        # L'IA enveloppe parfois le XML dans des balises de code markdown — on les retire
        if repaired_xml.startswith("```xml"):
            repaired_xml = repaired_xml[6:]
        if repaired_xml.startswith("```"):
            repaired_xml = repaired_xml[3:]
        if repaired_xml.endswith("```"):
            repaired_xml = repaired_xml[:-3]

        print("[NETMORPH AI] ✅ Fichier réparé avec succès par l'IA !")
        return repaired_xml.strip()

    except Exception as exc:
        print(f"[NETMORPH AI] ❌ Échec de la réparation IA : {exc}")
        return xml_str


# =============================================================================
# UTILITAIRES RÉSEAU — CONVERSION MASQUES / CIDR
# =============================================================================

def netmask_to_cidr(netmask: str) -> int:
    """Convertit un masque décimal (255.255.255.0) en longueur de préfixe CIDR (24)."""
    try:
        return sum(bin(int(x)).count("1") for x in netmask.split("."))
    except Exception:
        return 32  # fallback : /32 (hôte)


def cidr_to_netmask(cidr) -> str:
    """Convertit un préfixe CIDR (24) en masque décimal (255.255.255.0)."""
    cidr = int(cidr)
    mask = (0xFFFFFFFF >> (32 - cidr)) << (32 - cidr)
    return (
        f"{(mask >> 24) & 0xFF}."
        f"{(mask >> 16) & 0xFF}."
        f"{(mask >> 8)  & 0xFF}."
        f"{mask         & 0xFF}"
    )


# =============================================================================
# UTILITAIRES WATCHGUARD — RÉSOLUTION D'ALIAS ET DE SERVICES
# =============================================================================

def wg_get_service_details(wg_root, svc_name: str) -> tuple[str, str]:
    """
    Lit la service-list WatchGuard et retourne (proto, port) pour un service donné.

    Le numéro de protocole WG suit la norme IANA :
      6  → TCP
      17 → UDP
      1  → ICMP

    Returns:
        ("tcp"|"udp"|"icmp", "port_number") ou ("tcp", "") si service introuvable
    """
    proto_map = {"6": "tcp", "17": "udp", "1": "icmp"}

    for svc in wg_root.findall(".//service-list/service"):
        if safe_text(svc, "name") == svc_name:
            item = svc.find(".//service-item/member")
            if item is not None:
                proto_num = safe_text(item, "protocol")
                port = safe_text(item, "server-port")
                proto = proto_map.get(proto_num, "tcp")
                return proto, port

    return "tcp", ""


def resolve_wg_alias_deep(wg_root, alias_name: str, _visited: set = None) -> str:
    """
    Résout récursivement un alias WatchGuard vers une IP ou un nom pfSense normalisé.

    Traduction des alias WG standard :
      Any            → "any"
      Any-External   → "any"
      Any-Trusted    → "lan"
      Firebox        → "wanip"

    Pour les alias custom, on suit la chaîne alias-member jusqu'à trouver une IP.
    Si l'alias est introuvable, on retourne le nom tel quel (fallback safe).

    Args:
        alias_name : nom de l'alias WatchGuard à résoudre
        _visited   : ensemble interne pour détecter les cycles (ne pas passer manuellement)

    Returns:
        IP (str), identifiant pfSense ("lan", "any"…) ou alias_name inchangé
    """
    # Initialisation du set anti-cycle (premier appel uniquement)
    if _visited is None:
        _visited = set()

    # Garde anti-cycle : si on a déjà visité ce nom, on arrête la récursion
    if alias_name in _visited:
        return alias_name
    _visited.add(alias_name)

    # Traduction des alias WG standard vers les équivalents pfSense
    std_map = {
        "Any":          "any",
        "Any-External": "any",
        "Any-Trusted":  "lan",
        "Firebox":      "wanip",
    }
    if alias_name in std_map:
        return std_map[alias_name]

    # Résolution dans alias-list (peut pointer sur un autre alias → récursif)
    for al in wg_root.findall(".//alias-list/alias"):
        if safe_text(al, "name") == alias_name:
            mem = al.find(".//alias-member-list/alias-member")
            if mem is not None:
                # type=2 → référence à un autre alias (on suit la chaîne)
                if safe_text(mem, "type") == "2":
                    return resolve_wg_alias_deep(wg_root, safe_text(mem, "alias-name"), _visited)
                # type=1 → adresse directe (peut être une IP ou un autre alias)
                if safe_text(mem, "type") == "1":
                    addr = safe_text(mem, "address")
                    if addr and addr != "Firebox":
                        return resolve_wg_alias_deep(wg_root, addr, _visited)

    # Résolution dans address-group-list
    for ag in wg_root.findall(".//address-group-list/address-group"):
        if safe_text(ag, "name") == alias_name:
            mem = ag.find(".//addr-group-member/member")
            if mem is not None:
                ip = safe_text(mem, "host-ip-addr") or safe_text(mem, "ip-network-addr")
                if ip:
                    return ip

    # Fallback : on retourne le nom brut (peut être une IP déjà résolue)
    return alias_name


# =============================================================================
# INJECTEURS WATCHGUARD — CRÉATION DE STRUCTURES XML WG
# =============================================================================

def ensure_wg_ip_alias(root, ip_str: str) -> None:
    """
    Crée un address-group et un alias WatchGuard pour une IP donnée, si absents.

    WatchGuard n'accepte pas les IPs brutes dans les from/to-alias-list.
    Chaque IP doit être enveloppée dans un address-group + alias.

    Structure créée pour une IP hôte (ex: 192.168.1.10) :
      <address-group>
        <name>192.168.1.10</name>
        <property>16</property>         ← 16 = objet réseau créé par NETMORPH
        <addr-group-member>
          <member>
            <type>1</type>              ← 1 = hôte unique
            <host-ip-addr>192.168.1.10</host-ip-addr>
          </member>
        </addr-group-member>
      </address-group>

    Pour un réseau CIDR (ex: 10.0.0.0/24), type=2 avec ip-network-addr + ip-mask.
    """
    ag_list = root.find("address-group-list")
    alias_list = root.find("alias-list")
    if ag_list is None or alias_list is None:
        return

    # -- Address-group (stocke l'IP réelle) --
    already_in_ag = any(safe_text(ag, "name") == ip_str for ag in ag_list.findall("address-group"))
    if not already_in_ag:
        ag = ET.SubElement(ag_list, "address-group")
        ET.SubElement(ag, "name").text = ip_str
        ET.SubElement(ag, "property").text = "16"
        mem = ET.SubElement(ET.SubElement(ag, "addr-group-member"), "member")
        if "/" in ip_str:
            # Réseau CIDR → on décompose IP + masque
            ip_part, cidr_part = ip_str.split("/")
            ET.SubElement(mem, "type").text = "2"
            ET.SubElement(mem, "ip-network-addr").text = ip_part
            ET.SubElement(mem, "ip-mask").text = cidr_to_netmask(cidr_part)
        else:
            # Hôte unique
            ET.SubElement(mem, "type").text = "1"
            ET.SubElement(mem, "host-ip-addr").text = ip_str

    # -- Alias (wrapper référençant l'address-group) --
    already_in_al = any(safe_text(al, "name") == ip_str for al in alias_list.findall("alias"))
    if not already_in_al:
        new_al = ET.SubElement(alias_list, "alias")
        ET.SubElement(new_al, "name").text = ip_str
        ET.SubElement(new_al, "property").text = "16"
        al_mem = ET.SubElement(ET.SubElement(new_al, "alias-member-list"), "alias-member")
        ET.SubElement(al_mem, "type").text = "1"
        ET.SubElement(al_mem, "user").text = "Any"
        ET.SubElement(al_mem, "address").text = ip_str
        ET.SubElement(al_mem, "interface").text = "Any"


def ensure_wg_custom_service(wg_root, proto: str, port) -> str:
    """
    Crée un service custom WatchGuard (ex: TCP-8443) s'il n'existe pas encore.

    Utilisé pour les ports non référencés dans la service-list native WG
    (ex: port 33891, 8443, 9090…). Le service créé est de property=2 (custom).

    Args:
        proto : "tcp", "udp" ou autre
        port  : numéro de port (str ou int)

    Returns:
        Nom du service WatchGuard (ex: "TCP-8443")
    """
    svc_list = wg_root.find("service-list")
    if svc_list is None:
        svc_list = ET.SubElement(wg_root, "service-list")

    proto_upper = "TCP" if proto == "tcp" else ("UDP" if proto == "udp" else "ANY")
    svc_name = f"{proto_upper}-{port}"

    # Ne crée pas si déjà présent
    if any(safe_text(svc, "name") == svc_name for svc in svc_list.findall("service")):
        return svc_name

    # Numéro de protocole IANA
    proto_num = "6" if proto == "tcp" else ("17" if proto == "udp" else "0")

    new_svc = ET.SubElement(svc_list, "service")
    ET.SubElement(new_svc, "name").text = svc_name
    ET.SubElement(new_svc, "description").text = f"Migrated Custom Service {proto_upper} {port}"
    ET.SubElement(new_svc, "property").text = "2"       # 2 = service custom utilisateur
    ET.SubElement(new_svc, "proxy-type")                # vide obligatoire dans le schéma WG
    svc_item = ET.SubElement(new_svc, "service-item")
    mem = ET.SubElement(svc_item, "member")
    ET.SubElement(mem, "type").text = "1"
    ET.SubElement(mem, "protocol").text = proto_num
    ET.SubElement(mem, "server-port").text = str(port)
    ET.SubElement(new_svc, "idle-timeout").text = "0"

    return svc_name


def wg_inject_nat_rule(wg_root, nat_name: str, target_ip: str, ext_port, int_port, ext_alias: str = "Firebox") -> str:
    """
    Injecte un SNAT WatchGuard (type 7 = Static NAT / Port Forwarding).

    Un SNAT WatchGuard se compose de trois objets XML liés :
      1. address-group "<nat_name>.1.snat"  → contient l'IP interne cible
      2. nat            "<nat_name>"         → règle SNAT type 7, port externe → address-group
      3. alias          "<nat_name>.snat"    → wrapper que la policy référence via <to-alias-list>

    Exemple : SNAT "SNAT_0_443" pour wan:443 → 192.168.2.1:8443
      address-group  SNAT_0_443.1.snat  { host 192.168.2.1 }
      nat            SNAT_0_443         { type=7, port=443, addr=SNAT_0_443.1.snat, ext=Firebox }
      alias          SNAT_0_443.snat    { address=Firebox, interface=External }

    Args:
        nat_name   : nom unique du SNAT (ex: "SNAT_0_443")
        target_ip  : IP interne destination (ex: "192.168.2.1")
        ext_port   : port d'écoute WAN (ex: "443")
        int_port   : port interne cible (ex: "8443"), utilisé pour le service WG
        ext_alias  : alias de l'interface externe WG (défaut: "Firebox")

    Returns:
        Nom de l'alias wrapper (ex: "SNAT_0_443.snat") à utiliser dans <to-alias-list>
    """
    # Assure la présence des listes racines
    ag_list = root_ensure(wg_root, "address-group-list")
    alias_list = root_ensure(wg_root, "alias-list")
    nat_list = root_ensure(wg_root, "nat-list")

    ag_name = f"{nat_name}.1.snat"
    wrapper_name = f"{nat_name}.snat"

    # -- 1. Address-group pour l'IP interne --
    if not any(safe_text(ag, "name") == ag_name for ag in ag_list.findall("address-group")):
        ag = ET.SubElement(ag_list, "address-group")
        ET.SubElement(ag, "name").text = ag_name
        ET.SubElement(ag, "property").text = "16"
        mem = ET.SubElement(ET.SubElement(ag, "addr-group-member"), "member")
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target_ip):
            # IP hôte directe
            ET.SubElement(mem, "type").text = "1"
            ET.SubElement(mem, "host-ip-addr").text = target_ip
        else:
            # Nom d'alias indirect
            ET.SubElement(mem, "type").text = "2"
            ET.SubElement(mem, "alias-name").text = target_ip

    # -- 2. Règle NAT SNAT type 7 --
    if not any(safe_text(nt, "name") == nat_name for nt in nat_list.findall("nat")):
        new_nat = ET.SubElement(nat_list, "nat")
        ET.SubElement(new_nat, "name").text = nat_name
        ET.SubElement(new_nat, "property").text = "0"
        ET.SubElement(new_nat, "type").text = "7"       # 7 = SNAT (Static NAT)
        nat_item = ET.SubElement(new_nat, "nat-item")
        item_mem = ET.SubElement(nat_item, "member")
        if ext_port:
            ET.SubElement(item_mem, "addr-type").text = "4"    # 4 = port-based forwarding
            ET.SubElement(item_mem, "port").text = str(ext_port)
        else:
            ET.SubElement(item_mem, "addr-type").text = "1"    # 1 = full IP (pas de port)
        ET.SubElement(item_mem, "addr-name").text = ag_name
        ET.SubElement(item_mem, "ext-addr-name").text = ext_alias
        ET.SubElement(item_mem, "interface").text = "External"

    # -- 3. Alias wrapper (référencé dans <to-alias-list> de la policy) --
    if not any(safe_text(al, "name") == wrapper_name for al in alias_list.findall("alias")):
        new_al = ET.SubElement(alias_list, "alias")
        ET.SubElement(new_al, "name").text = wrapper_name
        ET.SubElement(new_al, "property").text = "32"  # 32 = objet système lié au SNAT
        al_mem = ET.SubElement(ET.SubElement(new_al, "alias-member-list"), "alias-member")
        ET.SubElement(al_mem, "type").text = "1"
        ET.SubElement(al_mem, "user").text = "Any"
        ET.SubElement(al_mem, "address").text = ext_alias
        ET.SubElement(al_mem, "interface").text = "External"

    return wrapper_name


def root_ensure(root, tag: str):
    """Retourne le nœud <tag> de root, le crée s'il est absent."""
    node = root.find(tag)
    if node is None:
        node = ET.SubElement(root, tag)
    return node


def wg_inject_rule(wg_root, name: str, action: str, service: str, src: str, dst: str,
                   pnat: str = None, is_snat: bool = False) -> None:
    """
    Injecte une policy complète dans un XML WatchGuard.

    Une policy WatchGuard se compose de DEUX nœuds XML liés par leur nom :
      - abs-policy  (dans abs-policy-list) : définition haut niveau visible dans la Web UI
      - policy      (dans policy-list)     : règle moteur interne référencée par l'abs-policy

    Conventions de nommage :
      abs-policy : name = <name>            (ex: "MIG_0")
      policy     : name = <name>-00         (ex: "MIG_0-00")

    Propriétés critiques :
      abs-policy : <property>0</property>    + <enabled>true</enabled>
      policy     : <property>0</property>    + <enable>1</enable>
      → Sans ça, WatchGuard affiche la règle comme "system rule" (property=32) ou désactivée

    Alias créés :
      "<name>.1.from"  → encapsule src
      "<name>.1.to"    → encapsule dst (uniquement si is_snat=False)
      Si is_snat=True, dst est déjà le wrapper alias du SNAT → on l'utilise directement

    Args:
        name     : nom de la policy (ex: "MIG_0", "HTTP-In")
        action   : "allow" ou "block"
        service  : nom WG exact du service (ex: "RDP", "TCP-8443")
        src      : source — alias WG ou IP (ex: "Any-External", "192.168.1.0/24")
        dst      : destination — alias WG, IP ou wrapper SNAT
        pnat     : nom du SNAT à lier via <policy-nat> (None si pas de NAT)
        is_snat  : True si dst est un alias SNAT wrapper (on ne crée pas d'alias .to)
    """
    abs_list   = wg_root.find("abs-policy-list")
    pol_list   = wg_root.find("policy-list")
    alias_list = wg_root.find("alias-list")

    internal_id = f"{name}-00"  # ID interne de la policy moteur

    # ── abs-policy : deepcopy du premier abs-policy existant comme template ──
    new_abs = copy.deepcopy(abs_list.find("abs-policy"))

    # Forcer property=0 : le template peut avoir property=32 (règle système cachée)
    prop_abs = new_abs.find("property")
    if prop_abs is not None:
        prop_abs.text = "0"
    else:
        ET.SubElement(new_abs, "property").text = "0"

    # Forcer enabled=true pour que la règle soit active dès l'import
    enabled_node = new_abs.find("enabled")
    if enabled_node is not None:
        enabled_node.text = "true"
    else:
        ET.SubElement(new_abs, "enabled").text = "true"

    # Remplissage des champs métier
    new_abs.find("name").text = name
    new_abs.find("service").text = service
    new_abs.find("firewall").text = "Allow" if action == "allow" else "Block"

    # Lien SNAT : <policy-nat> référence le nom du SNAT dans nat-list
    pnat_node = new_abs.find("policy-nat")
    if pnat_node is None:
        pnat_node = ET.SubElement(new_abs, "policy-nat")
    pnat_node.text = pnat if pnat else ""

    # Nettoyage des alias FROM/TO hérités du template
    for node_name in ["from-alias-list", "to-alias-list"]:
        node = new_abs.find(node_name)
        if node is not None:
            node.clear()

    # Mise à jour du lien abs-policy → policy moteur
    for p_link in new_abs.findall(".//policy-list/policy"):
        p_link.text = internal_id

    # ── policy (moteur interne) : deepcopy du premier policy existant comme template ──
    new_eng = copy.deepcopy(pol_list.find("policy"))

    # Forcer property=0 et enable=1 (obligatoires pour que WG accepte la règle)
    prop_eng = new_eng.find("property")
    if prop_eng is not None:
        prop_eng.text = "0"
    else:
        ET.SubElement(new_eng, "property").text = "0"

    enable_node = new_eng.find("enable")
    if enable_node is not None:
        enable_node.text = "1"
    else:
        ET.SubElement(new_eng, "enable").text = "1"

    new_eng.find("name").text = internal_id
    new_eng.find("service").text = service
    new_eng.find("firewall").text = "1" if action == "allow" else "2"  # 1=Allow, 2=Block

    # Nettoyage des alias FROM/TO hérités du template moteur
    for node_name in ["from-alias-list", "to-alias-list"]:
        node_eng = new_eng.find(node_name)
        if node_eng is not None:
            node_eng.clear()

    # Désactivation des source-port (non supportés en WG 12.x au niveau policy)
    for node in [new_abs, new_eng]:
        sp_en = node.find("source-port-enabled")
        if sp_en is not None:
            sp_en.text = "0"
        sp_list = node.find("source-port-list")
        if sp_list is not None:
            sp_list.clear()

    # ── Alias FROM ──
    f_alias = f"{name}.1.from"
    # Si src est une IP brute, on crée l'address-group + alias correspondant
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", src):
        ensure_wg_ip_alias(wg_root, src)
    if alias_list is not None:
        new_alias_src = ET.Element("alias")
        ET.SubElement(new_alias_src, "name").text = f_alias
        ET.SubElement(new_alias_src, "property").text = "16"
        mem = ET.SubElement(ET.SubElement(new_alias_src, "alias-member-list"), "alias-member")
        ET.SubElement(mem, "type").text = "2"
        ET.SubElement(mem, "alias-name").text = src
        alias_list.append(new_alias_src)
    ET.SubElement(new_abs.find("from-alias-list"), "alias").text = f_alias
    ET.SubElement(new_eng.find("from-alias-list"), "alias").text = f_alias

    # ── Alias TO ──
    if is_snat:
        # dst est déjà le wrapper alias du SNAT (ex: "SNAT_0_443.snat")
        # On l'utilise directement, pas besoin de créer un alias intermédiaire
        ET.SubElement(new_abs.find("to-alias-list"), "alias").text = dst
        ET.SubElement(new_eng.find("to-alias-list"), "alias").text = dst
    else:
        t_alias = f"{name}.1.to"
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$", dst):
            ensure_wg_ip_alias(wg_root, dst)
        if alias_list is not None:
            new_alias_dst = ET.Element("alias")
            ET.SubElement(new_alias_dst, "name").text = t_alias
            ET.SubElement(new_alias_dst, "property").text = "16"
            mem_dst = ET.SubElement(ET.SubElement(new_alias_dst, "alias-member-list"), "alias-member")
            ET.SubElement(mem_dst, "type").text = "2"
            ET.SubElement(mem_dst, "alias-name").text = dst
            alias_list.append(new_alias_dst)
        ET.SubElement(new_abs.find("to-alias-list"), "alias").text = t_alias
        ET.SubElement(new_eng.find("to-alias-list"), "alias").text = t_alias

    # Ajout final dans les listes
    abs_list.append(new_abs)
    pol_list.append(new_eng)


# =============================================================================
# INJECTEURS PFSENSE — CRÉATION DE STRUCTURES XML pfSense
# =============================================================================

def pfsense_inject_nat_rule(pfs_root, descr: str, proto: str, ext_port, target_ip: str, target_port) -> None:
    """
    Injecte une règle de port-forwarding (NAT) dans un XML pfSense.

    Structure créée dans <nat> :
      <rule>
        <source><any/></source>
        <destination>
          <network>wanip</network>    ← trafic arrivant sur l'IP WAN
          <port>443</port>            ← port externe
        </destination>
        <protocol>tcp</protocol>
        <target>192.168.2.1</target>  ← IP interne
        <local-port>8443</local-port> ← port interne (si différent du port externe)
        <interface>wan</interface>
        <descr>NAT_REDIRECTION</descr>
      </rule>

    Args:
        descr       : description de la règle (ex: "NAT_REDIRECTION")
        proto       : "tcp" ou "udp"
        ext_port    : port d'écoute WAN (ex: "443")
        target_ip   : IP interne destination (ex: "192.168.2.1")
        target_port : port interne (ex: "8443"), peut être None si identique à ext_port
    """
    nat_node = root_ensure(pfs_root, "nat")
    rule = ET.Element("rule")

    # Source : tout trafic entrant
    ET.SubElement(ET.SubElement(rule, "source"), "any")

    # Destination : IP WAN + port externe
    dest = ET.SubElement(rule, "destination")
    ET.SubElement(dest, "network").text = "wanip"
    if ext_port:
        ET.SubElement(dest, "port").text = ext_port

    ET.SubElement(rule, "protocol").text = proto
    ET.SubElement(rule, "target").text = target_ip
    if target_port:
        ET.SubElement(rule, "local-port").text = target_port
    ET.SubElement(rule, "interface").text = "wan"
    ET.SubElement(rule, "descr").text = descr

    nat_node.append(rule)


def _pf_is_network_keyword(val: str) -> bool:
    """
    Retourne True si val est un mot-clé réseau pfSense natif (injecté dans <network>)
    plutôt qu'une adresse IP ou un alias (injectés dans <address>).

    Couvre :
      - "wan", "lan"                        → sous-réseaux WAN/LAN
      - "wanip", "lanip"                    → IPs WAN/LAN
      - "opt1", "opt2", "opt1ip", "opt2ip"  → interfaces optionnelles
      - Toute valeur courte sans point ni slash (ex: "dmz", "dmzip")
    Les IPs (192.168.x.x) et les CIDR (1.2.3.0/24) ne sont jamais des keywords.
    """
    import re
    if not val or val == "any":
        return False
    if "." in val or "/" in val:           # IP ou CIDR → pas un keyword
        return False
    # Pattern pfSense : lettres minuscules + chiffres optionnels + "ip" optionnel
    return bool(re.match(r'^[a-z][a-z0-9]*$', val))


def pfsense_inject_rule(pfs_root, name: str, action: str, interface: str,
                        proto: str, src: str, dst: str, dst_port: str,
                        src_port: str = "") -> None:
    """
    Injecte une règle de filtrage dans un XML pfSense (<filter>).

    La balise <ipprotocol>inet</ipprotocol> est OBLIGATOIRE — sans elle,
    pfSense ignore silencieusement la règle au rechargement des filtres.

    Args:
        name      : description de la règle (champ <descr>)
        action    : "allow" → <type>pass</type> | "block" → <type>block</type>
        interface : clé d'interface pfSense ("wan", "lan", "opt1"…)
        proto     : "tcp", "udp", "icmp"…
        src       : source  — "any", keyword réseau, IP, IP/CIDR ou alias
        dst       : destination — mêmes valeurs que src
        dst_port  : port de destination (str ou "")
        src_port  : port source optionnel (str, ex: "1024" ou "1024:65535")
    """
    filter_node = root_ensure(pfs_root, "filter")
    rule = ET.Element("rule")

    ET.SubElement(rule, "type").text = "pass" if action == "allow" else "block"
    ET.SubElement(rule, "interface").text = interface
    ET.SubElement(rule, "ipprotocol").text = "inet"   # obligatoire pfSense
    ET.SubElement(rule, "protocol").text = proto

    # Encodage source et destination
    # Ordre des ports : source → src_port, destination → dst_port
    for tag, val, port in [("source", src, src_port), ("destination", dst, dst_port)]:
        node = ET.SubElement(rule, tag)
        if val == "any":
            ET.SubElement(node, "any")
        elif _pf_is_network_keyword(val):
            # Keyword pfSense natif : lan, wan, wanip, lanip, opt1, opt1ip…
            ET.SubElement(node, "network").text = val
        else:
            # IP, IP/CIDR ou nom d'alias
            ET.SubElement(node, "address").text = val
        # Port (non vide et pas ICMP)
        if port and proto != "icmp":
            ET.SubElement(node, "port").text = port

    ET.SubElement(rule, "descr").text = name
    filter_node.append(rule)


# =============================================================================
# TABLE DE CORRESPONDANCE SERVICES — PARTAGÉE PAR SAVE_RULE ET MIGRATION
# =============================================================================
# Format : "nom_UI" → ("nom_WG_exact", "proto_pfSense", "port_pfSense")
# Le nom WG exact doit correspondre exactement à un service dans la service-list WG.

SERVICE_TABLE = {
    # ── Web / Transfert ──────────────────────────────────────────────────────
    "HTTP":               ("HTTP",               "tcp",  "80"),
    "HTTPS":              ("HTTPS",              "tcp",  "443"),
    "FTP":                ("FTP",                "tcp",  "21"),
    "TFTP":               ("TFTP",               "udp",  "69"),
    "CVSup":              ("CVSup",              "tcp",  "5999"),
    # ── DNS ──────────────────────────────────────────────────────────────────
    "DNS":                ("DNS",                "udp",  "53"),
    "DNS over TLS":       ("DNS over TLS",       "tcp",  "853"),
    # ── Messagerie ───────────────────────────────────────────────────────────
    "SMTP":               ("SMTP",               "tcp",  "25"),
    "SMTP/S":             ("SMTP/S",             "tcp",  "465"),
    "SUBMISSION":         ("SUBMISSION",         "tcp",  "587"),
    "POP3":               ("POP3",               "tcp",  "110"),
    "POP3/S":             ("POP3/S",             "tcp",  "995"),
    "IMAP":               ("IMAP",               "tcp",  "143"),
    "IMAP/S":             ("IMAP/S",             "tcp",  "993"),
    "NNTP":               ("NNTP",               "tcp",  "119"),
    "MSN":                ("MSN",                "tcp",  "1863"),
    "ICQ":                ("ICQ",                "tcp",  "5190"),
    # ── Accès distant ────────────────────────────────────────────────────────
    "SSH":                ("SSH",                "tcp",  "22"),
    "Telnet":             ("Telnet",             "tcp",  "23"),
    "RDP":                ("RDP",                "tcp",  "3389"),
    "MS RDP":             ("MS RDP",             "tcp",  "3389"),
    "PPTP":               ("PPTP",               "tcp",  "1723"),
    # ── Annuaire / Auth ──────────────────────────────────────────────────────
    "LDAP":               ("LDAP",               "tcp",  "389"),
    "LDAP-SSL":           ("LDAP-SSL",           "tcp",  "636"),
    "LDAP/S":             ("LDAP/S",             "tcp",  "636"),
    "RADIUS":             ("RADIUS",             "udp",  "1812"),
    "RADIUS accounting":  ("RADIUS accounting",  "udp",  "1813"),
    "IDENT/AUTH":         ("IDENT/AUTH",         "tcp",  "113"),
    # ── Réseau / Infrastructure ───────────────────────────────────────────────
    "Ping":               ("Ping",               "icmp", ""),
    "SNMP":               ("SNMP",               "udp",  "161"),
    "SNMP-Trap":          ("SNMP-Trap",          "udp",  "162"),
    "NTP":                ("NTP",                "udp",  "123"),
    "Syslog":             ("Syslog",             "udp",  "514"),
    "BGP":                ("BGP",                "tcp",  "179"),
    "GRE":                ("GRE",                "gre",  ""),
    "STUN":               ("STUN",               "udp",  "3478"),
    "Teredo":             ("Teredo",             "udp",  "3544"),
    # ── Microsoft / Windows ───────────────────────────────────────────────────
    "SMB":                ("SMB",                "tcp",  "445"),
    "MS DS":              ("MS DS",              "tcp",  "445"),
    "MS WINS":            ("MS WINS",            "tcp",  "1512"),
    "NetBIOS-NS":         ("NetBIOS-NS",         "udp",  "137"),
    "NetBIOS-DGM":        ("NetBIOS-DGM",        "udp",  "138"),
    "NetBIOS-SSN":        ("NetBIOS-SSN",        "tcp",  "139"),
    "MS-SQL-Server":      ("MS-SQL-Server",      "tcp",  "1433"),
    # ── Base de données ───────────────────────────────────────────────────────
    "SQL*Net":            ("SQL*Net",            "tcp",  "1521"),
    "HBCI":               ("HBCI",               "tcp",  "3000"),
    # ── VoIP / Multimédia ────────────────────────────────────────────────────
    "SIP":                ("SIP",                "udp",  "5060"),
    "RTP":                ("RTP",                "udp",  "5004"),
    "MMS/TCP":            ("MMS/TCP",            "tcp",  "1755"),
    "MMS/UDP":            ("MMS/UDP",            "udp",  "7000"),
    # ── VPN ──────────────────────────────────────────────────────────────────
    "OpenVPN":            ("OpenVPN",            "udp",  "1194"),
    "IPsec NAT-T":        ("IPsec NAT-T",        "udp",  "4500"),
    "ISAKMP":             ("ISAKMP",             "udp",  "500"),
    "L2TP":               ("L2TP",               "udp",  "1701"),
}


# =============================================================================
# SAVE_RULE_XML — AJOUT MANUEL D'UNE RÈGLE DEPUIS L'UI
# =============================================================================

def save_rule_xml(data: dict) -> None:
    """
    Ajoute une règle de firewall dans le XML actif (WatchGuard ou pfSense).

    Appelé depuis l'interface NETMORPH quand l'utilisateur crée une règle manuellement.
    Détecte automatiquement le type de firewall via la balise racine XML.

    Args:
        data : dict avec les clés :
               "name"    (str)  — nom de la règle, obligatoire
               "action"  (str)  — "allow" ou "block"
               "service" (str)  — nom du service (ex: "HTTP") ou numéro de port
               "from"    (str)  — source (alias WG ou réseau pfSense)
               "to"      (str)  — destination

    Raises:
        FileNotFoundError : aucun XML chargé
        ValueError        : champs requis manquants ou format XML inconnu
    """
    xml_path = get_working_xml()
    if not xml_path:
        raise FileNotFoundError("Aucun fichier XML chargé. Importez d'abord une configuration.")

    tree = ET.parse(xml_path)
    root = tree.getroot()

    name        = data.get("name", "").strip()
    action      = data.get("action", "allow")
    service_raw = data.get("service", "").strip()
    src         = data.get("from", "Any")
    dst         = data.get("to", "Any")
    # Interface choisie par l'utilisateur dans le formulaire :
    #   WatchGuard : nom d'interface (ex: "Trusted", "DMZ") — info seulement, la règle WG utilise src/dst aliases
    #   pfSense    : clé XML de l'interface (ex: "lan", "wan", "opt1") — injectée dans <interface>
    interface_raw = data.get("interface", "").strip()

    if not name or not service_raw:
        raise ValueError("Nom et Service sont requis.")

    # ── WatchGuard ──
    if root.tag == "profile":
        if service_raw in SERVICE_TABLE:
            # Nom exact WatchGuard — garanti présent dans la service-list native
            svc_name = SERVICE_TABLE[service_raw][0]
        elif service_raw.isdigit():
            # Port numérique → crée un service custom TCP-<port> si absent
            svc_name = ensure_wg_custom_service(root, "tcp", service_raw)
        else:
            # Nom libre (service custom déjà existant dans le XML)
            svc_name = service_raw

        # Pour WatchGuard l'interface sélectionnée est déjà reflétée dans les aliases
        # from/to (l'UI auto-remplit la Source via onInterfaceChange). La règle WG
        # n'a pas de champ "interface" explicite — elle repose uniquement sur src/dst.
        wg_inject_rule(root, name, action, svc_name, src, dst)

    # ── pfSense ──
    elif root.tag == "pfsense":
        if service_raw in SERVICE_TABLE:
            _, proto, port = SERVICE_TABLE[service_raw]
        elif service_raw.isdigit():
            proto, port = "tcp", service_raw
        else:
            proto, port = "tcp", ""

        # Interface : priorité à la valeur UI, sinon heuristique sur src
        if interface_raw:
            interface = interface_raw
        else:
            interface = "lan" if src in ("Any-Trusted", "lan") else "wan"

        # ── Nouveaux params pfSense-style (depuis le formulaire redessiné) ──
        src_type = data.get("src_type", "").strip()
        src_addr = data.get("src_addr", "").strip()
        src_mask = data.get("src_mask", "").strip()
        src_port = data.get("src_port", "").strip()
        dst_type = data.get("dst_type", "").strip()
        dst_addr = data.get("dst_addr", "").strip()
        dst_mask = data.get("dst_mask", "").strip()

        # ── Port de destination : priorité au range From/To explicite ──────────
        # L'UI pfSense envoie dst_port_from et dst_port_to (valeurs numériques).
        # Si les deux sont identiques ou si seul "from" est renseigné → port unique.
        # Si from ≠ to → range "from:to" (ex: "1024:65535").
        # Fallback : port issu du SERVICE_TABLE (ex: "80" pour HTTP).
        dst_port_from = data.get("dst_port_from", "").strip()
        dst_port_to   = data.get("dst_port_to",   "").strip()
        if dst_port_from:
            if dst_port_to and dst_port_to != dst_port_from:
                port = f"{dst_port_from}:{dst_port_to}"
            else:
                port = dst_port_from
        # Si dst_port_from est vide, on garde le port issu du service (déjà dans `port`)

        if src_type:
            # Mode pfSense étendu : construire src/dst à partir des nouveaux params
            if src_type == "any":
                resolved_src = "any"
            elif src_type == "address":
                resolved_src = f"{src_addr}/{src_mask}" if src_mask else src_addr
            else:
                resolved_src = src_type   # "wanip", "lan", "opt1ip"…

            if dst_type == "any":
                resolved_dst = "any"
            elif dst_type == "address":
                resolved_dst = f"{dst_addr}/{dst_mask}" if dst_mask else dst_addr
            else:
                resolved_dst = dst_type

            pfsense_inject_rule(root, name, action, interface, proto,
                                resolved_src, resolved_dst, port, src_port)
        else:
            # Rétrocompatibilité : migration ou ancienne UI (from/to directs)
            pfsense_inject_rule(root, name, action, interface, proto, src, dst, port)

    else:
        raise ValueError("Format XML non reconnu.")

    # Sauvegarde dans les deux fichiers (firewall.xml = actif, firewall_modifie.xml = export)
    out_path = os.path.join(app_dir(), "firewall.xml")
    tree.write(out_path, encoding="unicode", xml_declaration=False)
    mod_path = os.path.join(app_dir(), "firewall_modifie.xml")
    if os.path.exists(mod_path):
        tree.write(mod_path, encoding="unicode", xml_declaration=False)


# =============================================================================
# SAVE_INTERFACE_XML — AJOUT D'UNE INTERFACE RÉSEAU DEPUIS L'UI
# =============================================================================

def save_interface_xml(data: dict) -> None:
    """
    Ajoute une interface réseau (physique ou VLAN) dans le XML actif.

    Compatible WatchGuard et pfSense. Détecte le format via la balise racine.

    Args:
        data : dict avec les clés :
               "name"     (str) — nom de l'interface (ex: "DMZ")
               "ip"       (str) — IP avec masque CIDR optionnel (ex: "10.0.50.1/24")
               "type"     (str) — "physical" ou "vlan"
               "vlan_id"  (str) — ID VLAN numérique (uniquement si type="vlan")
               "parent"   (str) — interface parente (ex: "eth1") pour les VLANs
               "port_num" (str) — numéro de port physique (ex: "2") pour type="physical"

    Raises:
        FileNotFoundError : aucun XML chargé
        ValueError        : validation échouée (doublon, champ manquant…)
    """
    xml_path = get_working_xml()
    if not xml_path:
        raise FileNotFoundError("Aucun fichier XML chargé. Importez d'abord une configuration.")

    tree = ET.parse(xml_path)
    root = tree.getroot()

    name     = data.get("name", "").strip()
    ip_raw   = data.get("ip", "").strip()
    itf_type = data.get("type", "physical")
    vlan_id  = data.get("vlan_id", "").strip()
    parent   = data.get("parent", "").strip()
    port_num = data.get("port_num", "").strip()

    if not name or not ip_raw:
        raise ValueError("Nom et IP sont requis.")

    # Validation des champs selon le type d'interface
    if itf_type == "vlan":
        if not vlan_id or not vlan_id.isdigit():
            raise ValueError("VLAN ID invalide (nombre entier requis).")
        if not parent:
            raise ValueError("Interface parente requise pour un VLAN.")
    else:
        if not port_num or not port_num.isdigit():
            raise ValueError(
                "Numéro de port physique invalide. Entrez 0, 1, 2… "
                "selon les ports disponibles sur votre appareil."
            )

    # Décompose IP/CIDR → adresse + masque
    if "/" in ip_raw:
        ip_addr, cidr = ip_raw.split("/", 1)
        netmask = cidr_to_netmask(cidr)
        subnet  = cidr.strip()
    else:
        ip_addr = ip_raw
        netmask = "255.255.255.0"
        subnet  = "24"

    # ─────────────────────────────────────────────────────────────────────
    # WATCHGUARD
    # ─────────────────────────────────────────────────────────────────────
    if root.tag == "profile":
        itf_list = root.find("interface-list")
        if itf_list is None:
            raise ValueError("Structure XML WatchGuard invalide : interface-list introuvable.")

        # Détection des doublons de nom et de port physique
        taken_ports = set()
        for itf in itf_list.findall("interface"):
            if safe_text(itf, "name") == name:
                raise ValueError(f"L'interface '{name}' existe déjà.")
            phys = itf.find(".//physical-if")
            if phys is not None:
                taken_ports.add(phys.findtext("if-num", ""))

        if itf_type == "physical" and port_num in taken_ports:
            raise ValueError(
                f"Le port physique {port_num} (eth{port_num}) est déjà utilisé par une autre interface."
            )

        if_num = int(port_num) if itf_type == "physical" else 0

        # Structure commune à toutes les interfaces WG
        new_itf = ET.SubElement(itf_list, "interface")
        ET.SubElement(new_itf, "name").text = name
        ET.SubElement(new_itf, "description")
        ET.SubElement(new_itf, "property").text = "0"
        ET.SubElement(new_itf, "netflow").text = "0"
        ET.SubElement(new_itf, "garp").text = "1"
        mc = ET.SubElement(new_itf, "multicast-if")
        ET.SubElement(mc, "enabled").text = "0"
        ET.SubElement(mc, "rp-candidate").text = "0"
        item_list = ET.SubElement(new_itf, "if-item-list")
        item = ET.SubElement(item_list, "item")

        if itf_type == "vlan":
            # ── Interface VLAN WatchGuard ──
            ET.SubElement(item, "item-type").text = "2"  # 2 = VLAN
            vif = ET.SubElement(item, "vlan-if")
            ET.SubElement(vif, "vlan-id").text = vlan_id
            ET.SubElement(vif, "if-num").text = vlan_id
            ET.SubElement(vif, "if-dev-name").text = f"vlan{vlan_id}"
            ET.SubElement(vif, "vif-property").text = "1"
            ET.SubElement(vif, "intra-vlan-inspection").text = "1"
            # Extrait le numéro du parent (ex: "eth1" → "1")
            parent_num = re.sub(r"\D", "", parent) or "1"
            mem_list = ET.SubElement(vif, "member-list")
            mem = ET.SubElement(mem_list, "member")
            ET.SubElement(mem, "if-num").text = parent_num
            ET.SubElement(mem, "if-dev-name").text = parent
            ET.SubElement(mem, "pvid-enabled").text = "0"
            ET.SubElement(vif, "ip").text = ip_addr
            ET.SubElement(vif, "netmask").text = netmask
            dhcp = ET.SubElement(vif, "dhcp-server")
            ET.SubElement(dhcp, "server-type").text = "0"
            ET.SubElement(vif, "secondary-ip-list")
            ET.SubElement(vif, "ip-node-type").text = "IP4_ONLY"
            ET.SubElement(vif, "pcp-enabled").text = "0"
        else:
            # ── Interface physique WatchGuard ──
            ET.SubElement(item, "item-type").text = "1"  # 1 = physique
            phys = ET.SubElement(item, "physical-if")
            ET.SubElement(phys, "if-num").text = str(if_num)
            ET.SubElement(phys, "if-dev-name").text = f"eth{if_num}"
            ET.SubElement(phys, "enabled").text = "1"
            ET.SubElement(phys, "if-property").text = "5"
            ET.SubElement(phys, "ip").text = ip_addr
            ET.SubElement(phys, "netmask").text = netmask
            ET.SubElement(phys, "mtu").text = "1500"
            ET.SubElement(phys, "auto-negotiation").text = "1"
            ET.SubElement(phys, "link-speed").text = "100"
            ET.SubElement(phys, "mac-address-enable").text = "0"
            ET.SubElement(phys, "mac-address")
            ET.SubElement(phys, "full-duplex").text = "1"
            ET.SubElement(phys, "default-gateway")
            ET.SubElement(phys, "secondary-ip-list")
            ET.SubElement(phys, "anti-spoof").text = "2"
            ET.SubElement(phys, "anti-scan").text = "0"
            ET.SubElement(phys, "block-notification").text = "0"
            ET.SubElement(phys, "dos-prevention").text = "1"
            ET.SubElement(phys, "intra-inspection").text = "0"

    # ─────────────────────────────────────────────────────────────────────
    # PFSENSE
    # ─────────────────────────────────────────────────────────────────────
    elif root.tag == "pfsense":
        itfs_node = root_ensure(root, "interfaces")

        # pfSense utilise le nom en minuscules sans caractères spéciaux comme tag XML
        tag_name = re.sub(r"[^a-z0-9]", "", name.lower())
        if not tag_name:
            raise ValueError("Nom d'interface invalide pour pfSense.")
        if itfs_node.find(tag_name) is not None:
            raise ValueError(f"L'interface '{name}' existe déjà.")

        if itf_type == "vlan":
            # ── VLAN pfSense : entrée dans <vlans> + entrée dans <interfaces> ──
            vlans_node = root_ensure(root, "vlans")
            vlan_if_name = f"{parent}.{vlan_id}"

            # Vérification doublon VLAN
            for vl in vlans_node.findall("vlan"):
                if safe_text(vl, "vlanif") == vlan_if_name:
                    raise ValueError(f"Le VLAN {vlan_id} sur {parent} existe déjà ({vlan_if_name}).")

            # Déclaration du VLAN dans <vlans>
            vlan_entry = ET.SubElement(vlans_node, "vlan")
            ET.SubElement(vlan_entry, "if").text = parent
            ET.SubElement(vlan_entry, "tag").text = vlan_id
            ET.SubElement(vlan_entry, "pcp").text = "0"
            ET.SubElement(vlan_entry, "descr").text = name.upper()
            ET.SubElement(vlan_entry, "vlanif").text = vlan_if_name

            # Interface logique pointant sur le VLAN dans <interfaces>
            new_itf = ET.SubElement(itfs_node, tag_name)
            ET.SubElement(new_itf, "descr").text = name.upper()
            ET.SubElement(new_itf, "if").text = vlan_if_name
            ET.SubElement(new_itf, "ipaddr").text = ip_addr
            ET.SubElement(new_itf, "subnet").text = subnet
            ET.SubElement(new_itf, "enable")

        else:
            # ── Interface physique pfSense ──
            # L'index détermine le nom de l'interface noyau (em0, em1, em2…)
            if_index = len(list(itfs_node))
            new_itf = ET.SubElement(itfs_node, tag_name)
            ET.SubElement(new_itf, "descr").text = name.upper()
            ET.SubElement(new_itf, "if").text = f"em{if_index}"
            ET.SubElement(new_itf, "ipaddr").text = ip_addr
            ET.SubElement(new_itf, "subnet").text = subnet
            ET.SubElement(new_itf, "enable")

    else:
        raise ValueError("Format XML non reconnu.")

    # Sauvegarde dans les deux fichiers
    out_path = os.path.join(app_dir(), "firewall.xml")
    tree.write(out_path, encoding="unicode", xml_declaration=False)
    mod_path = os.path.join(app_dir(), "firewall_modifie.xml")
    if os.path.exists(mod_path):
        tree.write(mod_path, encoding="unicode", xml_declaration=False)


# =============================================================================
# MOTEUR DE MIGRATION PRINCIPAL — WatchGuard ↔ pfSense
# =============================================================================

def _netmask_to_cidr(netmask: str) -> int:
    """
    Convertit un masque de sous-réseau pointé (ex: "255.255.255.0") en bits CIDR (ex: 24).
    Utilisé pour la migration WatchGuard → pfSense (WG stocke le masque en notation décimale,
    pfSense utilise le préfixe CIDR dans la balise <subnet>).

    Fallback : 24 si le masque est invalide ou absent.
    """
    try:
        return sum(bin(int(p)).count("1") for p in netmask.split("."))
    except Exception:
        return 24


def perform_migration(src_path: str, tgt_path: str) -> dict:
    """
    Migre les règles d'un firewall source vers un firewall cible.

    Directions supportées :
      - WatchGuard → pfSense  (r_src.tag == "profile"  → r_tgt.tag == "pfsense")
      - pfSense → WatchGuard  (r_src.tag == "pfsense"  → r_tgt.tag == "profile")

    Le résultat est écrit dans firewall_modifie.xml (fichier export)
    et copié dans firewall.xml (fichier actif).

    Returns:
        dict avec clés : count, rules, skipped, aliases, vlans, warnings

    Raises:
        ValueError : combinaison source/cible invalide
    """
    t_src = ET.parse(src_path)
    r_src = t_src.getroot()
    t_tgt = ET.parse(tgt_path)
    r_tgt = t_tgt.getroot()

    migrated_count = 0
    report = {
        "count":    0,
        "rules":    [],   # noms des règles migrées
        "skipped":  [],   # règles ignorées
        "aliases":  [],   # alias créés
        "vlans":    [],   # VLANs migrés
        "warnings": [],   # avertissements
    }

    # =========================================================================
    # DIRECTION : WATCHGUARD → PFSENSE
    # =========================================================================
    if r_src.tag == "profile" and r_tgt.tag == "pfsense":

        # ── Filtres d'exclusion WatchGuard ──
        # Ces règles sont internes à WatchGuard et n'ont aucun équivalent dans pfSense.
        # Les migrer casserait la configuration cible ou créerait du bruit inutile.

        # Noms exacts à ignorer (case-insensitive)
        WG_IGNORED_EXACT = {
            "watchguard certificate portal",
            "watchguard",               # management WatchGuard (port 4105)
            "unhandled internal packet",
            "unhandled external packet",
            "allow-ike-to-firebox",
            "outgoing",
            "wg-firebox-mgmt",
            "wg-logging",
            "wg-mgmt-server",
            "deny-all",
            "blocked sites exception",
            "blocked ports exception",
        }
        # Préfixes à ignorer : toute règle commençant par ces chaînes est une règle système WG
        WG_IGNORED_PREFIXES = (
            "watchguard",   # ex: "WatchGuard Authentication", "WatchGuard Web UI"
            "wg-",          # ex: "WG-IKE", "WG-BOVPN-Allow"
            "sslvpn-",      # tunnels SSL VPN internes
            "bovpn-",       # Branch Office VPN system rules
        )
        # Suffixes à ignorer : politiques proxy WG sans équivalent pfSense
        WG_IGNORED_SUFFIXES = (
            "-proxy",       # ex: "HTTP-proxy", "FTP-proxy", "HTTPS-proxy"
            "-proxy0",      # variante interne du proxy
        )

        # Ports protégés côté pfSense : on n'injecte JAMAIS de NAT sur ces ports
        # pour ne pas écraser l'accès admin pfSense (interface web, SSH, XMLRPC sync)
        PFSENSE_PROTECTED_PORTS = {"80", "443", "22", "4989", "8080", "8443"}

        # ── Étape 0 : Migration des interfaces et VLANs WatchGuard → pfSense ───
        # On traite les interfaces EN PREMIER pour que les règles puissent ensuite
        # référencer les bons noms de zones (wan, lan, opt1…) lors de l'injection.
        #
        # Mapping WatchGuard → pfSense :
        #   • Interface "External"  → wan  (WAN physique)
        #   • Interface "Trusted"   → lan  (LAN physique)
        #   • Autres physiques      → opt1, opt2… (interfaces optionnelles)
        #   • VLANs (item-type=2)   → entrée dans <vlans> + interface optionnelle optN
        #
        # On ne recrée pas les interfaces déjà présentes dans le template cible.

        itfs_pf   = root_ensure(r_tgt, "interfaces")
        vlans_pf  = root_ensure(r_tgt, "vlans")

        # Interfaces déjà présentes dans le template (ex: wan, lan du Template_pfsense.xml)
        existing_pf_tags = {child.tag for child in itfs_pf}

        # Prochain indice opt libre (évite les collisions avec le template)
        opt_index = 1
        for child in itfs_pf:
            m = re.match(r'^opt(\d+)$', child.tag)
            if m:
                opt_index = max(opt_index, int(m.group(1)) + 1)

        # Correspondance WG if-dev-name (ex: "eth1") → pfSense em-name (ex: "em1" ou "xn1"…)
        # Nécessaire pour que les VLANs puissent référencer la bonne interface parente.
        wg_eth_to_pf_em = {}

        # Lire les noms de périphériques réels depuis le template pfSense cible
        # (ex: "xn0" pour wan, "xn1" pour lan sur Xen ; "em0"/"em1" sur VMware/bare-metal)
        pf_wan_dev = safe_text(itfs_pf.find("wan"), "if") or ""
        pf_lan_dev = safe_text(itfs_pf.find("lan"), "if") or ""
        print(f"[NETMORPH] Template pfSense : wan={pf_wan_dev!r}  lan={pf_lan_dev!r}")

        # Passe 1 : interfaces physiques (on les traite avant les VLANs pour remplir wg_eth_to_pf_em)
        for itf in r_src.findall(".//interface-list/interface"):
            wg_name = safe_text(itf, "name") or ""
            # Ignorer les zones système/virtuelles WatchGuard :
            # - Any*, Firebox, Any-BOVPN : pseudo-zones internes WG
            # - Optional-X : zones de politique sans IP propre, déjà gérées par le template pfSense
            if wg_name in ("Any", "Firebox", "Any-External", "Any-Trusted",
                           "Any-Optional", "Any-BOVPN"):
                continue
            if re.match(r"^Optional(-\d+)?$", wg_name, re.IGNORECASE):
                print(f"[NETMORPH] ⏭ Interface WG ignorée (zone virtuelle) : {wg_name}")
                continue

            item = itf.find(".//if-item-list/item")
            if item is None or safe_text(item, "item-type") != "1":
                continue  # pas physique → traité en passe 2

            phys = item.find("physical-if")
            if phys is None:
                continue

            ip_wg      = safe_text(phys, "ip")     or ""
            netmask_wg = safe_text(phys, "netmask") or "255.255.255.0"
            if_dev     = safe_text(phys, "if-dev-name") or f"eth{safe_text(phys, 'if-num') or '0'}"

            # Utiliser les noms réels du template pfSense pour wan/lan,
            # et déduire les autres par incrément du dernier numéro trouvé.
            eth_num = re.sub(r"\D", "", if_dev) or "0"
            if wg_name == "External" and pf_wan_dev:
                pf_dev = pf_wan_dev
            elif wg_name == "Trusted" and pf_lan_dev:
                pf_dev = pf_lan_dev
            elif pf_lan_dev:
                # Déduire le préfixe (ex: "xn", "em", "vtnet") depuis l'interface lan
                pf_prefix = re.sub(r"\d+$", "", pf_lan_dev)  # "xn1" → "xn"
                pf_dev = f"{pf_prefix}{eth_num}"
            else:
                pf_dev = f"em{eth_num}"
            wg_eth_to_pf_em[if_dev] = pf_dev

            # Déterminer le tag pfSense cible
            if wg_name == "External":
                pf_tag = "wan"
            elif wg_name == "Trusted":
                pf_tag = "lan"
            else:
                pf_tag = f"opt{opt_index}"
                opt_index += 1

            if pf_tag in existing_pf_tags:
                # L'interface existe déjà dans le template pfSense → on ne la modifie pas.
                # Le template est la référence : ses IPs, son périphérique et sa config
                # doivent rester intacts. On renseigne juste wg_eth_to_pf_em pour les VLANs.
                print(f"[NETMORPH] ⏭ Interface déjà dans le template, ignorée : {wg_name} → {pf_tag}")
                continue

            # Créer l'interface physique pfSense
            cidr = _netmask_to_cidr(netmask_wg)
            new_if = ET.SubElement(itfs_pf, pf_tag)
            ET.SubElement(new_if, "descr").text  = wg_name.upper()
            ET.SubElement(new_if, "if").text      = pf_dev
            if ip_wg and ip_wg not in ("DHCP", ""):
                ET.SubElement(new_if, "ipaddr").text  = ip_wg
                ET.SubElement(new_if, "subnet").text  = str(cidr)
            else:
                ET.SubElement(new_if, "ipaddr").text  = "dhcp"
            ET.SubElement(new_if, "enable")
            existing_pf_tags.add(pf_tag)
            print(f"[NETMORPH] ✅ Interface physique migrée : {wg_name} → pfSense {pf_tag} ({pf_dev})")

        # Passe 2 : interfaces VLAN (item-type=2)
        for itf in r_src.findall(".//interface-list/interface"):
            wg_name = safe_text(itf, "name") or ""
            if wg_name in ("Any", "Firebox", "Any-External", "Any-Trusted",
                           "Any-Optional", "Any-BOVPN"):
                continue

            item = itf.find(".//if-item-list/item")
            if item is None or safe_text(item, "item-type") != "2":
                continue  # pas VLAN → déjà traité en passe 1

            vif = item.find("vlan-if")
            if vif is None:
                continue

            vlan_id    = safe_text(vif, "vlan-id") or ""
            ip_wg      = safe_text(vif, "ip")      or ""
            netmask_wg = safe_text(vif, "netmask")  or "255.255.255.0"

            if not vlan_id:
                print(f"[NETMORPH] ⚠ VLAN '{wg_name}' ignoré : vlan-id manquant")
                continue

            # Interface physique parente du VLAN
            parent_wg_dev = safe_text(vif, "member-list/member/if-dev-name") or "eth1"
            if parent_wg_dev in wg_eth_to_pf_em:
                pf_parent = wg_eth_to_pf_em[parent_wg_dev]
            else:
                # Fallback : déduire le préfixe depuis l'interface lan du template
                num = re.sub(r"[^0-9]", "", parent_wg_dev) or "1"
                if pf_lan_dev:
                    pf_prefix = re.sub(r"\d+$", "", pf_lan_dev)  # "xn1" → "xn"
                    pf_parent = f"{pf_prefix}{num}"
                else:
                    pf_parent = f"em{num}"
            vlan_if_name = f"{pf_parent}.{vlan_id}"

            # Doublon ?
            if any(safe_text(vl, "vlanif") == vlan_if_name
                   for vl in vlans_pf.findall("vlan")):
                print(f"[NETMORPH] ℹ VLAN {vlan_id} sur {pf_parent} déjà présent — ignoré")
                continue

            # Créer l'entrée VLAN dans <vlans>
            vlan_entry = ET.SubElement(vlans_pf, "vlan")
            ET.SubElement(vlan_entry, "if").text     = pf_parent
            ET.SubElement(vlan_entry, "tag").text    = vlan_id
            ET.SubElement(vlan_entry, "pcp").text    = "0"
            ET.SubElement(vlan_entry, "descr").text  = wg_name.upper()
            ET.SubElement(vlan_entry, "vlanif").text = vlan_if_name

            # Créer l'interface logique dans <interfaces>
            pf_tag = f"opt{opt_index}"
            opt_index += 1
            cidr   = _netmask_to_cidr(netmask_wg)

            new_if = ET.SubElement(itfs_pf, pf_tag)
            ET.SubElement(new_if, "descr").text  = wg_name.upper()
            ET.SubElement(new_if, "if").text      = vlan_if_name
            if ip_wg and ip_wg not in ("DHCP", ""):
                ET.SubElement(new_if, "ipaddr").text  = ip_wg
                ET.SubElement(new_if, "subnet").text  = str(cidr)
            ET.SubElement(new_if, "enable")
            existing_pf_tags.add(pf_tag)
            report["vlans"].append(f"{wg_name} → {pf_tag} ({vlan_if_name})")
            print(f"[NETMORPH] ✅ VLAN migré : {wg_name} (ID {vlan_id}, parent {pf_parent}) → {pf_tag} ({vlan_if_name})")

        # ── Étape 0b : Recenser les interfaces VLAN trusted pour la philosophie Any-Trusted ──
        # En WatchGuard, "Any-Trusted" signifie LAN + tous les VLANs côté trusted.
        # On collecte ici les pf_tags (optN) des VLANs dont le parent physique est le LAN
        # (pf_lan_dev = "xn1" ou équivalent). Ces interfaces recevront une copie des règles
        # qui ciblent Any-Trusted, pour que le trafic VLAN soit aussi couvert dans pfSense.
        trusted_vlan_pf_tags = []
        for child in itfs_pf:
            if_val = child.findtext("if") or ""
            # Une interface VLAN se reconnaît à son nom "xn1.10", "em1.20"…
            if "." in if_val and pf_lan_dev and if_val.startswith(pf_lan_dev + "."):
                trusted_vlan_pf_tags.append(child.tag)

        # ── Étape 0c : Migration des alias WatchGuard → pfSense ──────────────────
        # Les alias WG user-defined (property=16) sont convertis en aliases pfSense.
        # Cela préserve les noms sémantiques dans les règles migrées.
        SYSTEM_ALIAS_SUFFIXES = (".from", ".to", ".snat")
        WG_SYSTEM_ALIASES = {"Any", "Any-Trusted", "Any-External", "Any-Optional",
                             "Any-BOVPN", "Firebox"}
        aliases_pf_node = root_ensure(r_tgt, "aliases")
        existing_pf_aliases = {al.findtext("name") for al in aliases_pf_node.findall("alias")}

        for wg_al in r_src.findall(".//alias-list/alias"):
            al_name = safe_text(wg_al, "name") or ""
            al_prop = safe_text(wg_al, "property") or "0"
            if al_name in WG_SYSTEM_ALIASES:
                continue
            if any(al_name.endswith(s) for s in SYSTEM_ALIAS_SUFFIXES):
                continue
            if al_prop == "32":
                continue
            if al_name in existing_pf_aliases:
                continue
            resolved = resolve_wg_alias_deep(r_src, al_name)
            # Si resolved est un keyword pfSense ou non-IP, on n'en fait pas un alias
            if _pf_is_network_keyword(resolved) or resolved in ("any", "wanip", "lan", "wan"):
                continue
            pf_al = ET.SubElement(aliases_pf_node, "alias")
            ET.SubElement(pf_al, "name").text = al_name
            ET.SubElement(pf_al, "type").text = "network" if "/" in resolved else "host"
            ET.SubElement(pf_al, "address").text = resolved
            ET.SubElement(pf_al, "descr").text  = "Migré depuis WatchGuard"
            ET.SubElement(pf_al, "detail").text  = ""
            existing_pf_aliases.add(al_name)
            report["aliases"].append(al_name)
            print(f"[NETMORPH] 📋 Alias migré : {al_name} → {resolved}")

        # ── Étape 1 : Migration des règles et NAT ────────────────────────────────
        # Évite les NAT dupliqués quand plusieurs policies WG partagent le même <policy-nat>
        # (ex: HTTPS et HTTPS.1 pointant tous les deux vers SNAT "REDIRECTION")
        migrated_nats = set()

        for pol in r_src.findall(".//abs-policy-list/abs-policy"):
            # Sauter les règles système (property=32) et désactivées
            if safe_text(pol, "property") == "32":
                continue
            if safe_text(pol, "enabled") == "false":
                continue

            name = safe_text(pol, "name") or ""
            name_lower = name.lower()

            # Application des filtres d'exclusion
            if name_lower in WG_IGNORED_EXACT:
                report["skipped"].append(name)
                continue
            if any(name_lower.startswith(p) for p in WG_IGNORED_PREFIXES):
                report["skipped"].append(name)
                continue
            if any(name_lower.endswith(s) for s in WG_IGNORED_SUFFIXES):
                report["skipped"].append(name)
                continue

            # Résolution des attributs de la règle
            act        = "allow" if safe_text(pol, "firewall").lower() in ("1", "allow", "proxy") else "block"
            proto, port = wg_get_service_details(r_src, safe_text(pol, "service"))
            # Collecter TOUS les alias from/to (une policy WG peut en avoir plusieurs)
            wg_from_aliases = [a.text.strip() for a in pol.findall("from-alias-list/alias") if a.text]
            wg_to_aliases   = [a.text.strip() for a in pol.findall("to-alias-list/alias")   if a.text]
            wg_from_raw = wg_from_aliases[0] if wg_from_aliases else ""
            wg_to_raw   = wg_to_aliases[0]   if wg_to_aliases   else ""
            pf_src     = resolve_wg_alias_deep(r_src, wg_from_raw)
            pf_dst     = resolve_wg_alias_deep(r_src, wg_to_raw)
            pnat       = safe_text(pol, "policy-nat")

            # Interface pfSense : trafic depuis l'extérieur → WAN, sinon → LAN
            iface = "wan" if pf_src in ("any", "Any-External") else "lan"

            # Philosophie "Any-Trusted" : doit couvrir LAN + tous les VLANs trusted.
            # Déclenché si :
            # Déclencher la duplication sur les VLANs si la source résolue est "lan"
            # (peu importe le nom d'alias brut : "Any-Trusted", "DNS.1.from"… ils
            # résolvent tous en "lan" quand ils représentent le réseau trusted).
            expand_to_vlans = bool(trusted_vlan_pf_tags and pf_src == "lan")

            # Traitement du SNAT WatchGuard → NAT pfSense
            if pnat:
                for nat in r_src.findall(".//nat-list/nat"):
                    if safe_text(nat, "name") != pnat:
                        continue
                    mem = nat.find(".//nat-item/member")
                    if mem is not None:
                        real_ip = resolve_wg_alias_deep(r_src, safe_text(mem, "addr-name"))
                        t_port  = safe_text(mem, "port") or port

                        if port in PFSENSE_PROTECTED_PORTS:
                            # Port protégé : on garde la règle de filtrage mais
                            # on N'injecte PAS le NAT (évite de couper l'accès admin pfSense)
                            print(f"[NETMORPH] ⚠ NAT '{pnat}' ignoré : port {port} protégé (admin pfSense)")
                            pf_dst = real_ip
                            port   = t_port
                        elif pnat not in migrated_nats:
                            # Premier passage sur ce SNAT → on crée le NAT pfSense
                            pfsense_inject_nat_rule(r_tgt, f"NAT_{pnat}", proto, port, real_ip, t_port)
                            migrated_nats.add(pnat)
                            pf_dst = real_ip
                            port   = t_port
                        else:
                            # SNAT déjà créé (doublon) → on met juste à jour la destination
                            pf_dst = real_ip
                            port   = t_port
                    break

            # Injecte la règle sur l'interface principale (lan ou wan)
            if proto == "udp" or (port == "53" and proto == "tcp"):
                pfsense_inject_rule(r_tgt, f"[MIG] {name}",       act, iface, "tcp", pf_src, pf_dst, port)
                pfsense_inject_rule(r_tgt, f"[MIG] {name} (UDP)", act, iface, "udp", pf_src, pf_dst, port)
            else:
                pfsense_inject_rule(r_tgt, f"[MIG] {name}", act, iface, proto, pf_src, pf_dst, port)

            # Philosophie Any-Trusted : dupliquer sur chaque interface VLAN trusted.
            # IMPORTANT : la source devient le subnet propre à chaque VLAN (ex: "opt9"
            # pour MANAGE) et non "lan" — sinon pfSense ne matche pas le trafic entrant
            # sur l'interface VLAN car son subnet est différent du subnet LAN.
            if expand_to_vlans:
                for vlan_tag in trusted_vlan_pf_tags:
                    # Source = subnet de l'interface VLAN (keyword pfSense natif)
                    vlan_src = vlan_tag if pf_src == "lan" else pf_src
                    vlan_name = f"{name} ({vlan_tag.upper()})"
                    if proto == "udp" or (port == "53" and proto == "tcp"):
                        pfsense_inject_rule(r_tgt, f"[MIG] {vlan_name}",       act, vlan_tag, "tcp", vlan_src, pf_dst, port)
                        pfsense_inject_rule(r_tgt, f"[MIG] {vlan_name} (UDP)", act, vlan_tag, "udp", vlan_src, pf_dst, port)
                    else:
                        pfsense_inject_rule(r_tgt, f"[MIG] {vlan_name}", act, vlan_tag, proto, vlan_src, pf_dst, port)

            report["rules"].append(name)
            migrated_count += 1

    # =========================================================================
    # DIRECTION : PFSENSE → WATCHGUARD
    # =========================================================================
    elif r_src.tag == "pfsense" and r_tgt.tag == "profile":

        # Correspondance réseau pfSense → alias WatchGuard standard
        alias_map = {
            "lan":    "Any-Trusted",
            "wan":    "Any-External",
            "any":    "Any",
            "wanip":  "Firebox",
            "(self)": "Firebox",
        }

        # Table de correspondance port interne → nom de service WatchGuard exact
        # On utilise le port INTERNE (après translation NAT) pour identifier le vrai service.
        # Ex: ext_port=33891, int_port=3389 → service "RDP" (pas "TCP-33891")
        _PF_PORT_TO_WG_SVC = {
            "80":   "HTTP",          "443":  "HTTPS",
            "22":   "SSH",           "53":   "DNS",
            "23":   "Telnet",        "21":   "FTP",
            "25":   "SMTP",          "110":  "POP3",
            "143":  "IMAP",          "3389": "RDP",
            "161":  "SNMP",          "389":  "LDAP",
            "445":  "SMB",           "1645": "RADIUS",
            "514":  "Syslog",        "1433": "MS-SQL-Server",
            "1521": "SQL*Net",       "179":  "BGP",
            "69":   "TFTP",
        }

        def _pf_port_to_svc(proto: str, dst_port: str) -> str:
            """
            Traduit un couple (proto, port) pfSense vers le nom de service WatchGuard.

            Priorité :
              1. Lookup dans la table statique _PF_PORT_TO_WG_SVC
              2. ICMP → "Ping"
              3. Port non référencé → crée un service custom "TCP-XXXX" dans WG
              4. Fallback ultime → "HTTP" (ne devrait pas arriver)
            """
            if dst_port in _PF_PORT_TO_WG_SVC:
                return _PF_PORT_TO_WG_SVC[dst_port]
            if proto == "icmp":
                return "Ping"
            if dst_port:
                return ensure_wg_custom_service(r_tgt, proto, dst_port)
            return "HTTP"

        # Ports protégés côté WatchGuard : ne jamais créer de SNAT sur ces ports
        # (4105/8080/4106 = ports d'administration natifs WatchGuard)
        WG_PFSENSE_PROTECTED_PORTS = {"4105", "8080", "4106", "4117"}

        # ── Étape 1 : Migration des règles NAT pfSense → SNAT WatchGuard ──
        # On traite les NAT en premier pour construire nat_int_target_index,
        # qui sera utilisé dans l'étape 2 pour lier les filter rules correspondantes.
        pf_nats = r_src.find("nat")
        nat_target_ports_done = set()   # évite les SNAT dupliqués (même ip:port)
        nat_int_target_index  = {}      # (ip_interne, port_interne) → (snat_name, wrapper_alias, svc)

        if pf_nats is not None:
            for pf_nat in pf_nats.findall("rule"):
                target_ip = safe_text(pf_nat, "target")
                ext_port  = safe_text(pf_nat, "destination/port")
                int_port  = safe_text(pf_nat, "local-port") or ext_port
                proto_nat = safe_text(pf_nat, "protocol") or "tcp"
                descr_nat = safe_text(pf_nat, "descr") or f"NAT_{ext_port}"

                if not target_ip:
                    continue

                # Sauter les ports d'administration WatchGuard
                if ext_port in WG_PFSENSE_PROTECTED_PORTS:
                    print(f"[NETMORPH] ⚠ NAT pfSense '{descr_nat}' ignoré : port {ext_port} protégé (admin WG)")
                    continue

                # Dédoublonnage sur (ip_interne:port_externe)
                nat_key = f"{target_ip}:{ext_port}"
                if nat_key in nat_target_ports_done:
                    continue
                nat_target_ports_done.add(nat_key)

                sn_name = f"SNAT_{migrated_count}_{ext_port}"

                # Service identifié par le port INTERNE (pas l'externe potentiellement obfusqué)
                svc_nat = _pf_port_to_svc(proto_nat, int_port)

                # Création du SNAT WatchGuard : address-group + nat + alias wrapper
                wg_dst_nat = wg_inject_nat_rule(r_tgt, sn_name, target_ip, ext_port, int_port)

                # Policy WG associée au SNAT (Any-External → wrapper SNAT)
                wg_inject_rule(
                    r_tgt, f"MIG_NAT_{migrated_count}", "allow", svc_nat,
                    "Any-External", wg_dst_nat, pnat=sn_name, is_snat=True
                )

                # Index pour retrouver ce SNAT depuis les filter rules de l'étape 2
                nat_int_target_index[(target_ip, int_port)] = (sn_name, wg_dst_nat, svc_nat)
                migrated_count += 1

        # ── Étape 2 : Migration des règles de filtrage pfSense → policies WatchGuard ──

        # Noms exacts de règles pfSense système à ne pas migrer
        PF_IGNORED_EXACT = {
            "anti-lockout rule",
            "default allow lan to any rule",
            "default allow lan ipv6 to any rule",
            "default deny rule ipv4",
            "default deny rule ipv6",
            "allow access to dhcp server on lan interface",
            "allow ipv6",
            "allow ipv4",
            "ipv6 allow",
            "allow icmp",
        }
        # Préfixes de règles système pfSense à ignorer
        PF_IGNORED_PREFIXES = (
            "default ",         # toutes les règles "Default *" pfSense
            "auto-generated",   # règles générées automatiquement
        )

        # Déduplication (svc, port, dst) pour éviter les doublons DNS TCP+UDP
        # (pfSense peut avoir deux règles séparées TCP/53 et UDP/53 qui donnent
        #  le même service WG "DNS" → on n'en veut qu'une seule)
        migrated_filter_keys = set()

        for pf_rule in r_src.findall(".//filter/rule"):

            # Règle désactivée → on ne migre pas
            if pf_rule.find("disabled") is not None:
                continue

            descr = (safe_text(pf_rule, "descr") or "").strip()

            # Règle sans description = règle par défaut pfSense (pas de nom utilisateur) → ignorer
            if not descr:
                continue

            descr_lower = descr.lower()
            if descr_lower in PF_IGNORED_EXACT:
                continue
            if any(descr_lower.startswith(p) for p in PF_IGNORED_PREFIXES):
                continue

            # Règle auto-générée par une règle NAT pfSense → déjà couverte par l'étape 1
            if pf_rule.find("associated-rule-id") is not None:
                continue

            # Extraction des attributs de la règle pfSense
            act      = "allow" if safe_text(pf_rule, "type").lower() == "pass" else "block"
            proto    = safe_text(pf_rule, "protocol") or "tcp"
            dst_port = safe_text(pf_rule, "destination/port")
            dst_addr = (
                safe_text(pf_rule, "destination/address")
                or safe_text(pf_rule, "destination/network")
                or "any"
            )
            src_net  = safe_text(pf_rule, "source/network") or "any"

            svc    = _pf_port_to_svc(proto.lower(), dst_port)
            wg_src = alias_map.get(src_net.lower(), "Any")
            wg_dst = alias_map.get(dst_addr.lower(), dst_addr)

            # Déduplication DNS (et autres services avec TCP+UDP)
            filter_key = (svc.lower(), dst_port or "", wg_dst.lower())
            if filter_key in migrated_filter_keys:
                continue
            migrated_filter_keys.add(filter_key)

            # Si la destination (ip, port) est une cible NAT connue → lier au SNAT existant
            # Cela relie une filter rule manuelle pfSense (sans associated-rule-id) au bon SNAT WG.
            nat_match = nat_int_target_index.get((dst_addr, dst_port))
            if nat_match:
                sn_name_lnk, wg_dst_lnk, svc_lnk = nat_match
                wg_inject_rule(
                    r_tgt, f"MIG_{migrated_count}", act, svc_lnk,
                    "Any-External", wg_dst_lnk, pnat=sn_name_lnk, is_snat=True
                )
            else:
                wg_inject_rule(r_tgt, f"MIG_{migrated_count}", act, svc, wg_src, wg_dst)

            report["rules"].append(descr)
            migrated_count += 1

    else:
        raise ValueError(
            "Erreur de sélection de fichier : "
            "Assurez-vous d'avoir un source et une cible compatibles (WG↔pfSense)."
        )

    # =========================================================================
    # PHASE DE LINTING ET D'AUTO-RÉPARATION IA
    # =========================================================================
    out_path = os.path.join(app_dir(), "firewall_modifie.xml")

    # ── Rotation de l'historique (3 sauvegardes glissantes) ──────────────────
    # firewall_modifie.xml → .1.xml → .2.xml → .3.xml (le plus ancien est écrasé)
    for i in range(2, 0, -1):
        src_bak = os.path.join(app_dir(), f"firewall_modifie.{i}.xml")
        dst_bak = os.path.join(app_dir(), f"firewall_modifie.{i+1}.xml")
        if os.path.exists(src_bak):
            shutil.move(src_bak, dst_bak)
    if os.path.exists(out_path):
        shutil.copy(out_path, os.path.join(app_dir(), "firewall_modifie.1.xml"))

    # Sérialisation du XML cible en mémoire pour validation
    raw_xml_bytes = ET.tostring(r_tgt, encoding="utf-8", xml_declaration=True)
    raw_xml_str   = raw_xml_bytes.decode("utf-8")

    is_valid      = True
    error_msg     = ""
    target_system = "Inconnu"

    # Choix du linter selon l'OS cible
    if r_tgt.tag == "profile":
        target_system = "WatchGuard"
        is_valid, error_msg = watchguard_xml_linter(raw_xml_str)
    elif r_tgt.tag == "pfsense":
        target_system = "pfSense"
        is_valid, error_msg = pfsense_xml_linter(raw_xml_str)

    # Correction des erreurs détectées
    if not is_valid:
        if r_tgt.tag == "pfsense" and "ipprotocol" in error_msg.lower():
            # Correction programmatique : ajouter <ipprotocol>inet</ipprotocol>
            # à toutes les règles pfSense qui en sont dépourvues.
            # On ne touche PAS au reste du XML (notamment la section <system>/<webgui>).
            print("[NETMORPH] 🔧 Correction automatique : ajout <ipprotocol> manquants…")
            fixed_root = ET.fromstring(raw_xml_bytes)
            for rule_el in fixed_root.findall(".//filter/rule"):
                if rule_el.find("ipprotocol") is None:
                    ET.SubElement(rule_el, "ipprotocol").text = "inet"
            raw_xml_bytes = ET.tostring(fixed_root, encoding="utf-8", xml_declaration=True)
            raw_xml_str   = raw_xml_bytes.decode("utf-8")
            print("[NETMORPH] ✅ <ipprotocol> ajouté sans modifier la config système.")
        else:
            # Pour les autres erreurs (WatchGuard ou cas inconnus) → IA en dernier recours
            raw_xml_str = ask_ai_to_repair(raw_xml_str, error_msg, target_system)

    # Sauvegarde finale
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(raw_xml_str)

    # Copie dans firewall.xml (fichier actif de l'application)
    shutil.copy(out_path, os.path.join(app_dir(), "firewall.xml"))

    report["count"] = migrated_count
    return report


# =============================================================================
# DELETE_RULE_XML — SUPPRESSION D'UNE RÈGLE PFSENSE PAR INDEX
# =============================================================================

def delete_rule_xml(index: int) -> None:
    """
    Supprime une règle de filtrage pfSense par son index (0-based) dans <filter>.

    Args:
        index : index de la règle (0-based, dans l'ordre d'apparition dans le XML)

    Raises:
        FileNotFoundError : aucun XML chargé
        ValueError        : XML non pfSense
        IndexError        : index hors limites
    """
    xml_path = get_working_xml()
    if not xml_path:
        raise FileNotFoundError("Aucun fichier XML chargé.")

    tree = ET.parse(xml_path)
    root = tree.getroot()

    if root.tag != "pfsense":
        raise ValueError("La suppression de règle n'est supportée que pour pfSense.")

    filter_node = root.find("filter")
    if filter_node is None:
        raise IndexError("Aucune règle de filtrage trouvée.")

    rules = filter_node.findall("rule")
    if index < 0 or index >= len(rules):
        raise IndexError(f"Index {index} hors limites (0–{len(rules)-1}).")

    filter_node.remove(rules[index])

    out_path = os.path.join(app_dir(), "firewall.xml")
    tree.write(out_path, encoding="unicode", xml_declaration=False)
    mod_path = os.path.join(app_dir(), "firewall_modifie.xml")
    if os.path.exists(mod_path):
        tree.write(mod_path, encoding="unicode", xml_declaration=False)
