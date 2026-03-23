"""
audit.py — Moteur d'audit de sécurité NETMORPH
================================================
Analyse un fichier de configuration WatchGuard ou pfSense et retourne
une liste de findings classés par sévérité.

Niveaux de sévérité :
  CRITICAL  — Exposition immédiate, risque d'intrusion ou de ransomware
  HIGH      — Surface d'attaque significative, action requise
  MEDIUM    — Mauvaise pratique, atténuer si possible
  LOW       — Amélioration recommandée
  INFO      — Statistiques et observations générales
"""

import xml.etree.ElementTree as ET
from utils import safe_text

_SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
_SEVERITY_ORDER  = {"CRITICAL": 0,  "HIGH": 1,  "MEDIUM": 2, "LOW": 3, "INFO": 4}


# =============================================================================
# API PUBLIQUE
# =============================================================================

def run_audit(xml_path: str) -> list[dict]:
    """
    Point d'entrée principal. Parse le XML et lance l'audit adapté au type de firewall.

    Returns:
        list of dict [{"severity", "title", "detail", "rule"}, …]
        trié du plus critique au moins critique.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    is_wg = (root.tag == "profile")
    findings = _audit_watchguard(root) if is_wg else _audit_pfsense(root)
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 99))
    return findings


def compute_score(findings: list[dict]) -> int:
    """
    Calcule un score de sécurité sur 100 en déduisant une pénalité par finding.

    Pénalités : CRITICAL −25 · HIGH −15 · MEDIUM −8 · LOW −3
    Score plancher : 0
    """
    score = 100
    for f in findings:
        score -= _SEVERITY_WEIGHT.get(f["severity"], 0)
    return max(0, score)


# =============================================================================
# HELPERS INTERNES
# =============================================================================

def _finding(severity: str, title: str, detail: str, rule: str = "") -> dict:
    return {"severity": severity, "title": title, "detail": detail, "rule": rule}


# =============================================================================
# AUDIT WATCHGUARD
# =============================================================================

def _audit_watchguard(root) -> list[dict]:
    findings = []

    # ── Collecte des politiques (hors règles système property=32) ─────────────
    policies = []
    for pol in root.findall(".//abs-policy-list/abs-policy"):
        if safe_text(pol, "property") == "32":
            continue
        name    = safe_text(pol, "name")
        act_raw = safe_text(pol, "firewall").lower()
        action  = "allow" if act_raw in ["1", "allow", "proxy", "allowed"] else "deny"
        service = safe_text(pol, "service")
        froms   = [a.text for a in pol.findall(".//from-alias-list/alias") if a.text]
        tos     = [a.text for a in pol.findall(".//to-alias-list/alias") if a.text]
        enabled = safe_text(pol, "enabled").lower() != "false"
        policies.append({
            "name":    name,
            "action":  action,
            "service": service,
            "froms":   froms,
            "tos":     tos,
            "enabled": enabled,
        })

    ANY_ALIASES = {"Any", "Any-External", "Any-Trusted", "Any-Optional"}
    EXT_ALIASES = {"Any", "Any-External"}

    for p in policies:
        if not p["enabled"]:
            continue
        src_any = any(f in ANY_ALIASES for f in p["froms"])
        dst_any = any(t in ANY_ALIASES for t in p["tos"])
        src_ext = any(f in EXT_ALIASES for f in p["froms"])
        svc     = p["service"].lower()

        # ── CRITICAL : Any-to-Any autorisé ────────────────────────────────────
        if p["action"] == "allow" and src_any and dst_any:
            findings.append(_finding("CRITICAL",
                "Règle Any-to-Any autorisée",
                "Tout le trafic est accepté sans restriction de source ni de destination. "
                "Affinez la règle avec des alias réseau spécifiques.",
                p["name"]))

        # ── CRITICAL : Telnet ──────────────────────────────────────────────────
        if p["action"] == "allow" and ("telnet" in svc or "tcp-23" in svc):
            findings.append(_finding("CRITICAL",
                "Telnet autorisé (port 23 — non chiffré)",
                "Telnet transmet identifiants et données en clair sur le réseau. "
                "Remplacez par SSH (port 22) qui chiffre l'intégralité de la session.",
                p["name"]))

        # ── CRITICAL : SMB/NetBIOS depuis l'extérieur ─────────────────────────
        if p["action"] == "allow" and src_ext:
            for kw in ("smb", "ms ds", "netbios", "cifs"):
                if kw in svc:
                    findings.append(_finding("CRITICAL",
                        "SMB/NetBIOS exposé depuis l'extérieur",
                        "SMB (port 445) ne doit jamais être accessible depuis Internet — "
                        "vecteur principal des ransomwares WannaCry et NotPetya. "
                        "Bloquez immédiatement sur l'interface externe.",
                        p["name"]))
                    break

        # ── HIGH : RDP depuis l'extérieur ─────────────────────────────────────
        if p["action"] == "allow" and src_ext and ("rdp" in svc or "tcp-3389" in svc):
            findings.append(_finding("HIGH",
                "RDP exposé depuis l'extérieur (port 3389)",
                "RDP est une cible constante de bruteforce et d'exploits (BlueKeep CVE-2019-0708). "
                "Restreignez l'accès via VPN ou filtrez par IP source de confiance.",
                p["name"]))

        # ── HIGH : SSH depuis l'extérieur ─────────────────────────────────────
        if p["action"] == "allow" and src_ext and ("ssh" in svc or "tcp-22" in svc):
            findings.append(_finding("HIGH",
                "SSH accessible depuis n'importe quelle IP externe",
                "SSH ouvert à toutes les IPs subit des attaques de bruteforce en continu. "
                "Limitez la source à vos plages d'administration ou utilisez un bastion.",
                p["name"]))

        # ── HIGH : Bases de données depuis l'extérieur ────────────────────────
        if p["action"] == "allow" and src_ext:
            DB_KEYWORDS = [
                ("sql server", "SQL Server (1433)"),
                ("tcp-1433",   "SQL Server (1433)"),
                ("oracle",     "Oracle SQL*Net (1521)"),
                ("sql*net",    "Oracle SQL*Net (1521)"),
                ("tcp-3306",   "MySQL (3306)"),
                ("tcp-5432",   "PostgreSQL (5432)"),
            ]
            for kw, label in DB_KEYWORDS:
                if kw in svc:
                    findings.append(_finding("HIGH",
                        f"Base de données {label} exposée sur Internet",
                        "Les SGBD ne doivent jamais être accessibles directement depuis Internet. "
                        "Utilisez un VPN ou un bastion pour les accès d'administration.",
                        p["name"]))
                    break

        # ── MEDIUM : FTP (non chiffré) ────────────────────────────────────────
        if p["action"] == "allow" and ("ftp" in svc) and "sftp" not in svc and "ftps" not in svc:
            findings.append(_finding("MEDIUM",
                "FTP autorisé (port 21 — non chiffré)",
                "FTP transmet identifiants et fichiers en clair. "
                "Migrez vers SFTP (SSH, port 22) ou FTPS (FTP over TLS, port 990).",
                p["name"]))

        # ── MEDIUM : SNMP depuis l'extérieur ─────────────────────────────────
        if p["action"] == "allow" and src_ext and "snmp" in svc:
            findings.append(_finding("MEDIUM",
                "SNMP accessible depuis l'extérieur",
                "SNMP v1/v2c utilise une chaîne de communauté en clair. "
                "Depuis Internet, cela permet la cartographie complète du réseau. "
                "Bloquez sur l'interface externe et utilisez SNMPv3 si nécessaire.",
                p["name"]))

        # ── LOW : HTTP (non-HTTPS) depuis l'extérieur ────────────────────────
        if p["action"] == "allow" and src_ext and svc == "http":
            findings.append(_finding("LOW",
                "HTTP non chiffré autorisé depuis l'extérieur (port 80)",
                "HTTP expose les communications en clair (cookies, formulaires). "
                "Activez HTTPS et redirigez HTTP → HTTPS.",
                p["name"]))

    # ── LOW : Règles dupliquées ────────────────────────────────────────────────
    seen = {}
    for p in policies:
        key = (p["action"], p["service"].lower(),
               frozenset(p["froms"]), frozenset(p["tos"]))
        if key in seen:
            findings.append(_finding("LOW",
                "Règle dupliquée détectée",
                f"'{p['name']}' est identique à '{seen[key]}' "
                "(même service, source, destination et action). "
                "Supprimez le doublon pour éviter la confusion.",
                p["name"]))
        else:
            seen[key] = p["name"]

    # ── INFO : Règles désactivées ──────────────────────────────────────────────
    disabled = [p["name"] for p in policies if not p["enabled"]]
    if disabled:
        findings.append(_finding("INFO",
            f"{len(disabled)} règle(s) désactivée(s) dans la configuration",
            "Les règles désactivées alourdissent la config et peuvent être réactivées "
            "par erreur. Supprimez-les si elles ne sont plus utiles.",
            ", ".join(disabled[:5]) + ("…" if len(disabled) > 5 else "")))

    # ── INFO : Règles sans nom explicite ──────────────────────────────────────
    unnamed = [p["name"] for p in policies
               if not p["name"] or p["name"].lower().startswith("policy-")]
    if unnamed:
        findings.append(_finding("INFO",
            f"{len(unnamed)} règle(s) sans nom explicite",
            "Des règles non nommées rendent l'audit et la maintenance difficiles "
            "et augmentent le risque d'erreur de configuration.",
            ", ".join(unnamed[:5]) + ("…" if len(unnamed) > 5 else "")))

    # ── INFO : Statistiques générales ─────────────────────────────────────────
    active  = [p for p in policies if p["enabled"]]
    n_allow = sum(1 for p in active if p["action"] == "allow")
    n_deny  = sum(1 for p in active if p["action"] == "deny")
    findings.append(_finding("INFO",
        f"Politique : {len(active)} règles actives — {n_allow} Allow / {n_deny} Deny",
        "Vue d'ensemble de la politique de filtrage WatchGuard Fireware.",
        ""))

    return findings


# =============================================================================
# AUDIT PFSENSE
# =============================================================================

def _audit_pfsense(root) -> list[dict]:
    findings = []

    # ── Collecte des règles de filtrage ───────────────────────────────────────
    policies = []
    for pol in root.findall(".//filter/rule"):
        name     = safe_text(pol, "descr") or "Règle Anonyme"
        action   = safe_text(pol, "type").lower()           # "pass" ou "block"
        proto    = safe_text(pol, "protocol").lower() or "any"
        iface    = safe_text(pol, "interface").lower() or "lan"
        src_any  = pol.find("source/any") is not None
        dst_any  = pol.find("destination/any") is not None
        src_net  = (safe_text(pol, "source/network")
                    or safe_text(pol, "source/address")
                    or ("any" if src_any else "?"))
        dst_port = safe_text(pol, "destination/port")
        disabled = pol.find("disabled") is not None
        has_log  = pol.find("log") is not None
        policies.append({
            "name":     name,
            "action":   action,
            "proto":    proto,
            "iface":    iface,
            "src_any":  src_any,
            "dst_any":  dst_any,
            "src":      src_net,
            "dst_port": dst_port,
            "disabled": disabled,
            "log":      has_log,
        })

    WAN_IFACES = {"wan", "wan1", "wan2", "opt1"}

    for p in policies:
        if p["disabled"]:
            continue
        is_wan = p["iface"] in WAN_IFACES

        # ── CRITICAL : Any-to-Any autorisé ────────────────────────────────────
        if p["action"] == "pass" and p["src_any"] and p["dst_any"]:
            findings.append(_finding("CRITICAL",
                "Règle Any-to-Any autorisée",
                "Tout le trafic est accepté sans restriction. "
                "Affinez les sources et destinations pour ne laisser passer que ce qui est nécessaire.",
                p["name"]))

        # ── CRITICAL : Telnet ──────────────────────────────────────────────────
        if p["action"] == "pass" and p["dst_port"] == "23":
            findings.append(_finding("CRITICAL",
                "Telnet autorisé (port 23 — non chiffré)",
                "Telnet transmet identifiants et données en clair. "
                "Remplacez par SSH (port 22).",
                p["name"]))

        # ── Ports dangereux sur WAN ────────────────────────────────────────────
        DANGEROUS = {
            "445":  ("CRITICAL", "SMB (445) exposé sur WAN — vecteur ransomware critique (WannaCry, NotPetya). Bloquez immédiatement."),
            "3389": ("HIGH",     "RDP (3389) exposé sur WAN — cible de bruteforce et d'exploits (BlueKeep). Utilisez un VPN."),
            "22":   ("HIGH",     "SSH (22) ouvert depuis toutes les IPs sur le WAN. Limitez à vos IPs d'admin ou placez derrière VPN."),
            "137":  ("HIGH",     "NetBIOS-NS (137) accessible depuis Internet. Ce service ne doit jamais être exposé."),
            "138":  ("HIGH",     "NetBIOS-DGM (138) accessible depuis Internet. Ce service ne doit jamais être exposé."),
            "139":  ("HIGH",     "NetBIOS-SSN (139) accessible depuis Internet. Ce service ne doit jamais être exposé."),
            "1433": ("HIGH",     "SQL Server (1433) exposé sur Internet. Utilisez un VPN pour les accès distants."),
            "1521": ("HIGH",     "Oracle SQL*Net (1521) exposé sur Internet. Utilisez un VPN."),
            "3306": ("HIGH",     "MySQL (3306) exposé sur Internet. Utilisez un VPN ou tunnel SSH."),
            "5432": ("HIGH",     "PostgreSQL (5432) exposé sur Internet. Utilisez un VPN ou tunnel SSH."),
            "21":   ("MEDIUM",   "FTP (21) transmet credentials et données en clair. Utilisez SFTP ou FTPS."),
            "161":  ("MEDIUM",   "SNMP (161) depuis Internet — risque de cartographie réseau et d'énumération."),
            "80":   ("LOW",      "HTTP (80) non chiffré. Activez HTTPS et redirigez HTTP → HTTPS."),
        }
        if is_wan and p["action"] == "pass" and p["dst_port"] in DANGEROUS:
            sev, msg = DANGEROUS[p["dst_port"]]
            findings.append(_finding(sev,
                f"Port dangereux exposé sur WAN : {p['dst_port']}",
                msg,
                p["name"]))

        # ── MEDIUM : FTP partout ───────────────────────────────────────────────
        if p["action"] == "pass" and p["dst_port"] == "21" and not is_wan:
            findings.append(_finding("MEDIUM",
                "FTP autorisé (port 21 — non chiffré)",
                "FTP transmet identifiants et fichiers en clair sur le réseau interne. "
                "Migrez vers SFTP (SSH) ou FTPS.",
                p["name"]))

    # ── LOW : Règles pass sans logging ────────────────────────────────────────
    no_log = [p for p in policies
              if p["action"] == "pass" and not p["log"]
              and not p["src_any"] and not p["disabled"]]
    if no_log:
        findings.append(_finding("LOW",
            f"{len(no_log)} règle(s) pass sans logging activé",
            "Sans journalisation, vous ne pouvez pas détecter les connexions suspectes "
            "ni répondre efficacement à un incident de sécurité. "
            "Activez <log/> sur les règles sensibles.",
            ""))

    # ── LOW : Règles dupliquées ────────────────────────────────────────────────
    seen = {}
    for p in policies:
        key = (p["action"], p["proto"], p["iface"], p["src"], p["dst_port"])
        if key in seen:
            findings.append(_finding("LOW",
                "Règle dupliquée détectée",
                f"'{p['name']}' semble identique à '{seen[key]}' "
                "(même interface, protocole, source et port destination). "
                "Supprimez le doublon.",
                p["name"]))
        else:
            seen[key] = p["name"]

    # ── INFO : Règles désactivées ──────────────────────────────────────────────
    disabled_list = [p["name"] for p in policies if p["disabled"]]
    if disabled_list:
        findings.append(_finding("INFO",
            f"{len(disabled_list)} règle(s) désactivée(s) dans la configuration",
            "Supprimez les règles inutilisées pour clarifier la politique de sécurité "
            "et réduire la surface d'attaque de la configuration.",
            ", ".join(disabled_list[:5]) + ("…" if len(disabled_list) > 5 else "")))

    # ── INFO : Règles sans description ────────────────────────────────────────
    unnamed = [p for p in policies if p["name"] == "Règle Anonyme"]
    if unnamed:
        findings.append(_finding("INFO",
            f"{len(unnamed)} règle(s) sans description (<descr>)",
            "Ajoutez une balise <descr> à chaque règle pour faciliter l'audit "
            "et la traçabilité des modifications.",
            ""))

    # ── INFO : Statistiques générales ─────────────────────────────────────────
    active  = [p for p in policies if not p["disabled"]]
    n_pass  = sum(1 for p in active if p["action"] == "pass")
    n_block = sum(1 for p in active if p["action"] == "block")
    findings.append(_finding("INFO",
        f"Politique : {len(active)} règles actives — {n_pass} Pass / {n_block} Block",
        "Vue d'ensemble de la politique de filtrage pfSense.",
        ""))

    return findings
