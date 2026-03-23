"""
ui_template.py — Moteur de rendu HTML/CSS/JS de NETMORPH
==========================================================
Génère le HTML complet injecté dans le QWebEngineView.
L'UI est divisée en trois onglets :
  - Tableau de bord  : topologie, règles, NAT
  - Éditeur rapide   : création de règle / interface
  - Migrateur        : wizard 2 étapes (source → cible auto-détectée)
"""


# =============================================================================
# AUDIT — HELPERS DE RENDU
# =============================================================================

_SEV_COLOR = {
    "CRITICAL": "#fa194f",
    "HIGH":     "#ff9500",
    "MEDIUM":   "#f5c518",
    "LOW":      "#00e5ff",
    "INFO":     "#7070a0",
}
_SEV_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


def _audit_nav_badge(findings: list) -> str:
    """Retourne un badge rouge si des findings CRITICAL/HIGH existent."""
    has_critical = any(f["severity"] in ("CRITICAL", "HIGH") for f in findings)
    if has_critical:
        return '<span class="nav-badge nav-badge-red">!</span>'
    return '<span class="nav-badge">•</span>'


def _render_audit_section(findings, data) -> str:
    """Génère le HTML complet de l'onglet Audit de Sécurité."""
    from audit import compute_score

    fw_label = data["fw_type"] if data else "Firewall"

    if not findings:
        return f"""
        <h2 class="section-title">
            <span class="title-accent">Audit de Sécurité</span>
            <span class="title-sub">Importez une configuration pour lancer l'analyse</span>
        </h2>
        <div class="gx-card" style="text-align:center; padding:60px;">
            <div style="font-size:48px; margin-bottom:16px;">🔍</div>
            <div style="color:var(--text-muted);">
                Aucune configuration chargée.<br>
                Importez un fichier XML WatchGuard ou pfSense pour démarrer l'audit.
            </div>
        </div>"""

    score = compute_score(findings)
    n_critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    n_high     = sum(1 for f in findings if f["severity"] == "HIGH")
    n_medium   = sum(1 for f in findings if f["severity"] == "MEDIUM")
    n_low      = sum(1 for f in findings if f["severity"] == "LOW")
    n_info     = sum(1 for f in findings if f["severity"] == "INFO")

    # Couleur + label du score
    if score >= 80:
        score_color = "#00ff88"
        score_label = "Bon"
    elif score >= 60:
        score_color = "#ff9500"
        score_label = "Moyen"
    elif score >= 40:
        score_color = "#fa194f"
        score_label = "Faible"
    else:
        score_color = "#fa194f"
        score_label = "Critique"

    # ── Barre de score ─────────────────────────────────────────────────────────
    score_html = f"""
    <div class="audit-score-block">
        <div class="audit-score-circle" style="--score-color:{score_color};">
            <svg viewBox="0 0 120 120" class="audit-score-svg">
                <circle cx="60" cy="60" r="52" class="score-track"/>
                <circle cx="60" cy="60" r="52" class="score-fill"
                        style="stroke:{score_color};
                               stroke-dasharray:{int(score * 3.267)} 327;"/>
            </svg>
            <div class="audit-score-inner">
                <span class="audit-score-num" style="color:{score_color};">{score}</span>
                <span class="audit-score-label" style="color:{score_color};">{score_label}</span>
            </div>
        </div>
        <div class="audit-score-legend">
            <div class="audit-score-title">Score de sécurité</div>
            <div class="audit-score-fw">{fw_label}</div>
            <div class="audit-breakdown">
                <div class="audit-breakdown-item" style="color:#fa194f;">
                    <span class="bk-num">{n_critical}</span>
                    <span class="bk-label">Critical</span>
                </div>
                <div class="audit-breakdown-item" style="color:#ff9500;">
                    <span class="bk-num">{n_high}</span>
                    <span class="bk-label">High</span>
                </div>
                <div class="audit-breakdown-item" style="color:#f5c518;">
                    <span class="bk-num">{n_medium}</span>
                    <span class="bk-label">Medium</span>
                </div>
                <div class="audit-breakdown-item" style="color:#00e5ff;">
                    <span class="bk-num">{n_low}</span>
                    <span class="bk-label">Low</span>
                </div>
                <div class="audit-breakdown-item" style="color:#7070a0;">
                    <span class="bk-num">{n_info}</span>
                    <span class="bk-label">Info</span>
                </div>
            </div>
        </div>
    </div>"""

    # ── Liste des findings ─────────────────────────────────────────────────────
    cards_html = ""
    current_sev = None
    for f in findings:
        sev   = f["severity"]
        color = _SEV_COLOR.get(sev, "#7070a0")
        icon  = _SEV_ICON.get(sev, "⚪")

        # Séparateur de groupe par sévérité
        if sev != current_sev:
            current_sev = sev
            cards_html += f"""
            <div class="audit-group-header" style="color:{color};">
                {icon} &nbsp;{sev}
            </div>"""

        rule_badge = (
            f'<span class="audit-rule-badge">{f["rule"]}</span>'
            if f.get("rule") else ""
        )
        cards_html += f"""
        <div class="audit-card" style="border-left-color:{color};">
            <div class="audit-card-head">
                <span class="audit-sev-dot" style="background:{color};
                      box-shadow:0 0 6px {color};"></span>
                <span class="audit-card-title">{f["title"]}</span>
                {rule_badge}
            </div>
            <div class="audit-card-detail">{f["detail"]}</div>
        </div>"""

    return f"""
    <h2 class="section-title">
        <span class="title-accent">Audit de Sécurité</span>
        <span class="title-sub">{fw_label}</span>
    </h2>

    <div class="grid-audit">
        <!-- Bloc score -->
        <div class="gx-card glow-red" style="align-self:start;">
            <div class="card-header">🛡️ Score global</div>
            {score_html}
        </div>

        <!-- Aide à la lecture -->
        <div class="gx-card" style="align-self:start;">
            <div class="card-header">📖 Niveaux de sévérité</div>
            <div class="audit-legend-list">
                <div class="audit-legend-item">
                    <span class="audit-sev-dot" style="background:#fa194f;box-shadow:0 0 6px #fa194f;"></span>
                    <div>
                        <b style="color:#fa194f;">CRITICAL</b> — Pénalité ×25<br>
                        <span class="dim">Exposition immédiate, correctif urgent requis.</span>
                    </div>
                </div>
                <div class="audit-legend-item">
                    <span class="audit-sev-dot" style="background:#ff9500;box-shadow:0 0 6px #ff9500;"></span>
                    <div>
                        <b style="color:#ff9500;">HIGH</b> — Pénalité ×15<br>
                        <span class="dim">Surface d'attaque significative, à corriger rapidement.</span>
                    </div>
                </div>
                <div class="audit-legend-item">
                    <span class="audit-sev-dot" style="background:#f5c518;box-shadow:0 0 6px #f5c518;"></span>
                    <div>
                        <b style="color:#f5c518;">MEDIUM</b> — Pénalité ×8<br>
                        <span class="dim">Mauvaise pratique, à atténuer si possible.</span>
                    </div>
                </div>
                <div class="audit-legend-item">
                    <span class="audit-sev-dot" style="background:#00e5ff;box-shadow:0 0 6px #00e5ff;"></span>
                    <div>
                        <b style="color:#00e5ff;">LOW</b> — Pénalité ×3<br>
                        <span class="dim">Amélioration recommandée pour durcir la config.</span>
                    </div>
                </div>
                <div class="audit-legend-item">
                    <span class="audit-sev-dot" style="background:#7070a0;"></span>
                    <div>
                        <b style="color:#7070a0;">INFO</b> — Pas de pénalité<br>
                        <span class="dim">Observations et statistiques générales.</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Méthodologie -->
    <div class="gx-card" style="margin-top:24px;">
        <div class="card-header" style="cursor:pointer; user-select:none;"
             onclick="toggleMethodo()">
            📚 Méthodologie &amp; Références
            <span id="methodo-arrow" style="float:right; transition:transform 0.2s;">▼</span>
        </div>
        <div id="methodo-body">
            <p class="methodo-intro">
                L'audit NETMORPH est basé sur les référentiels de sécurité suivants.
                Chaque vérification est rattachée à un ou plusieurs standards reconnus.
            </p>

            <div class="methodo-grid">

                <div class="methodo-ref-block">
                    <div class="methodo-ref-title">
                        <span class="methodo-ref-badge" style="background:#1a3a6a;">NIST</span>
                        SP 800-41 — Guidelines on Firewalls
                    </div>
                    <div class="methodo-ref-desc">
                        Publication du NIST définissant les bonnes pratiques de configuration
                        des firewalls. Couvre : principe du moindre privilège (any-to-any interdit),
                        protocoles non chiffrés (Telnet, FTP), gestion des règles.
                    </div>
                    <div class="methodo-checks">
                        <span class="methodo-check-tag" style="border-color:#fa194f;">Any-to-Any</span>
                        <span class="methodo-check-tag" style="border-color:#fa194f;">Telnet</span>
                        <span class="methodo-check-tag" style="border-color:#ff9500;">FTP</span>
                        <span class="methodo-check-tag" style="border-color:#f5c518;">SNMP externe</span>
                    </div>
                </div>

                <div class="methodo-ref-block">
                    <div class="methodo-ref-title">
                        <span class="methodo-ref-badge" style="background:#0d4f3c;">CIS</span>
                        Controls v8 — Control 12 &amp; 13
                    </div>
                    <div class="methodo-ref-desc">
                        Le CIS Control 12 (Gestion de l'infrastructure réseau) impose de bloquer
                        les services non nécessaires sur les interfaces exposées.
                        Le Control 13 (Surveillance réseau) impose le logging des règles sensibles.
                    </div>
                    <div class="methodo-checks">
                        <span class="methodo-check-tag" style="border-color:#fa194f;">SMB/NetBIOS WAN</span>
                        <span class="methodo-check-tag" style="border-color:#ff9500;">RDP WAN</span>
                        <span class="methodo-check-tag" style="border-color:#00e5ff;">Logging absent</span>
                    </div>
                </div>

                <div class="methodo-ref-block">
                    <div class="methodo-ref-title">
                        <span class="methodo-ref-badge" style="background:#1c3a1c;">ANSSI</span>
                        Guide de sécurisation des pare-feux
                    </div>
                    <div class="methodo-ref-desc">
                        L'Agence Nationale de la Sécurité des Systèmes d'Information recommande
                        d'interdire tout service d'administration (SSH, RDP, SNMP) depuis Internet,
                        de journaliser tous les flux autorisés, et d'éliminer les règles obsolètes.
                    </div>
                    <div class="methodo-checks">
                        <span class="methodo-check-tag" style="border-color:#ff9500;">SSH WAN</span>
                        <span class="methodo-check-tag" style="border-color:#ff9500;">RDP WAN</span>
                        <span class="methodo-check-tag" style="border-color:#f5c518;">SNMP v1/v2</span>
                        <span class="methodo-check-tag" style="border-color:#00e5ff;">Règles désactivées</span>
                    </div>
                </div>

                <div class="methodo-ref-block">
                    <div class="methodo-ref-title">
                        <span class="methodo-ref-badge" style="background:#4a1a1a;">CVE</span>
                        Vulnérabilités critiques connues
                    </div>
                    <div class="methodo-ref-desc">
                        Certains checks ciblent des vecteurs d'attaque liés à des CVE historiques
                        majeurs : <b>EternalBlue / MS17-010</b> (SMB port 445 → WannaCry, NotPetya),
                        <b>BlueKeep CVE-2019-0708</b> (RDP non patché → exécution de code à distance).
                    </div>
                    <div class="methodo-checks">
                        <span class="methodo-check-tag" style="border-color:#fa194f;">SMB 445 WAN</span>
                        <span class="methodo-check-tag" style="border-color:#ff9500;">RDP 3389 WAN</span>
                    </div>
                </div>

                <div class="methodo-ref-block">
                    <div class="methodo-ref-title">
                        <span class="methodo-ref-badge" style="background:#2a1a4a;">PCI-DSS</span>
                        Requirement 1 — Firewall Configuration
                    </div>
                    <div class="methodo-ref-desc">
                        La norme PCI-DSS impose des règles strictes pour les firewalls protégeant
                        les environnements de traitement de données de cartes : interdiction des règles
                        trop permissives, documentation de chaque règle, révision régulière.
                    </div>
                    <div class="methodo-checks">
                        <span class="methodo-check-tag" style="border-color:#fa194f;">Any-to-Any</span>
                        <span class="methodo-check-tag" style="border-color:#00e5ff;">Règles sans nom</span>
                        <span class="methodo-check-tag" style="border-color:#00e5ff;">Doublons</span>
                    </div>
                </div>

                <div class="methodo-ref-block">
                    <div class="methodo-ref-title">
                        <span class="methodo-ref-badge" style="background:#1a3a4a;">NIST</span>
                        SP 800-92 — Log Management
                    </div>
                    <div class="methodo-ref-desc">
                        Définit les exigences de journalisation pour la réponse aux incidents.
                        Les règles de filtrage autorisant du trafic sans logging rendent
                        impossible toute investigation forensique post-incident.
                    </div>
                    <div class="methodo-checks">
                        <span class="methodo-check-tag" style="border-color:#00e5ff;">Logging absent</span>
                    </div>
                </div>

            </div>

            <div class="methodo-footer">
                <span class="dim">
                    ℹ L'audit NETMORPH est un outil d'aide à la décision.
                    Il ne remplace pas un audit de sécurité complet réalisé par un expert certifié.
                    Les findings sont basés sur l'analyse statique du fichier XML de configuration.
                </span>
            </div>
        </div>
    </div>

    <!-- Findings -->
    <div class="gx-card" style="margin-top:24px;">
        <div class="card-header">
            📋 Findings détaillés
            <span class="dim" style="font-weight:400; text-transform:none; letter-spacing:0;">
                — {len([f for f in findings if f['severity'] != 'INFO'])} problème(s) détecté(s)
            </span>
        </div>
        <div class="audit-findings-list">
            {cards_html}
        </div>
    </div>"""


def get_ui(data=None, mig_state=None, audit_results=None):
    """
    Génère le corps HTML de l'application.

    Args:
        data      : dict retourné par get_dashboard_data() — None si aucun fichier chargé
        mig_state : dict {"src_path", "src_type", "src_name"} — état du wizard de migration

    Returns:
        str HTML (sans <html>/<head>/<body> — injecté directement dans le template)
    """
    if mig_state is None:
        mig_state = {}

    # ─── Écran d'accueil (aucun fichier chargé) ───────────────────────────────
    if not data:
        return """
        <div class="welcome-screen">
            <div class="welcome-bg-grid"></div>
            <div class="gx-card welcome-card">
                <div class="welcome-logo" onerror="">
                    <img src="logo.png" alt="NETMORPH"
                         style="max-width:220px; filter:drop-shadow(0 0 18px #00e5ff);"
                         onerror="this.outerHTML='<div class=\\'logo-text\\'>&lt;/NETMORPH&gt;</div>'">
                </div>
                <p class="welcome-sub">DUAL ENGINE · WATCHGUARD &amp; PFSENSE</p>
                <p class="welcome-desc">
                    Importez une configuration XML pour analyser, éditer<br>
                    et migrer vos règles de pare-feu.
                </p>
                <button class="gx-btn btn-glow" onclick="window.location.href='netmorph://import'">
                    📂 &nbsp;CHARGER UNE CONFIGURATION
                </button>
                <div class="welcome-badges">
                    <span class="fw-badge">WatchGuard Fireware</span>
                    <span class="fw-badge">pfSense CE / Plus</span>
                </div>
            </div>
        </div>"""

    # ─── Génération des données pour le dashboard ─────────────────────────────
    alias_opts = "".join(
        f'<option value="{a}">{a}</option>' for a in data["aliases"]
    )

    is_wg = data.get("is_wg", True)

    # ─── Dropdown interfaces pour le formulaire de règle ──────────────────────
    # WatchGuard : value = nom d'interface (ex: "Trusted"), JS pré-remplit Source
    # pfSense    : value = clé XML (ex: "lan", "wan"), envoyée à engine.py
    if is_wg:
        iface_opts = "".join(
            f'<option value="{i["if_key"]}">'
            f'{i["name"]}'
            f'{(" — " + i["if_dev"]) if i["if_dev"] else ""}'
            f' ({i["ip"]})</option>'
            for i in data["itf"]
        ) or '<option value="">Aucune interface détectée</option>'
    else:
        iface_opts = "".join(
            f'<option value="{i["if_key"]}">'
            f'{i["name"]} — {i["if_dev"]} ({i["ip"]})</option>'
            for i in data["itf"]
        ) or '<option value="lan">LAN (défaut)</option>'

    # ─── Sélecteur de port pour le bloc "Port Destination" pfSense ────────────
    # Défini ICI (avant le f-string src_dst_html qui l'utilise) pour éviter UnboundLocalError.
    # Valeur = numéro de port, sauf "any" = "" et "other" = custom.
    _PORT_ENTRIES = sorted([
        ("BGP",               "179"),  ("CVSup",            "5999"),
        ("DNS",               "53"),   ("DNS over TLS",     "853"),
        ("FTP",               "21"),   ("HBCI",             "3000"),
        ("HTTP",              "80"),   ("HTTPS",            "443"),
        ("IDENT/AUTH",        "113"),  ("ICQ",              "5190"),
        ("IMAP",              "143"),  ("IMAP/S",           "993"),
        ("IPsec NAT-T",       "4500"), ("ISAKMP",           "500"),
        ("L2TP",              "1701"), ("LDAP",             "389"),
        ("LDAP/S",            "636"),  ("MMS/TCP",          "1755"),
        ("MMS/UDP",           "7000"), ("MS DS",            "445"),
        ("MS RDP",            "3389"), ("MS SQL Server",    "1433"),
        ("MS WINS",           "1512"), ("MSN",              "1863"),
        ("NetBIOS-DGM",       "138"),  ("NetBIOS-NS",       "137"),
        ("NetBIOS-SSN",       "139"),  ("NNTP",             "119"),
        ("NTP",               "123"),  ("OpenVPN",          "1194"),
        ("Oracle SQL*Net",    "1521"), ("POP3",             "110"),
        ("POP3/S",            "995"),  ("PPTP",             "1723"),
        ("RADIUS",            "1812"), ("RADIUS accounting","1813"),
        ("RTP",               "5004"), ("SIP",              "5060"),
        ("SMB",               "445"),  ("SMTP",             "25"),
        ("SMTP/S",            "465"),  ("SNMP",             "161"),
        ("SNMP-Trap",         "162"),  ("SSH",              "22"),
        ("STUN",              "3478"), ("SUBMISSION",       "587"),
        ("Syslog",            "514"),  ("Telnet",           "23"),
        ("Teredo",            "3544"), ("TFTP",             "69"),
    ], key=lambda x: x[0].upper())
    port_sel_opts = (
        '<option value="">any</option>'
        + "".join(
            f'<option value="{p}">{n} ({p})</option>'
            for n, p in _PORT_ENTRIES
        )
        + '<option value="other">(other)</option>'
    )

    # ─── Options Source/Destination style pfSense ─────────────────────────────
    # Pour pfSense : chaque interface génère deux options (address + subnets)
    # Pour WatchGuard : bloc alias standard (pas de type selector)
    if not is_wg:
        iface_net_grp = "".join(
            f'<optgroup label="{i["name"]}">'
            f'<option value="{i["if_key"]}ip">{i["name"]} address</option>'
            f'<option value="{i["if_key"]}">{i["name"]} subnets</option>'
            f'</optgroup>'
            for i in data["itf"]
        )
        src_dst_html = f"""
        <div class="pf-addr-block">
            <div class="pf-addr-section">
                <div class="pf-addr-title">Source</div>
                <div class="pf-type-row">
                    <select id="rl-src-type" class="gx-input pf-type-sel"
                            onchange="toggleAddrField('src')">
                        <option value="any">Any</option>
                        <option value="address">Address or Alias</option>
                        {iface_net_grp}
                    </select>
                </div>
                <div id="rl-src-addr-wrap" class="pf-addr-wrap" style="display:none;">
                    <input type="text" id="rl-src-addr" class="gx-input pf-addr-input"
                           placeholder="IP ou alias (ex: 192.168.1.0)">
                    <span class="pf-mask-sep">/</span>
                    <input type="number" id="rl-src-mask" class="gx-input pf-mask-input"
                           placeholder="24" min="0" max="128">
                </div>
                <!-- ── Port Source Range (style pfSense) ── -->
                <div class="pf-port-range-block">
                    <div class="pf-addr-title" style="margin-top:10px;">
                        Source Port Range
                    </div>
                    <div class="pf-port-range-row">
                        <div class="pf-port-col">
                            <span class="pf-sub-label">De</span>
                            <select id="rl-src-pf"
                                    class="gx-input pf-port-sel"
                                    onchange="togglePortCustom('src','pf')">
                                {port_sel_opts}
                            </select>
                            <input type="number" id="rl-src-pf-custom"
                                   class="gx-input pf-port-custom"
                                   placeholder="Port" min="1" max="65535"
                                   style="display:none;">
                        </div>
                        <span class="pf-port-dash">—</span>
                        <div class="pf-port-col">
                            <span class="pf-sub-label">À</span>
                            <select id="rl-src-pt"
                                    class="gx-input pf-port-sel"
                                    onchange="togglePortCustom('src','pt')">
                                {port_sel_opts}
                            </select>
                            <input type="number" id="rl-src-pt-custom"
                                   class="gx-input pf-port-custom"
                                   placeholder="Port" min="1" max="65535"
                                   style="display:none;">
                        </div>
                    </div>
                    <div class="pf-port-hint dim">
                        Laissez "any" pour ne pas filtrer sur le port source.
                    </div>
                </div>
            </div>
            <div class="pf-addr-divider">→</div>
            <div class="pf-addr-section">
                <div class="pf-addr-title">Destination</div>
                <div class="pf-type-row">
                    <select id="rl-dst-type" class="gx-input pf-type-sel"
                            onchange="toggleAddrField('dst')">
                        <option value="any">Any</option>
                        <option value="address">Address or Alias</option>
                        {iface_net_grp}
                    </select>
                </div>
                <div id="rl-dst-addr-wrap" class="pf-addr-wrap" style="display:none;">
                    <input type="text" id="rl-dst-addr" class="gx-input pf-addr-input"
                           placeholder="IP ou alias (ex: 10.0.0.1)">
                    <span class="pf-mask-sep">/</span>
                    <input type="number" id="rl-dst-mask" class="gx-input pf-mask-input"
                           placeholder="32" min="0" max="128">
                </div>

                <!-- ── Port Destination Range (style pfSense) ── -->
                <div class="pf-port-range-block">
                    <div class="pf-addr-title" style="margin-top:10px;">
                        Destination Port Range
                    </div>
                    <div class="pf-port-range-row">
                        <div class="pf-port-col">
                            <span class="pf-sub-label">De</span>
                            <select id="rl-dst-pf"
                                    class="gx-input pf-port-sel"
                                    onchange="togglePortCustom('dst','pf')">
                                {port_sel_opts}
                            </select>
                            <input type="number" id="rl-dst-pf-custom"
                                   class="gx-input pf-port-custom"
                                   placeholder="Port" min="1" max="65535"
                                   style="display:none;">
                        </div>
                        <span class="pf-port-dash">—</span>
                        <div class="pf-port-col">
                            <span class="pf-sub-label">À</span>
                            <select id="rl-dst-pt"
                                    class="gx-input pf-port-sel"
                                    onchange="togglePortCustom('dst','pt')">
                                {port_sel_opts}
                            </select>
                            <input type="number" id="rl-dst-pt-custom"
                                   class="gx-input pf-port-custom"
                                   placeholder="Port" min="1" max="65535"
                                   style="display:none;">
                        </div>
                    </div>
                    <div class="pf-port-hint dim">
                        Laissez "any" pour utiliser le port du service sélectionné ci-dessus.
                    </div>
                </div>
            </div>
        </div>"""
    else:
        # WatchGuard : source et destination via alias dropdowns
        src_dst_html = f"""
        <div class="field-row">
            <div class="field-col">
                <label>Source <span class="dim">(alias WG)</span></label>
                <select id="rl-src" class="gx-input">{alias_opts}</select>
            </div>
            <div class="field-arrow">→</div>
            <div class="field-col">
                <label>Destination <span class="dim">(alias WG)</span></label>
                <select id="rl-dst" class="gx-input">{alias_opts}</select>
            </div>
        </div>"""

    itf_rows = "".join(
        f"<tr><td><span class='hl'>{i['name']}</span></td><td class='dim'>{i['ip']}</td></tr>"
        for i in data["itf"]
    )

    # ─── Tableau des règles existantes avec bouton de suppression (pfSense only) ──
    if not is_wg:
        def _del_row(p):
            action_cls = "badge-allowed" if p["action"].lower() in ("allowed", "allow") else "badge-denied"
            return (
                f"<tr>"
                f"<td class='dim' style='font-size:11px;'>{p.get('interface','—')}</td>"
                f"<td><span class='{action_cls}' style='font-size:10px;'>{p['action']}</span></td>"
                f"<td class='svc-cell' style='font-size:11px;'>{p['service']}</td>"
                f"<td class='dim' style='font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'>"
                f"{p['from']} → {p['to']}</td>"
                f"<td style='max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;'>{p['name']}</td>"
                f"<td><button class='del-btn' onclick=\"delRule({p['idx']})\" title='Supprimer'>✕</button></td>"
                f"</tr>"
            )
        existing_rules_table = f"""
        <div class="gx-card" style="margin-top:24px;">
            <div class="card-header" style="display:flex;justify-content:space-between;align-items:center;">
                <span>🗂️ Règles existantes <span class="dim">({len(data["pol"])} au total)</span></span>
            </div>
            <div style="max-height:320px;overflow-y:auto;">
            <table>
                <thead>
                    <tr>
                        <th>Iface</th><th>Action</th><th>Service</th>
                        <th>Flux</th><th>Nom</th><th style="width:38px;"></th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(_del_row(p) for p in data["pol"])
                      if data["pol"] else
                      "<tr><td colspan='6' class='empty-row'>Aucune règle</td></tr>"}
                </tbody>
            </table>
            </div>
        </div>"""
    else:
        existing_rules_table = ""

    def _pol_row(p):
        nat_info  = p.get("nat", "")
        nat_badge = (
            f"<span class='badge-nat' title='SNAT → {nat_info}'>&#x21AA; {nat_info}</span>"
            if nat_info else ""
        )
        action_cls = "badge-allowed" if p["action"].lower() == "allow" else "badge-denied"
        return (
            f"<tr>"
            f"<td>{p['name']} {nat_badge}</td>"
            f"<td><span class='{action_cls}'>{p['action']}</span></td>"
            f"<td class='svc-cell'>{p['service']}</td>"
            f"<td class='dim'>{p['from']} → {p['to']}</td>"
            f"</tr>"
        )

    pol_rows = "".join(_pol_row(p) for p in data["pol"][-15:])
    nat_list = data.get("nat", [])
    nat_rows = "".join(
        f"<tr>"
        f"<td><span class='hl'>{n['name']}</span></td>"
        f"<td><span class='badge-nat'>{n['type']}</span></td>"
        f"<td class='dim'>{n['ext']}</td>"
        f"<td class='dim'>→ {n['int']}</td>"
        f"</tr>"
        for n in nat_list
    ) or "<tr><td colspan='4' class='empty-row'>Aucune règle NAT détectée</td></tr>"

    # Infos système (sidebar bas)
    sys_name = (
        f"{data['sys']['hostname']} · {data['sys']['model']}"
        if data["is_wg"]
        else f"{data['sys']['hostname']}.{data['sys']['model']}"
    )
    fw_label = data["fw_type"]
    fw_icon  = "🔴" if data["is_wg"] else "🟦"

    # Stats rapides
    n_rules = len(data["pol"])
    n_itf   = len(data["itf"])
    n_nat   = len(nat_list)
    n_alias = len(data["aliases"])

    # ─── Dropdown Services (liste complète pfSense-compatible) ───────────────
    svc_opts = (
        '<optgroup label="Web / Transfert">'
        '<option value="HTTP">HTTP (80)</option>'
        '<option value="HTTPS">HTTPS (443)</option>'
        '<option value="FTP">FTP (21)</option>'
        '<option value="TFTP">TFTP (69)</option>'
        '<option value="CVSup">CVSup (5999)</option>'
        '</optgroup>'
        '<optgroup label="DNS">'
        '<option value="DNS">DNS (53)</option>'
        '<option value="DNS over TLS">DNS over TLS (853)</option>'
        '</optgroup>'
        '<optgroup label="Messagerie">'
        '<option value="SMTP">SMTP (25)</option>'
        '<option value="SMTP/S">SMTP/S (465)</option>'
        '<option value="SUBMISSION">SUBMISSION (587)</option>'
        '<option value="POP3">POP3 (110)</option>'
        '<option value="POP3/S">POP3/S (995)</option>'
        '<option value="IMAP">IMAP (143)</option>'
        '<option value="IMAP/S">IMAP/S (993)</option>'
        '<option value="NNTP">NNTP (119)</option>'
        '<option value="MSN">MSN (1863)</option>'
        '<option value="ICQ">ICQ (5190)</option>'
        '</optgroup>'
        '<optgroup label="Accès distant">'
        '<option value="SSH">SSH (22)</option>'
        '<option value="Telnet">Telnet (23)</option>'
        '<option value="RDP">MS RDP (3389)</option>'
        '<option value="PPTP">PPTP (1723)</option>'
        '</optgroup>'
        '<optgroup label="Annuaire / Auth">'
        '<option value="LDAP">LDAP (389)</option>'
        '<option value="LDAP/S">LDAP/S (636)</option>'
        '<option value="RADIUS">RADIUS (1812)</option>'
        '<option value="RADIUS accounting">RADIUS accounting (1813)</option>'
        '<option value="IDENT/AUTH">IDENT/AUTH (113)</option>'
        '</optgroup>'
        '<optgroup label="Réseau / Infrastructure">'
        '<option value="Ping">Ping — ICMP</option>'
        '<option value="SNMP">SNMP (161)</option>'
        '<option value="SNMP-Trap">SNMP-Trap (162)</option>'
        '<option value="NTP">NTP (123)</option>'
        '<option value="Syslog">Syslog (514)</option>'
        '<option value="BGP">BGP (179)</option>'
        '<option value="GRE">GRE — Proto 47</option>'
        '<option value="STUN">STUN (3478)</option>'
        '<option value="Teredo">Teredo (3544)</option>'
        '</optgroup>'
        '<optgroup label="Microsoft / Windows">'
        '<option value="SMB">SMB / MS DS (445)</option>'
        '<option value="MS WINS">MS WINS (1512)</option>'
        '<option value="NetBIOS-NS">NetBIOS-NS (137)</option>'
        '<option value="NetBIOS-DGM">NetBIOS-DGM (138)</option>'
        '<option value="NetBIOS-SSN">NetBIOS-SSN (139)</option>'
        '<option value="MS-SQL-Server">MS SQL Server (1433)</option>'
        '</optgroup>'
        '<optgroup label="Base de données">'
        '<option value="SQL*Net">Oracle SQL*Net (1521)</option>'
        '<option value="HBCI">HBCI (3000)</option>'
        '</optgroup>'
        '<optgroup label="VoIP / Multimédia">'
        '<option value="SIP">SIP (5060)</option>'
        '<option value="RTP">RTP (5004)</option>'
        '<option value="MMS/TCP">MMS/TCP (1755)</option>'
        '<option value="MMS/UDP">MMS/UDP (7000)</option>'
        '</optgroup>'
        '<optgroup label="VPN">'
        '<option value="OpenVPN">OpenVPN (1194)</option>'
        '<option value="IPsec NAT-T">IPsec NAT-T (4500)</option>'
        '<option value="ISAKMP">ISAKMP (500)</option>'
        '<option value="L2TP">L2TP (1701)</option>'
        '</optgroup>'
        '<optgroup label="Autre">'
        '<option value="custom">Port personnalisé…</option>'
        '</optgroup>'
    )

    # Interfaces physiques parentes (pour la création de VLAN)
    phys_itfs = [
        i for i in data["itf"]
        if i.get("if_dev") and "." not in i["if_dev"] and not i["if_dev"].startswith("vlan")
    ]
    parent_opts = (
        "".join(
            f'<option value="{i["if_dev"]}">{i["name"]} — {i["if_dev"]}</option>'
            for i in phys_itfs
        )
        or '<option value="">Aucune interface physique détectée</option>'
    )

    # ─── Wizard de migration ──────────────────────────────────────────────────
    src_detected = mig_state.get("src_type")
    src_name     = mig_state.get("src_name", "")

    if src_detected:
        # Étape 1 terminée — on affiche la marque détectée + le dropdown de destination
        opposite   = "pfSense" if src_detected == "WatchGuard" else "WatchGuard"
        src_icon   = "🔴" if src_detected == "WatchGuard" else "🟦"
        dst_icon   = "🟦" if src_detected == "WatchGuard" else "🔴"

        step1_html = f"""
        <div class="wizard-step wizard-step-done">
            <div class="step-num done">✓</div>
            <div class="step-body">
                <div class="step-label">Étape 1 — Source détectée</div>
                <div class="step-value">
                    {src_icon} <b>{src_detected}</b>
                    &nbsp;·&nbsp; <span class="dim">{src_name}</span>
                </div>
            </div>
            <button class="gx-btn btn-sm btn-ghost"
                    onclick="window.location.href='netmorph://reset_mig'">✕ Changer</button>
        </div>"""

        step2_html = f"""
        <div class="wizard-step wizard-step-active">
            <div class="step-num active">2</div>
            <div class="step-body">
                <div class="step-label">Étape 2 — Destination</div>
                <div class="step-hint">
                    Choisissez la marque cible. NETMORPH utilisera automatiquement
                    le template depuis <code>template/</code>.
                </div>
            </div>
        </div>

        <div class="dest-selector">
            <label class="dest-label">Vers quelle marque migrer ?</label>
            <div class="dest-cards" id="dest-cards">
                <div class="dest-card dest-card-selected" id="dest-card-{opposite}"
                     onclick="selectDest('{opposite}')">
                    <span class="dest-icon">{dst_icon}</span>
                    <div class="dest-info">
                        <span class="dest-name">{opposite}</span>
                        <span class="dest-tmpl">template/Template_{'pfsense' if opposite == 'pfSense' else 'Firebox'}.xml</span>
                    </div>
                    <span class="dest-check" id="dest-check-{opposite}">✓</span>
                </div>
            </div>
            <button class="gx-btn btn-migrate" style="width:100%; margin-top:18px;"
                    onclick="launchMigration('{opposite}')">
                🚀 &nbsp;MIGRER VERS {opposite.upper()}
            </button>
        </div>"""

    else:
        # Étape 1 non commencée
        step1_html = f"""
        <div class="wizard-step wizard-step-active">
            <div class="step-num active">1</div>
            <div class="step-body">
                <div class="step-label">Étape 1 — Fichier source</div>
                <div class="step-hint">
                    Sélectionnez votre fichier <b>WatchGuard</b> ou <b>pfSense</b> source.
                    NETMORPH détectera automatiquement la marque.
                </div>
            </div>
        </div>
        <button class="gx-btn btn-cyan" style="width:100%; margin-top:20px;"
                onclick="window.location.href='netmorph://pick_source'">
            📂 &nbsp;CHOISIR LE FICHIER SOURCE
        </button>"""

        step2_html = f"""
        <div class="wizard-step wizard-step-locked">
            <div class="step-num locked">2</div>
            <div class="step-body">
                <div class="step-label">Étape 2 — Destination</div>
                <div class="step-hint">
                    Disponible après la détection de la source.<br>
                    Un menu vous proposera la marque compatible avec le template associé.
                </div>
            </div>
        </div>"""

    # ─── HTML principal ───────────────────────────────────────────────────────
    return f"""
    <div class="layout">

        <!-- ═══════ SIDEBAR ═══════ -->
        <div class="sidebar">
            <div class="sidebar-logo">
                <img src="logo.png" alt="NETMORPH"
                     style="max-width:80%; filter:drop-shadow(0 0 6px #00e5ff);"
                     onerror="this.outerHTML='<div class=\\'logo-text\\'>&lt;/NETMORPH&gt;</div>'">
            </div>

            <nav class="sidebar-nav">
                <div class="nav-item active" id="nav-dash"  onclick="tab('dash')">
                    <span class="nav-icon">📊</span> Tableau de bord
                </div>
                <div class="nav-item" id="nav-gen"   onclick="tab('gen')">
                    <span class="nav-icon">🛡️</span> Éditeur Rapide
                </div>
                <div class="nav-item" id="nav-mig"   onclick="tab('mig')">
                    <span class="nav-icon">🔄</span> Migrateur
                    {('<span class="nav-badge">•</span>' if src_detected else '')}
                </div>
                <div class="nav-item" id="nav-audit" onclick="tab('audit')">
                    <span class="nav-icon">🔍</span> Audit Sécurité
                    {(_audit_nav_badge(audit_results) if audit_results else '')}
                </div>
            </nav>

            <div class="sidebar-spacer"></div>

            <div class="sidebar-actions">
                <button class="gx-btn btn-export" onclick="window.location.href='netmorph://export'">
                    💾 &nbsp;Exporter le XML
                </button>
                <p class="export-hint">
                    Importez le fichier exporté dans WatchGuard (System › Backup/Restore)
                    ou pfSense (Diagnostics › Backup &amp; Restore).
                </p>
            </div>

            <div class="sidebar-sysinfo">
                <span class="fw-chip">{fw_icon} {fw_label}</span>
                <span class="sys-name">{sys_name}</span>
                <span class="dim">{n_alias} alias · {n_itf} interfaces</span>
            </div>
        </div>

        <!-- ═══════ CONTENU ═══════ -->
        <div class="content">

            <!-- ─── TABLEAU DE BORD ─── -->
            <div id="section-dash" class="scroll-area">
                <h2 class="section-title">
                    <span class="title-accent">Dashboard</span>
                    <span class="title-sub">{fw_label}</span>
                </h2>

                <!-- Stats rapides -->
                <div class="stats-row">
                    <div class="stat-card">
                        <div class="stat-val">{n_rules}</div>
                        <div class="stat-label">Règles</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-val">{n_nat}</div>
                        <div class="stat-label">NAT / Port-Fwd</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-val">{n_itf}</div>
                        <div class="stat-label">Interfaces</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-val">{n_alias}</div>
                        <div class="stat-label">Alias</div>
                    </div>
                </div>

                <!-- Topologie + Politiques -->
                <div class="grid-2">
                    <div class="gx-card">
                        <div class="card-header">🌐 Topologie réseau</div>
                        <table>
                            <thead><tr><th>Interface</th><th>Adresse IP</th></tr></thead>
                            <tbody>{itf_rows}</tbody>
                        </table>
                    </div>
                    <div class="gx-card">
                        <div class="card-header">📋 Dernières politiques</div>
                        <table>
                            <thead>
                                <tr><th>Règle</th><th>Action</th><th>Service</th><th>Flux</th></tr>
                            </thead>
                            <tbody>{pol_rows}</tbody>
                        </table>
                    </div>
                </div>

                <!-- NAT -->
                <div class="gx-card" style="margin-top:24px">
                    <div class="card-header">🔀 NAT &amp; Port Forwarding</div>
                    <table>
                        <thead>
                            <tr><th>Nom</th><th>Type</th><th>Externe</th><th>Interne</th></tr>
                        </thead>
                        <tbody>{nat_rows}</tbody>
                    </table>
                </div>
            </div>

            <!-- ─── ÉDITEUR RAPIDE ─── -->
            <div id="section-gen" class="scroll-area" style="display:none;">
                <h2 class="section-title">
                    <span class="title-accent">Éditeur Rapide</span>
                    <span class="title-sub">{fw_label}</span>
                </h2>
                <div class="grid-2">

                    <!-- Nouvelle règle -->
                    <div class="gx-card glow-red">
                        <div class="card-header">🛡️ Nouvelle règle de filtrage</div>
                        <label>Nom de la règle</label>
                        <input type="text" id="rl-n" class="gx-input" placeholder="Ex : ALLOW_WEB_DMZ">

                        <label>Interface</label>
                        <div class="ifc-select-wrap">
                            <select id="rl-ifc" class="gx-input ifc-select"
                                    onchange="onInterfaceChange()">
                                {iface_opts}
                            </select>
                            <span class="ifc-hint" id="rl-ifc-hint"></span>
                        </div>

                        <label>Service</label>
                        <select id="rl-s" class="gx-input" onchange="toggleCustomSvc()">{svc_opts}</select>
                        <input type="number" id="rl-s-custom" class="gx-input"
                               placeholder="Numéro de port (ex : 8080)" min="1" max="65535"
                               style="display:none; margin-top:-12px;">
                        {src_dst_html}
                        <label>Action</label>
                        <select id="rl-a" class="gx-input">
                            <option value="allow">✅ Autoriser</option>
                            <option value="deny">🚫 Bloquer</option>
                        </select>
                        <button class="gx-btn" style="width:100%;" onclick="runRl()">
                            ➕ &nbsp;CRÉER LA RÈGLE
                        </button>
                    </div>

                    <!-- Nouvelle interface -->
                    <div class="gx-card glow-cyan">
                        <div class="card-header">🔌 Nouvelle interface réseau</div>
                        <label>Nom de l'interface</label>
                        <input type="text" id="if-n" class="gx-input" placeholder="Ex : DMZ">
                        <label>Adresse IP</label>
                        <input type="text" id="if-i" class="gx-input" placeholder="Ex : 10.0.50.1 ou 10.0.50.1/24">
                        <label>Type</label>
                        <select id="if-t" class="gx-input" onchange="toggleVlan()">
                            <option value="physical">Interface physique</option>
                            <option value="vlan">VLAN (sous-interface)</option>
                        </select>
                        <div id="phys-fields">
                            <label>N° port physique</label>
                            <input type="number" id="if-portnum" class="gx-input"
                                   placeholder="Ex : 0, 1, 2 …" min="0" max="63">
                        </div>
                        <div id="vlan-fields" style="display:none;">
                            <label>VLAN ID</label>
                            <input type="number" id="if-vid" class="gx-input"
                                   placeholder="Ex : 100" min="1" max="4094">
                            <label>Interface parente</label>
                            <select id="if-parent" class="gx-input">{parent_opts}</select>
                        </div>
                        <button class="gx-btn btn-cyan" style="width:100%;" onclick="runIf()">
                            ➕ &nbsp;CRÉER L'INTERFACE
                        </button>
                    </div>

                </div>
                {existing_rules_table}
            </div>

            <!-- ─── MIGRATEUR ─── -->
            <div id="section-mig" class="scroll-area" style="display:none;">
                <h2 class="section-title">
                    <span class="title-accent">Migrateur Cross-Vendor</span>
                    <span class="title-sub">Traduction sémantique des politiques</span>
                </h2>

                <div class="grid-mig">

                    <!-- Wizard -->
                    <div class="gx-card glow-purple">
                        <div class="card-header">⚙️ Assistant de migration</div>
                        <div class="wizard-info">
                            NETMORPH détecte automatiquement la marque source et
                            ne propose que le type de destination compatible —
                            impossible de migrer WatchGuard → WatchGuard par accident.
                        </div>
                        <div class="wizard-steps">
                            {step1_html}
                            <div class="wizard-connector"></div>
                            {step2_html}
                        </div>
                    </div>

                    <!-- Capacités de traduction -->
                    <div class="gx-card">
                        <div class="card-header">🧠 Ce que NETMORPH traduit</div>
                        <div class="feature-list">
                            <div class="feature-item">
                                <span class="feature-icon">🌐</span>
                                <div>
                                    <b>Alias réseau</b><br>
                                    <span class="dim">Any-External → ANY · Any-Trusted → LAN</span>
                                </div>
                            </div>
                            <div class="feature-item">
                                <span class="feature-icon">⚙️</span>
                                <div>
                                    <b>Services métier</b><br>
                                    <span class="dim">Port interne → RDP, HTTP, DNS… (pas TCP-3389)</span>
                                </div>
                            </div>
                            <div class="feature-item">
                                <span class="feature-icon">🔀</span>
                                <div>
                                    <b>Port Forwarding / SNAT</b><br>
                                    <span class="dim">SNAT WG ↔ NAT pfSense avec liaison automatique</span>
                                </div>
                            </div>
                            <div class="feature-item">
                                <span class="feature-icon">🔒</span>
                                <div>
                                    <b>Protection admin</b><br>
                                    <span class="dim">Ports d'admin jamais écrasés par un NAT migré</span>
                                </div>
                            </div>
                            <div class="feature-item">
                                <span class="feature-icon">🧹</span>
                                <div>
                                    <b>Filtrage des règles système</b><br>
                                    <span class="dim">Règles proxy, WG-IKE, default pfSense ignorées</span>
                                </div>
                            </div>
                        </div>
                    </div>

                </div>
            </div>

            <!-- ─── AUDIT DE SÉCURITÉ ─── -->
            <div id="section-audit" class="scroll-area" style="display:none;">
                {_render_audit_section(audit_results, data)}
            </div>

        </div><!-- /content -->
    </div><!-- /layout -->
    """


# =============================================================================
# CSS
# =============================================================================

def get_css():
    return """<style>
    /* ── Variables ── */
    :root {
        --bg-main:     #08080f;
        --bg-panel:    #0f0f1a;
        --bg-card:     #13131f;
        --bg-card2:    #1a1a28;
        --red-neon:    #fa194f;
        --purple-neon: #9d00ff;
        --cyan-neon:   #00e5ff;
        --green-neon:  #00ff88;
        --orange-neon: #ff9500;
        --text-main:   #dde0f0;
        --text-muted:  #7070a0;
        --border:      #1e1e30;
        --border-hi:   #2a2a42;
    }

    /* ── Reset / Base ── */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: 'Segoe UI', system-ui, sans-serif;
        background: var(--bg-main);
        color: var(--text-main);
        font-size: 14px;
        line-height: 1.5;
    }

    /* Scrollbar personnalisée */
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: #2a2a42; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--purple-neon); }

    /* ── Layout principal ── */
    .layout { display: flex; height: 100vh; overflow: hidden; }
    .content {
        flex: 1;
        overflow-y: auto;
        padding: 36px 44px;
        background: radial-gradient(ellipse at 80% 0%, #14142a 0%, var(--bg-main) 55%);
    }
    .scroll-area { animation: fadeIn 0.25s ease; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }

    /* ── Sidebar ── */
    .sidebar {
        width: 255px;
        min-width: 255px;
        background: var(--bg-panel);
        display: flex;
        flex-direction: column;
        border-right: 1px solid var(--border);
    }
    .sidebar-logo {
        padding: 28px 24px 22px;
        text-align: center;
        border-bottom: 1px solid var(--border);
    }
    .logo-text {
        font-size: 20px;
        font-weight: 900;
        color: white;
        letter-spacing: 3px;
        text-shadow: 0 0 12px var(--cyan-neon);
    }
    .sidebar-nav { padding: 12px 0; }
    .nav-item {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 14px 22px;
        cursor: pointer;
        font-size: 14px;
        font-weight: 500;
        color: var(--text-muted);
        border-left: 3px solid transparent;
        transition: all 0.2s;
        position: relative;
    }
    .nav-item:hover { color: var(--text-main); background: rgba(255,255,255,0.04); }
    .nav-item.active {
        color: white;
        background: linear-gradient(90deg, rgba(250,25,79,0.12), transparent);
        border-left-color: var(--red-neon);
    }
    .nav-icon { font-size: 15px; }
    .nav-badge {
        position: absolute;
        right: 16px;
        top: 50%;
        transform: translateY(-50%);
        width: 8px; height: 8px;
        background: var(--cyan-neon);
        border-radius: 50%;
        box-shadow: 0 0 6px var(--cyan-neon);
    }
    .sidebar-spacer { flex: 1; }
    .sidebar-actions { padding: 16px; border-top: 1px solid var(--border); }
    .btn-export {
        width: 100%;
        background: linear-gradient(90deg, #00995c, #00e5ff);
        font-size: 13px;
        padding: 12px;
        box-shadow: 0 4px 14px rgba(0,229,255,0.15);
    }
    .export-hint {
        margin-top: 10px;
        font-size: 10px;
        color: var(--text-muted);
        line-height: 1.5;
        text-align: center;
    }
    .sidebar-sysinfo {
        padding: 14px 18px;
        font-size: 11px;
        background: #080810;
        border-top: 1px solid var(--border);
        line-height: 1.8;
    }
    .fw-chip {
        display: inline-block;
        font-size: 11px;
        font-weight: 700;
        color: var(--cyan-neon);
        letter-spacing: 0.5px;
    }
    .sys-name { display: block; color: var(--text-main); font-size: 11.5px; }

    /* ── Titres de section ── */
    .section-title {
        display: flex;
        align-items: baseline;
        gap: 12px;
        margin-bottom: 28px;
        padding-left: 16px;
        border-left: 4px solid var(--red-neon);
    }
    .title-accent {
        font-size: 22px;
        font-weight: 300;
        letter-spacing: 1px;
        color: white;
    }
    .title-sub {
        font-size: 13px;
        color: var(--text-muted);
        font-weight: 400;
    }

    /* ── Stats row ── */
    .stats-row {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 16px;
        margin-bottom: 28px;
    }
    .stat-card {
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 18px 20px;
        text-align: center;
        transition: border-color 0.2s, transform 0.2s;
    }
    .stat-card:hover { border-color: var(--purple-neon); transform: translateY(-2px); }
    .stat-val {
        font-size: 30px;
        font-weight: 700;
        color: white;
        letter-spacing: -1px;
    }
    .stat-label {
        font-size: 11px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.8px;
        margin-top: 4px;
    }

    /* ── Cards ── */
    .gx-card {
        background: var(--bg-card);
        padding: 28px;
        border-radius: 10px;
        border: 1px solid var(--border);
        position: relative;
        overflow: hidden;
        box-shadow: 0 8px 28px rgba(0,0,0,0.4);
    }
    .gx-card::after {
        content: '';
        position: absolute;
        top: 0; left: 0;
        width: 100%; height: 2px;
        background: var(--border-hi);
        transition: background 0.3s, box-shadow 0.3s;
    }
    .gx-card:hover::after              { background: var(--purple-neon); box-shadow: 0 0 12px var(--purple-neon); }
    .glow-red:hover::after             { background: var(--red-neon);    box-shadow: 0 0 12px var(--red-neon); }
    .glow-cyan:hover::after            { background: var(--cyan-neon);   box-shadow: 0 0 12px var(--cyan-neon); }
    .glow-purple:hover::after          { background: var(--purple-neon); box-shadow: 0 0 12px var(--purple-neon); }
    .card-header {
        font-size: 13px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: white;
        margin-bottom: 22px;
        padding-bottom: 12px;
        border-bottom: 1px solid var(--border);
    }

    /* ── Grilles ── */
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
    .grid-mig { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; align-items: start; }

    /* ── Tableaux ── */
    table { width: 100%; border-collapse: collapse; }
    th {
        text-align: left;
        padding: 10px 12px;
        font-size: 10px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        color: var(--text-muted);
        border-bottom: 1px solid var(--border);
    }
    td { padding: 11px 12px; border-bottom: 1px solid var(--border); font-size: 13px; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255,255,255,0.025); }
    .empty-row { text-align: center; color: var(--text-muted); padding: 20px; font-style: italic; }
    .svc-cell { color: var(--cyan-neon); font-size: 12px; }

    /* ── Badges ── */
    .hl { color: var(--cyan-neon); font-weight: 600; }
    .dim { color: var(--text-muted); }
    .badge-allowed {
        display: inline-block;
        padding: 2px 9px;
        border-radius: 99px;
        font-size: 11px;
        font-weight: 700;
        background: rgba(0,255,136,0.12);
        color: var(--green-neon);
        border: 1px solid rgba(0,255,136,0.25);
    }
    .badge-denied {
        display: inline-block;
        padding: 2px 9px;
        border-radius: 99px;
        font-size: 11px;
        font-weight: 700;
        background: rgba(250,25,79,0.12);
        color: var(--red-neon);
        border: 1px solid rgba(250,25,79,0.25);
    }
    .badge-nat {
        display: inline-block;
        padding: 2px 9px;
        border-radius: 99px;
        font-size: 11px;
        font-weight: 700;
        background: rgba(255,149,0,0.12);
        color: var(--orange-neon);
        border: 1px solid rgba(255,149,0,0.25);
        margin-left: 6px;
    }

    /* ── Bouton de suppression de règle ── */
    .del-btn {
        background: transparent;
        border: 1px solid rgba(250,25,79,0.35);
        color: var(--red-neon);
        border-radius: 4px;
        padding: 3px 8px;
        font-size: 11px;
        cursor: pointer;
        transition: background 0.15s;
    }
    .del-btn:hover {
        background: rgba(250,25,79,0.15);
    }

    /* ── Formulaires ── */
    label {
        display: block;
        font-size: 11px;
        font-weight: 600;
        color: var(--text-muted);
        margin-bottom: 6px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .gx-input {
        width: 100%;
        background: #0a0a12;
        border: 1px solid var(--border-hi);
        color: white;
        padding: 12px 14px;
        font-size: 13px;
        border-radius: 6px;
        box-sizing: border-box;
        margin-bottom: 18px;
        outline: none;
        transition: border-color 0.2s, box-shadow 0.2s;
        font-family: inherit;
    }
    .gx-input:focus {
        border-color: var(--red-neon);
        box-shadow: 0 0 0 3px rgba(250,25,79,0.15);
    }
    select.gx-input {
        cursor: pointer;
        appearance: none;
        background-image: url("data:image/svg+xml;charset=US-ASCII,%3Csvg xmlns%3D'http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg' width%3D'12' height%3D'12'%3E%3Cpath fill%3D'%239d00ff' d%3D'M6 8L1 3h10z'/%3E%3C%2Fsvg%3E");
        background-repeat: no-repeat;
        background-position: right 14px center;
        padding-right: 36px;
    }
    .field-row { display: flex; gap: 10px; align-items: flex-end; margin-bottom: 18px; }
    .field-col { flex: 1; }
    .field-col .gx-input { margin-bottom: 0; }
    .field-arrow { color: var(--text-muted); padding-bottom: 13px; font-size: 16px; }

    /* ── Interface selector ── */
    .ifc-select-wrap { position: relative; }
    .ifc-select { border-left: 3px solid var(--accent); padding-left: 12px; }
    .ifc-hint {
        display: block;
        font-size: 11px;
        color: var(--accent);
        margin-top: -10px;
        margin-bottom: 14px;
        min-height: 14px;
        letter-spacing: .03em;
    }

    /* ── Source / Destination pfSense-style ── */
    .pf-addr-block {
        display: flex;
        flex-direction: column;
        gap: 6px;
        margin-bottom: 18px;
    }
    .pf-addr-section {
        background: rgba(255,255,255,.03);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 12px 14px 8px;
    }
    .pf-addr-title {
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: .1em;
        color: var(--text-muted);
        margin-bottom: 8px;
    }
    .pf-type-row { display: flex; gap: 8px; align-items: center; }
    .pf-type-sel { flex: 1; margin-bottom: 0; }
    .pf-addr-wrap {
        display: flex;
        align-items: center;
        gap: 6px;
        margin-top: 8px;
    }
    .pf-addr-input { flex: 1; margin-bottom: 0 !important; }
    .pf-mask-sep { color: var(--text-muted); font-size: 18px; font-weight: 300; }
    .pf-mask-input {
        width: 64px !important;
        min-width: 0;
        text-align: center;
        margin-bottom: 0 !important;
        flex-shrink: 0;
    }
    .pf-addr-divider {
        text-align: center;
        color: var(--accent);
        font-size: 18px;
        line-height: 1;
        margin: 2px 0;
    }
    .pf-port-toggle { margin-top: 8px; }
    .pf-port-link {
        font-size: 11px;
        color: var(--text-muted);
        cursor: pointer;
        text-decoration: underline dotted;
    }
    .pf-port-link:hover { color: var(--accent); }

    /* ── Destination Port Range ── */
    .pf-port-range-block { margin-top: 4px; }
    .pf-port-range-row {
        display: flex;
        align-items: flex-end;
        gap: 8px;
        margin-top: 4px;
    }
    .pf-port-col {
        display: flex;
        flex-direction: column;
        flex: 1;
        gap: 4px;
    }
    .pf-sub-label {
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: .08em;
        color: var(--text-muted);
    }
    .pf-port-sel { margin-bottom: 0 !important; }
    .pf-port-custom { margin-bottom: 0 !important; margin-top: 4px !important; }
    .pf-port-dash {
        color: var(--text-muted);
        font-size: 16px;
        padding-bottom: 8px;
    }
    .pf-port-hint {
        font-size: 11px;
        margin-top: 6px;
    }

    /* ── Boutons ── */
    .gx-btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 6px;
        background: linear-gradient(90deg, var(--red-neon), var(--purple-neon));
        border: none;
        padding: 13px 20px;
        color: white;
        font-weight: 700;
        letter-spacing: 0.8px;
        border-radius: 6px;
        cursor: pointer;
        transition: all 0.2s;
        text-transform: uppercase;
        font-size: 13px;
        box-shadow: 0 4px 16px rgba(250,25,79,0.25);
        font-family: inherit;
    }
    .gx-btn:hover {
        filter: brightness(1.15);
        transform: translateY(-1px);
        box-shadow: 0 6px 22px rgba(157,0,255,0.45);
    }
    .btn-cyan {
        background: linear-gradient(90deg, #0088ff, var(--cyan-neon));
        box-shadow: 0 4px 16px rgba(0,229,255,0.2);
    }
    .btn-cyan:hover { box-shadow: 0 6px 22px rgba(0,229,255,0.45); }
    .btn-migrate {
        background: linear-gradient(90deg, var(--purple-neon), #ff007f);
        box-shadow: 0 4px 16px rgba(157,0,255,0.3);
    }
    .btn-migrate:hover { box-shadow: 0 6px 22px rgba(157,0,255,0.55); }
    .btn-glow {
        box-shadow: 0 0 24px rgba(250,25,79,0.4);
        padding: 16px 32px;
        font-size: 14px;
    }
    .btn-ghost {
        background: transparent;
        border: 1px solid var(--border-hi);
        color: var(--text-muted);
        font-size: 11px;
        padding: 6px 12px;
        box-shadow: none;
        text-transform: none;
        letter-spacing: 0;
        font-weight: 500;
        flex-shrink: 0;
    }
    .btn-ghost:hover {
        border-color: var(--red-neon);
        color: white;
        transform: none;
        box-shadow: none;
        filter: none;
    }
    .btn-sm { padding: 8px 14px; font-size: 12px; }

    /* ── Wizard de migration ── */
    .wizard-info {
        font-size: 12.5px;
        color: var(--text-muted);
        line-height: 1.7;
        margin-bottom: 24px;
        padding: 14px 16px;
        background: rgba(255,255,255,0.03);
        border-radius: 6px;
        border-left: 3px solid var(--purple-neon);
    }
    .wizard-steps { display: flex; flex-direction: column; gap: 0; }
    .wizard-connector {
        width: 2px;
        height: 14px;
        background: var(--border-hi);
        margin-left: 19px;
    }
    .wizard-step {
        display: flex;
        align-items: flex-start;
        gap: 14px;
        padding: 14px 16px;
        border-radius: 8px;
        border: 1px solid var(--border);
        transition: border-color 0.2s;
    }
    .wizard-step-active  { border-color: var(--cyan-neon); background: rgba(0,229,255,0.04); }
    .wizard-step-done    { border-color: var(--green-neon); background: rgba(0,255,136,0.04); }
    .wizard-step-locked  { opacity: 0.45; }
    .step-num {
        width: 32px; height: 32px;
        border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        font-size: 13px;
        font-weight: 700;
        flex-shrink: 0;
    }
    .step-num.active { background: var(--cyan-neon);   color: #000; }
    .step-num.done   { background: var(--green-neon);  color: #000; }
    .step-num.locked { background: var(--border-hi);   color: var(--text-muted); }
    .step-body { flex: 1; min-width: 0; }
    .step-label { font-size: 12px; font-weight: 700; color: white; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
    .step-value { font-size: 13px; color: var(--text-main); }
    .step-hint  { font-size: 12px; color: var(--text-muted); line-height: 1.5; }

    /* ── Feature list (onglet migration) ── */
    .feature-list { display: flex; flex-direction: column; gap: 16px; }
    .feature-item { display: flex; gap: 14px; align-items: flex-start; }
    .feature-icon { font-size: 20px; flex-shrink: 0; margin-top: 2px; }
    .feature-item b { font-size: 13px; color: white; display: block; margin-bottom: 2px; }
    .feature-item .dim { font-size: 12px; }

    /* ── Destination selector (wizard étape 2) ── */
    .dest-selector { margin-top: 20px; }
    .dest-label {
        font-size: 11px;
        font-weight: 700;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 10px;
        display: block;
    }
    .dest-cards { display: flex; flex-direction: column; gap: 10px; }
    .dest-card {
        display: flex;
        align-items: center;
        gap: 14px;
        padding: 14px 16px;
        border-radius: 8px;
        border: 2px solid var(--border-hi);
        cursor: pointer;
        transition: all 0.2s;
        background: rgba(255,255,255,0.02);
    }
    .dest-card:hover { border-color: var(--cyan-neon); background: rgba(0,229,255,0.05); }
    .dest-card-selected { border-color: var(--cyan-neon) !important; background: rgba(0,229,255,0.07) !important; }
    .dest-icon { font-size: 22px; flex-shrink: 0; }
    .dest-info { flex: 1; min-width: 0; }
    .dest-name { display: block; font-size: 14px; font-weight: 700; color: white; }
    .dest-tmpl { display: block; font-size: 11px; color: var(--text-muted); font-family: monospace; margin-top: 2px; }
    .dest-check {
        width: 22px; height: 22px;
        background: var(--cyan-neon);
        color: #000;
        border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        font-size: 12px;
        font-weight: 900;
        flex-shrink: 0;
    }
    code {
        font-family: 'Consolas', monospace;
        font-size: 11px;
        background: rgba(255,255,255,0.06);
        padding: 1px 5px;
        border-radius: 3px;
        color: var(--cyan-neon);
    }

    /* ── Welcome screen ── */
    .welcome-screen {
        height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        background: radial-gradient(ellipse at center, #14142a 0%, var(--bg-main) 65%);
        position: relative;
        overflow: hidden;
    }
    .welcome-bg-grid {
        position: absolute;
        inset: 0;
        background-image:
            linear-gradient(rgba(0,229,255,0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,229,255,0.03) 1px, transparent 1px);
        background-size: 40px 40px;
        mask-image: radial-gradient(ellipse at center, black 30%, transparent 75%);
    }
    .welcome-card {
        max-width: 500px;
        width: 90%;
        text-align: center;
        z-index: 1;
        padding: 48px 40px;
        border-color: var(--border-hi);
    }
    .welcome-sub {
        color: var(--cyan-neon);
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 3px;
        margin: 18px 0 12px;
    }
    .welcome-desc {
        color: var(--text-muted);
        font-size: 13px;
        line-height: 1.7;
        margin-bottom: 32px;
    }
    .welcome-badges {
        display: flex;
        gap: 10px;
        justify-content: center;
        margin-top: 22px;
    }
    .fw-badge {
        font-size: 11px;
        color: var(--text-muted);
        border: 1px solid var(--border-hi);
        border-radius: 99px;
        padding: 4px 12px;
    }

    /* ── Audit de sécurité ── */
    .nav-badge-red {
        background: var(--red-neon) !important;
        box-shadow: 0 0 6px var(--red-neon) !important;
        width: auto !important;
        height: auto !important;
        border-radius: 99px !important;
        padding: 0 5px !important;
        font-size: 10px !important;
        font-weight: 900 !important;
        color: white !important;
    }
    .grid-audit {
        display: grid;
        grid-template-columns: 260px 1fr;
        gap: 24px;
        margin-bottom: 24px;
        align-items: start;
    }
    /* Score circulaire */
    .audit-score-block {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 16px;
        padding: 8px 0;
    }
    .audit-score-circle {
        position: relative;
        width: 120px;
        height: 120px;
    }
    .audit-score-svg {
        width: 120px;
        height: 120px;
        transform: rotate(-90deg);
    }
    .score-track {
        fill: none;
        stroke: var(--border-hi);
        stroke-width: 8;
    }
    .score-fill {
        fill: none;
        stroke-width: 8;
        stroke-linecap: round;
        transition: stroke-dasharray 0.6s ease;
    }
    .audit-score-inner {
        position: absolute;
        inset: 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
    }
    .audit-score-num {
        font-size: 30px;
        font-weight: 900;
        letter-spacing: -2px;
        line-height: 1;
    }
    .audit-score-label {
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-top: 2px;
    }
    .audit-score-legend { text-align: center; }
    .audit-score-title {
        font-size: 12px;
        font-weight: 700;
        color: white;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 2px;
    }
    .audit-score-fw {
        font-size: 11px;
        color: var(--text-muted);
        margin-bottom: 12px;
    }
    .audit-breakdown {
        display: flex;
        gap: 14px;
        justify-content: center;
        flex-wrap: wrap;
    }
    .audit-breakdown-item {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 2px;
    }
    .bk-num   { font-size: 20px; font-weight: 700; line-height: 1; }
    .bk-label { font-size: 9px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.7; }

    /* Légende sévérités */
    .audit-legend-list { display: flex; flex-direction: column; gap: 14px; }
    .audit-legend-item { display: flex; align-items: flex-start; gap: 12px; font-size: 12px; line-height: 1.5; }
    .audit-sev-dot {
        width: 10px; height: 10px;
        border-radius: 50%;
        flex-shrink: 0;
        margin-top: 3px;
    }

    /* Groupe de findings */
    .audit-group-header {
        font-size: 10px;
        font-weight: 900;
        text-transform: uppercase;
        letter-spacing: 2px;
        margin: 18px 0 8px;
        padding-left: 4px;
    }
    .audit-group-header:first-child { margin-top: 0; }

    /* Carte finding individuelle */
    .audit-card {
        border-left: 3px solid var(--border-hi);
        border-radius: 0 6px 6px 0;
        background: var(--bg-card2);
        padding: 12px 16px;
        margin-bottom: 6px;
        transition: background 0.15s;
    }
    .audit-card:hover { background: rgba(255,255,255,0.03); }
    .audit-card-head {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 5px;
        flex-wrap: wrap;
    }
    .audit-card-title {
        font-size: 13px;
        font-weight: 600;
        color: white;
        flex: 1;
        min-width: 0;
    }
    .audit-rule-badge {
        font-size: 10px;
        font-family: 'Consolas', monospace;
        background: rgba(255,255,255,0.06);
        border: 1px solid var(--border-hi);
        border-radius: 4px;
        padding: 1px 7px;
        color: var(--cyan-neon);
        white-space: nowrap;
        max-width: 200px;
        overflow: hidden;
        text-overflow: ellipsis;
    }
    .audit-card-detail {
        font-size: 12px;
        color: var(--text-muted);
        line-height: 1.55;
        padding-left: 20px;
    }
    .audit-findings-list { padding: 4px 0; }

    /* ── Méthodologie ── */
    .methodo-intro {
        font-size: 13px;
        color: var(--text-muted);
        margin-bottom: 20px;
        line-height: 1.6;
    }
    .methodo-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 16px;
        margin-bottom: 18px;
    }
    .methodo-ref-block {
        background: var(--bg-card2);
        border: 1px solid var(--border-hi);
        border-radius: 8px;
        padding: 14px 16px;
    }
    .methodo-ref-title {
        font-size: 12px;
        font-weight: 700;
        color: white;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .methodo-ref-badge {
        font-size: 9px;
        font-weight: 900;
        letter-spacing: 0.5px;
        padding: 2px 6px;
        border-radius: 4px;
        color: white;
        flex-shrink: 0;
    }
    .methodo-ref-desc {
        font-size: 11.5px;
        color: var(--text-muted);
        line-height: 1.55;
        margin-bottom: 10px;
    }
    .methodo-ref-desc b { color: var(--text-main); }
    .methodo-checks {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
    }
    .methodo-check-tag {
        font-size: 10px;
        font-weight: 600;
        font-family: 'Consolas', monospace;
        border: 1px solid var(--border-hi);
        border-radius: 4px;
        padding: 1px 7px;
        color: var(--text-muted);
        background: rgba(255,255,255,0.03);
    }
    .methodo-footer {
        font-size: 11px;
        line-height: 1.6;
        padding: 12px 14px;
        background: rgba(255,255,255,0.02);
        border-radius: 6px;
        border: 1px solid var(--border);
    }
    </style>"""


# =============================================================================
# JS
# =============================================================================

def get_js():
    return """<script>
    /* ── Toggle méthodologie audit ── */
    function toggleMethodo() {
        var body  = document.getElementById('methodo-body');
        var arrow = document.getElementById('methodo-arrow');
        if (!body) return;
        var hidden = body.style.display === 'none';
        body.style.display  = hidden ? 'block' : 'none';
        arrow.style.transform = hidden ? 'rotate(0deg)' : 'rotate(-90deg)';
    }

    /* ── Destination sélectionnée (wizard) ── */
    var _selectedDest = null;

    function selectDest(brand) {
        _selectedDest = brand;
        // Highlight visuel de la carte sélectionnée
        document.querySelectorAll('.dest-card').forEach(function(c) {
            c.classList.remove('dest-card-selected');
        });
        var card = document.getElementById('dest-card-' + brand);
        if (card) card.classList.add('dest-card-selected');
    }

    function launchMigration(fallback) {
        var dest = _selectedDest || fallback;
        if (!dest) return alert('Choisissez une marque de destination.');
        window.location.href = 'netmorph://migrate?dest=' + encodeURIComponent(dest);
    }

    /* ── Navigation entre onglets ── */
    function tab(t) {
        ['dash', 'gen', 'mig', 'audit'].forEach(function(id) {
            var sec = document.getElementById('section-' + id);
            var nav = document.getElementById('nav-' + id);
            if (sec) sec.style.display = (id === t) ? 'block' : 'none';
            if (nav) nav.classList.toggle('active', id === t);
        });
    }

    /* ── Champ port personnalisé ── */
    function toggleCustomSvc() {
        var s = document.getElementById('rl-s').value;
        var el = document.getElementById('rl-s-custom');
        if (el) el.style.display = (s === 'custom') ? 'block' : 'none';
    }

    /* ── Basculer champs VLAN / Physique ── */
    function toggleVlan() {
        var t = document.getElementById('if-t').value;
        var vl = document.getElementById('vlan-fields');
        var ph = document.getElementById('phys-fields');
        if (vl) vl.style.display = (t === 'vlan')     ? 'block' : 'none';
        if (ph) ph.style.display = (t === 'physical') ? 'block' : 'none';
    }

    /* ── Mapping interface WatchGuard → alias source ── */
    var WG_ZONE_TO_ALIAS = {
        "Trusted":  "Any-Trusted",
        "External": "Any-External",
        "Optional": "Any-Optional"
    };

    /* ── Mise à jour automatique de la Source quand l'interface change ── */
    function onInterfaceChange() {
        var ifc     = document.getElementById('rl-ifc').value;
        var hint    = document.getElementById('rl-ifc-hint');
        var srcEl   = document.getElementById('rl-src');

        // Pour WatchGuard : pré-sélectionner l'alias de zone correspondant
        var mapped = WG_ZONE_TO_ALIAS[ifc];
        if (mapped) {
            for (var i = 0; i < srcEl.options.length; i++) {
                if (srcEl.options[i].value === mapped) {
                    srcEl.selectedIndex = i;
                    break;
                }
            }
            hint.textContent = '→ Source auto-remplie : ' + mapped;
        } else if (ifc) {
            // Interface custom WG ou pfSense : indication visuelle uniquement
            hint.textContent = ifc ? ('Interface : ' + ifc) : '';
        } else {
            hint.textContent = '';
        }
    }

    /* ── Affiche / cache le champ adresse selon le type sélectionné ── */
    function toggleAddrField(side) {
        var typeEl = document.getElementById('rl-' + side + '-type');
        var wrap   = document.getElementById('rl-' + side + '-addr-wrap');
        if (!typeEl || !wrap) return;
        // Afficher le champ IP/alias uniquement si "address" est sélectionné
        wrap.style.display = (typeEl.value === 'address') ? 'flex' : 'none';
    }

    /* ── Affiche / cache un champ port custom selon "other" sélectionné ── */
    /* side = 'src' | 'dst', which = 'pf' (from) | 'pt' (to) */
    function togglePortCustom(side, which) {
        var sel = document.getElementById('rl-' + side + '-' + which);
        var inp = document.getElementById('rl-' + side + '-' + which + '-custom');
        if (!sel || !inp) return;
        inp.style.display = (sel.value === 'other') ? 'block' : 'none';
    }

    /* ── Création d'une règle ── */
    function runRl() {
        var n = document.getElementById('rl-n').value.trim();
        var s = document.getElementById('rl-s').value;
        if (!n) return alert('Entrez un nom pour la règle.');
        if (s === 'custom') {
            s = document.getElementById('rl-s-custom').value.trim();
            if (!s) return alert('Entrez un numéro de port.');
        }
        var a   = document.getElementById('rl-a').value;
        var ifc = document.getElementById('rl-ifc') ? document.getElementById('rl-ifc').value : '';

        var url = 'netmorph://add_rule'
            + '?name='      + encodeURIComponent(n)
            + '&action='    + encodeURIComponent(a)
            + '&service='   + encodeURIComponent(s)
            + '&interface=' + encodeURIComponent(ifc);

        // ── Mode pfSense : type selector + adresse + masque + ports ──
        if (document.getElementById('rl-src-type')) {
            var srcType = document.getElementById('rl-src-type').value;
            var srcAddr = srcType === 'address'
                ? document.getElementById('rl-src-addr').value.trim() : '';
            var srcMask = srcType === 'address'
                ? document.getElementById('rl-src-mask').value.trim() : '';

            // ── Port Source Range (From / To) ──
            var srcPfSel = document.getElementById('rl-src-pf');
            var srcPtSel = document.getElementById('rl-src-pt');
            var srcPortFrom = '', srcPortTo = '';
            if (srcPfSel) {
                srcPortFrom = srcPfSel.value === 'other'
                    ? (document.getElementById('rl-src-pf-custom').value.trim())
                    : srcPfSel.value;
                srcPortTo = srcPtSel.value === 'other'
                    ? (document.getElementById('rl-src-pt-custom').value.trim())
                    : srcPtSel.value;
            }
            // Construire src_port au format pfSense (vide = any)
            var srcPort = '';
            if (srcPortFrom && srcPortFrom !== 'any') {
                srcPort = (srcPortTo && srcPortTo !== 'any' && srcPortTo !== srcPortFrom)
                    ? srcPortFrom + ':' + srcPortTo
                    : srcPortFrom;
            }

            var dstType = document.getElementById('rl-dst-type').value;
            var dstAddr = dstType === 'address'
                ? document.getElementById('rl-dst-addr').value.trim() : '';
            var dstMask = dstType === 'address'
                ? document.getElementById('rl-dst-mask').value.trim() : '';

            // ── Port Destination Range (From / To) ──
            var pfSel = document.getElementById('rl-dst-pf');
            var ptSel = document.getElementById('rl-dst-pt');
            var dstPortFrom = '', dstPortTo = '';
            if (pfSel) {
                dstPortFrom = pfSel.value === 'other'
                    ? (document.getElementById('rl-dst-pf-custom').value.trim())
                    : pfSel.value;
                dstPortTo = ptSel.value === 'other'
                    ? (document.getElementById('rl-dst-pt-custom').value.trim())
                    : ptSel.value;
            }

            if (srcType === 'address' && !srcAddr)
                return alert('Entrez une adresse ou un alias pour la source.');
            if (dstType === 'address' && !dstAddr)
                return alert('Entrez une adresse ou un alias pour la destination.');

            url += '&src_type='      + encodeURIComponent(srcType)
                +  '&src_addr='      + encodeURIComponent(srcAddr)
                +  '&src_mask='      + encodeURIComponent(srcMask)
                +  '&src_port='      + encodeURIComponent(srcPort)
                +  '&dst_type='      + encodeURIComponent(dstType)
                +  '&dst_addr='      + encodeURIComponent(dstAddr)
                +  '&dst_mask='      + encodeURIComponent(dstMask)
                +  '&dst_port_from=' + encodeURIComponent(dstPortFrom)
                +  '&dst_port_to='   + encodeURIComponent(dstPortTo);

        // ── Mode WatchGuard : alias dropdowns classiques ──
        } else {
            var src = document.getElementById('rl-src').value;
            var dst = document.getElementById('rl-dst').value;
            url += '&from=' + encodeURIComponent(src)
                +  '&to='   + encodeURIComponent(dst);
        }

        window.location.href = url;
    }

    /* ── Suppression d'une règle existante ── */
    function delRule(idx) {
        if (!confirm('Supprimer cette règle ? Cette action est irréversible.')) return;
        window.location.href = 'netmorph://delete_rule?index=' + idx;
    }

    /* ── Création d'une interface ── */
    function runIf() {
        var n = document.getElementById('if-n').value.trim();
        var i = document.getElementById('if-i').value.trim();
        var t = document.getElementById('if-t').value;
        if (!n || !i) return alert("Complétez le nom et l'IP.");
        if (t === 'vlan') {
            var vid    = document.getElementById('if-vid').value.trim();
            var parent = document.getElementById('if-parent').value.trim();
            if (!vid)    return alert('Entrez un VLAN ID.');
            if (!parent) return alert('Aucune interface physique disponible.');
            window.location.href =
                'netmorph://add_if'
                + '?name='    + encodeURIComponent(n)
                + '&ip='      + encodeURIComponent(i)
                + '&type=vlan'
                + '&vlan_id=' + encodeURIComponent(vid)
                + '&parent='  + encodeURIComponent(parent);
        } else {
            var portnum = document.getElementById('if-portnum').value.trim();
            if (portnum === '') return alert("Entrez le numéro du port physique (ex : 0, 1, 2).");
            window.location.href =
                'netmorph://add_if'
                + '?name='     + encodeURIComponent(n)
                + '&ip='       + encodeURIComponent(i)
                + '&type=physical'
                + '&port_num=' + encodeURIComponent(portnum);
        }
    }
    </script>"""


# =============================================================================
# HELPERS (compatibilité avec main.py qui importe get_css_js séparément)
# =============================================================================

def get_css_js():
    """Retourne CSS + JS concaténés (compatibilité avec anciens imports)."""
    return get_css() + get_js()
