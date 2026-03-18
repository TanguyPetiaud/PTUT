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
                    <div class="gx-card"><div class="card-header">Dernières Politiques Injectées</div><table><thead><tr><th>Règle</th><th>Action</th><th>Service</th><th>Flux</th></tr></thead><tbody>{pol_rows}</tbody></table></div>
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

def get_css_js():
    return """<style>
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
    </style>
    <script>
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