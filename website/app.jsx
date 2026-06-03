/* HoneyMind — shell : routing, thème, DataProvider (fetch IOC API + Loki) */

const D = window.HM_DATA;

// ── Utilitaires ────────────────────────────────────────────────────────────────

async function fetchSafe(url, fallback, timeoutMs = 12000) {
  try {
    return await fetchJson(url, timeoutMs);
  } catch (e) {
    console.warn(`[HM] fetch failed [${url}]:`, e.message);
    return fallback;
  }
}

async function fetchJson(url, timeoutMs = 12000) {
  const ctrl = new AbortController();
  const tid = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { signal: ctrl.signal });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } catch (e) {
    throw new Error(`Impossible de charger ${url}: ${e.message}`);
  } finally {
    clearTimeout(tid);
  }
}

// Jitter déterministe à partir de l'IP (évite que tous les IPs d'un pays se superposent)
function ipJitter(ip, axis) {
  let h = 0;
  for (let i = 0; i < ip.length; i++) h = (Math.imul(h, 31) + ip.charCodeAt(i)) >>> 0;
  const val = ((h + axis * 1234567) >>> 0) / 4294967296;
  return (val - 0.5) * (axis === 0 ? 3 : 5);
}

// ── Parsing STIX 2.1 bundle → IOCs ────────────────────────────────────────────

function parseStixBundle(bundle) {
  const result = { ips: [], domains: [], urls: [], hashes: [] };
  if (!bundle?.objects) return result;
  for (const obj of bundle.objects) {
    if (obj.type !== 'indicator') continue;
    const type = obj.x_honeymind_ioc_type;
    const matches = [...(obj.pattern || '').matchAll(/'([^']+)'/g)];
    const val = matches.length ? matches[matches.length - 1][1] : null;
    if (!val) continue;
    if      (type === 'ipv4-addr'   && !result.ips.includes(val))     result.ips.push(val);
    else if (type === 'domain-name' && !result.domains.includes(val)) result.domains.push(val);
    else if (type === 'url'         && !result.urls.includes(val))     result.urls.push(val);
    else if (type === 'file'        && !result.hashes.includes(val))   result.hashes.push(val);
  }
  return result;
}

// ── Transformation données API → format UI ────────────────────────────────────

const VERDICT_LABELS = {
  brute_force:         'Brute Force SSH',
  cryptomining:        'Cryptominage',
  botnet_recruitment:  'Recrutement Botnet',
  reconnaissance:      'Reconnaissance',
  webshell:            'Web Shell',
  lateral_movement:    'Mouvement Latéral',
  dropper:             'Dropper ELF',
  exploit:             'Exploitation CVE',
  ransomware:          'Ransomware',
  scan:                'Scan massif',
  unknown:             'Activité Inconnue',
};

function formatVerdict(v) {
  return VERDICT_LABELS[v] || v.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function campaignStatus(c) {
  if (c.status === 'closed') return 'clôturée';
  if (c.status === 'active') return 'active';
  if (!c.time_end) return 'active';
  const end = new Date(c.time_end).getTime();
  if (!Number.isFinite(end)) return 'active';
  return Date.now() - end < 60 * 60 * 1000 ? 'active' : 'clôturée';
}

function campaignSeverity(c) {
  if (c.confidence > 0.85 || c.session_count > 500) return 'critique';
  if (c.confidence > 0.70 || c.session_count > 100) return 'élevée';
  if (c.confidence > 0.50 || c.session_count > 20)  return 'moyenne';
  return 'faible';
}

function generateAiSummary(c, ipDetails) {
  const top = ipDetails.slice(0, 3);
  const observed = (c.observed_commands || []).map(item => item.command).filter(Boolean);
  const cmds = (observed.length ? observed : (c.shared_commands || [])).slice(0, 5);
  return `# Analyse IA — ${c.campaign_id}

> _Synthèse générée automatiquement par le module d'analyse HoneyMind._

## Vue d'ensemble
La campagne **${formatVerdict(c.verdict)}** a mobilisé **${c.ips.length} adresses IP** distinctes${c.time_start ? ` sur la période du **${c.time_start.split('T')[0]}**` : ''}${c.time_end ? ` au **${c.time_end.split('T')[0]}**` : ''}, totalisant **${(c.session_count || 0).toLocaleString('fr-FR')} sessions**. Niveau de confiance : **${((c.confidence || 0) * 100).toFixed(0)}%**.

## Commandes observées
${cmds.length > 0 ? cmds.map(cmd => `- \`${cmd}\``).join('\n') : '_(aucune commande détectée)_'}

## Acteurs principaux
${top.length > 0 ? top.map((t, i) => `${i + 1}. \`${t.ip}\` — ${t.country} · ${t.asn}`).join('\n') : '_(aucune IP géolocalisée)_'}

## Recommandations
- Bloquer les plages IP listées dans les IOC ci-contre.
- Surveiller les hash SHA-256 des charges utiles sur le parc.
- Corréler avec les flux de threat intelligence externes.`;
}

function buildIpDetails(ipAddr, allIpsMap, geoMap, campaign) {
  const ipInfo  = allIpsMap[ipAddr] || {};
  const geo     = geoMap[ipAddr]   || {};
  const code    = geo.country_code || '';
  const centroid = D.centroids[code] || null;
  const name    = geo.country || (centroid && centroid.name) || 'Inconnu';
  const lat = (geo.lat != null) ? geo.lat : (centroid ? centroid.lat + ipJitter(ipAddr, 0) : 0);
  const lon = (geo.lon != null) ? geo.lon : (centroid ? centroid.lon + ipJitter(ipAddr, 1) : 0);
  return {
    ip:           ipAddr,
    country:      name,
    code:         code || '??',
    lat,
    lon,
    connections:  (campaign.ip_session_counts || {})[ipAddr] || 1,
    success:      0,
    commands:     (ipInfo.ioc_counts || {}).url || 0,
    sampleCommands: ((campaign.observed_commands || []).map(item => item.command).filter(Boolean).length
      ? (campaign.observed_commands || []).map(item => item.command).filter(Boolean)
      : (campaign.shared_commands || [])
    ).slice(0, 8),
    asn:          geo.asn || '—',
    org:          geo.isp || '—',
    firstSeen:    (ipInfo.first_seen || campaign.time_start || '').split('T')[0] || '—',
  };
}

function transformCampaigns(apiCampaigns, allIpsArr, geoMap) {
  const allIpsMap = {};
  for (const ip of allIpsArr) allIpsMap[ip.ip] = ip;

  return apiCampaigns.map(c => {
    const ipDetails = (c.ips || []).map(ip => buildIpDetails(ip, allIpsMap, geoMap, c));
    return {
      id:                   c.campaign_id,
      name:                 formatVerdict(c.verdict),
      status:               campaignStatus(c),
      start:                (c.time_start || '').split('T')[0] || '—',
      end:                  (c.time_end   || '').split('T')[0] || '—',
      lastActivity:         c.time_end || null,
      attackingIps:         (c.ips || []).length,
      connectionAttempts:   c.session_count || 0,
      successfulConnections:0,
      commandsRun:          c.command_count || (c.observed_commands || []).reduce((s, item) => s + (item.count || 0), 0) || (c.shared_commands || []).length,
      observedCommands:     c.observed_commands || [],
      sharedCommands:       c.shared_commands || [],
      filesTransferred:     (c.ioc_counts || {})['file'] || (c.ips || []).reduce((s, ip) => s + (((allIpsMap[ip] || {}).ioc_counts || {}).file || 0), 0),
      severity:             campaignSeverity(c),
      confidence:           c.confidence || 0,
      ips:                  ipDetails,
      aiSummary:            generateAiSummary(c, ipDetails),
    };
  });
}

function computeStats(campaigns, ipsArr, commandTotal = 0, iocStats = {}) {
  return {
    totalAttacks:     campaigns.reduce((s, c) => s + c.connectionAttempts, 0),
    uniqueIps:        ipsArr.length,
    activeCampaigns:  campaigns.filter(c => c.status === 'active').length,
    totalCampaigns:   campaigns.length,
    totalCommands:    commandTotal || campaigns.reduce((s, c) => s + c.commandsRun, 0),
    filesTransferred: iocStats.file || ipsArr.reduce((s, ip) => s + ((ip.ioc_counts || {}).file || 0), 0),
  };
}

function computeTopCountries(ipsArr, geoMap) {
  const byCountry = {};
  for (const ipInfo of ipsArr) {
    const geo  = geoMap[ipInfo.ip] || {};
    const code = geo.country_code || '';
    if (!code) continue;
    const name = geo.country || (D.centroids[code] || {}).name || code;
    if (!byCountry[code]) byCountry[code] = { code, name, attacks: 0, ips: 0 };
    byCountry[code].attacks += 1;
    byCountry[code].ips     += 1;
  }
  return Object.values(byCountry).sort((a, b) => b.attacks - a.attacks).slice(0, 8);
}

function computeMapPoints(ipsArr, geoMap) {
  return ipsArr.map(ipInfo => {
    const geo      = geoMap[ipInfo.ip] || {};
    const code     = geo.country_code  || '';
    const centroid = D.centroids[code] || null;
    // Use real GeoIP coords; fall back to country centroid + jitter
    const lat = (geo.lat != null) ? geo.lat : (centroid ? centroid.lat + ipJitter(ipInfo.ip, 0) : null);
    const lon = (geo.lon != null) ? geo.lon : (centroid ? centroid.lon + ipJitter(ipInfo.ip, 1) : null);
    if (lat == null || lon == null) return null;
    return {
      ip:      ipInfo.ip,
      lat,
      lon,
      weight:  Object.values(ipInfo.ioc_counts || {}).reduce((a, b) => a + b, 0) || 1,
      country: geo.country || (centroid && centroid.name) || code,
    };
  }).filter(Boolean);
}

function computeTopCommands(commandsArr, campaigns = []) {
  if (commandsArr?.length) {
    return commandsArr
      .slice(0, 10)
      .map(item => ({ label: item.command, count: item.count || 0 }));
  }
  const counts = {};
  for (const c of campaigns)
    for (const cmd of (c.shared_commands || []))
      counts[cmd] = (counts[cmd] || 0) + 1;
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1]).slice(0, 10)
    .map(([label, count]) => ({ label, count }));
}

// Loki range query → [{day, attacks}] sur N jours
function transformLokiTimeseries(lokiResp, days = 30) {
  const fallback = Array.from({ length: days }, (_, i) => ({ day: i + 1, attacks: 0 }));
  const results = lokiResp?.data?.result;
  if (!results?.length) return fallback;
  const values = results[0].values || [];
  if (!values.length) return fallback;
  return values.map((v, i) => ({ day: i + 1, attacks: parseInt(v[1]) || 0 }));
}

function transformLocalActivity(activityResp, days = 30) {
  const rows = activityResp?.activity || [];
  if (!rows.length) {
    return Array.from({ length: days }, (_, i) => ({ day: i + 1, attacks: 0 }));
  }
  return rows.map((row, i) => ({
    day: row.day || i + 1,
    date: row.date,
    attacks: row.attacks || 0,
  }));
}

// ── DataProvider ──────────────────────────────────────────────────────────────

function DataProvider({ children }) {
  const [state, setState] = useState({ data: null, loading: true, error: null });

  const load = useCallback(async () => {
    setState(s => ({ ...s, loading: true, error: null }));
    try {
      // Sources primaires (IOC API via proxy nginx)
      const [campaignsRes, ipsRes, commandsRes, activityRes, iocStatsRes] = await Promise.all([
        fetchJson('/api/v1/iocs/campaigns'),
        fetchJson('/api/v1/iocs/ips'),
        fetchJson('/api/v1/iocs/commands?limit=25'),
        fetchJson('/api/v1/iocs/activity?days=30'),
        fetchSafe('/api/v1/iocs/stats', {}),
      ]);

      // Sources Loki (optionnelles — dégradées en silence si absentes)
      const now     = Math.floor(Date.now() / 1000);
      const start30 = now - 30 * 86400;
      const lokiSeriesUrl = `/loki/api/v1/series?${new URLSearchParams({
        'match[]': '{job="honeymind",client_ip!="",country_code!=""}',
        start: start30, end: now,
      })}`;
      const lokiTsUrl = `/loki/api/v1/query_range?${new URLSearchParams({
        query: 'sum(count_over_time({job="honeymind"}[1d]))',
        step:  86400, start: start30, end: now,
      })}`;
      const [lokiSeries, lokiTs] = await Promise.all([
        fetchSafe(lokiSeriesUrl, { data: [] },            15000),
        fetchSafe(lokiTsUrl,     { data: { result: [] } }, 15000),
      ]);

      // Construire map IP → géo à partir des séries Loki
      const geoMap = {};
      for (const s of (lokiSeries.data || [])) {
        if (s.client_ip && !geoMap[s.client_ip])
          geoMap[s.client_ip] = {
            country:      s.country      || '',
            country_code: s.country_code || '',
            isp:          s.isp          || '',
            asn:          s.asn          || '',
            lat:          s.lat ? parseFloat(s.lat) : null,
            lon:          s.lon ? parseFloat(s.lon) : null,
          };
      }

      const rawCampaigns = campaignsRes.campaigns || [];
      const rawIps       = ipsRes.ips              || [];
      const rawCommands  = commandsRes.commands   || [];
      const commandTotal = commandsRes.total       || 0;
      const campaigns    = transformCampaigns(rawCampaigns, rawIps, geoMap);

      setState({
        loading: false,
        error:   null,
        data: {
          campaigns,
          ips:          rawIps,
          geoMap,
          stats:        computeStats(campaigns, rawIps, commandTotal, iocStatsRes),
          topCountries: computeTopCountries(rawIps, geoMap),
          topCommands:  computeTopCommands(rawCommands, rawCampaigns),
          timeseries:   transformLocalActivity(activityRes),
          lokiTimeseries: transformLokiTimeseries(lokiTs),
          mapPoints:    computeMapPoints(rawIps, geoMap),
          lastUpdated:  new Date().toISOString(),
        },
      });
    } catch (e) {
      setState({ loading: false, error: e.message || 'Erreur inconnue', data: null });
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Fetch lazy des IOC STIX pour une campagne
  async function fetchCampaignIOCs(campaignId) {
    const bundle = await fetchSafe(
      `/api/v1/iocs?campaign=${encodeURIComponent(campaignId)}`, null, 15000
    );
    return bundle ? parseStixBundle(bundle) : { ips: [], domains: [], urls: [], hashes: [] };
  }

  async function fetchReport(campaignId) {
    try {
      const r = await fetch(`/api/v1/reports/campaign/${encodeURIComponent(campaignId)}`);
      if (r.status === 404) return { status: 'not_found' };
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return await r.json();
    } catch (e) {
      return { status: 'error', error: e.message };
    }
  }

  async function generateReport(campaignId) {
    const r = await fetch(`/api/v1/reports/campaign/${encodeURIComponent(campaignId)}/generate`, {
      method: 'POST',
    });
    if (!r.ok && r.status !== 202) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  }

  async function cancelReport(campaignId) {
    const r = await fetch(`/api/v1/reports/campaign/${encodeURIComponent(campaignId)}/generate`, {
      method: 'DELETE',
    });
    if (!r.ok && r.status !== 404) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  }

  return (
    <window.HMContext.Provider value={{ ...state, reload: load, fetchCampaignIOCs, fetchReport, generateReport, cancelReport }}>
      {children}
    </window.HMContext.Provider>
  );
}

// ── App shell ─────────────────────────────────────────────────────────────────

function App() {
  const [theme, setTheme] = useState(() => localStorage.getItem('hm-theme') || 'dark');
  const [route, setRoute] = useState(() => {
    try { return JSON.parse(localStorage.getItem('hm-route')) || { name: 'dashboard' }; }
    catch { return { name: 'dashboard' }; }
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('hm-theme', theme);
  }, [theme]);

  useEffect(() => {
    localStorage.setItem('hm-route', JSON.stringify(route));
    const m = document.querySelector('.main');
    if (m) m.scrollTop = 0;
    window.scrollTo(0, 0);
  }, [route]);

  const go = r => setRoute(r);
  const themeToggle = <ThemeToggle theme={theme} setTheme={setTheme} />;

  let view;
  if      (route.name === 'campaigns') view = <CampaignsView go={go} themeToggle={themeToggle} />;
  else if (route.name === 'campaign')  view = <CampaignDetailView id={route.id} go={go} themeToggle={themeToggle} />;
  else if (route.name === 'iocs')      view = <IocView themeToggle={themeToggle} />;
  else if (route.name === 'commands')  view = <CommandsView go={go} themeToggle={themeToggle} />;
  else if (route.name === 'cost')      view = <CostView themeToggle={themeToggle} />;
  else                                  view = <DashboardView go={go} themeToggle={themeToggle} />;

  return (
    <DataProvider>
      <div className="app">
        <Sidebar route={route} go={go} />
        {view}
      </div>
    </DataProvider>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
