/* HoneyMind — composants partagés */
const { useState, useEffect, useRef, useMemo, useCallback } = React;
const D = window.HM_DATA;

// Contexte global (views.jsx et app.jsx l'utilisent via window.HMContext)
window.HMContext = React.createContext({ data: null, loading: true, error: null, fetchCampaignIOCs: null });

/* ---- CSS additionnel injecté une fois ---- */
const HM_CSS = `
.app { display: grid; grid-template-columns: 248px 1fr; min-height: 100vh; }
@media (max-width: 880px){ .app{ grid-template-columns: 72px 1fr; } }

/* Sidebar */
.side { position: sticky; top: 0; height: 100vh; display: flex; flex-direction: column;
  gap: 6px; padding: 22px 16px; border-right: 1px solid var(--border-soft);
  background: color-mix(in oklch, var(--surface) 70%, transparent); backdrop-filter: blur(6px); }
.side-logo { display: flex; align-items: center; gap: 11px; padding: 4px 8px 22px; }
.side-nav { display: flex; flex-direction: column; gap: 4px; margin-top: 6px; }
.nav-item { display: flex; align-items: center; gap: 12px; padding: 10px 12px; border-radius: 10px;
  color: var(--text-dim); cursor: pointer; font-weight: 500; font-size: 14.5px; border: 1px solid transparent;
  transition: background .15s, color .15s; user-select: none; }
.nav-item:hover { background: var(--surface-2); color: var(--text); }
.nav-item.active { background: color-mix(in oklch, var(--honey) 16%, transparent);
  color: var(--text); border-color: color-mix(in oklch, var(--honey) 40%, transparent); }
.nav-item.active .nav-ic { color: var(--honey-deep); }
.nav-ic { width: 18px; height: 18px; flex: none; color: var(--text-faint); }
.side-foot { margin-top: auto; display: flex; flex-direction: column; gap: 10px; padding: 0 4px; }
.side-status { display: flex; align-items: center; gap: 8px; font-size: 13.5px; color: var(--text-faint); }
.dot-live { width: 8px; height: 8px; border-radius: 50%; background: var(--c-green);
  box-shadow: 0 0 0 0 color-mix(in oklch, var(--c-green) 70%, transparent); animation: pulse 2.2s infinite; }
@keyframes pulse { 0%{ box-shadow:0 0 0 0 color-mix(in oklch,var(--c-green) 60%, transparent);} 70%{ box-shadow:0 0 0 7px transparent;} 100%{ box-shadow:0 0 0 0 transparent;} }
@media (max-width: 880px){ .side-label, .side-foot .txt { display:none; } .side-logo .wordmark{ display:none; } }

/* Main */
.main { min-width: 0; display: flex; flex-direction: column; }
.topbar { display: flex; align-items: center; justify-content: space-between; gap: 16px;
  padding: 20px 34px; border-bottom: 1px solid var(--border-soft); position: sticky; top: 0; z-index: 20;
  background: color-mix(in oklch, var(--bg) 78%, transparent); backdrop-filter: blur(10px); }
.crumb { font-size: 12.5px; color: var(--text-faint); letter-spacing: .04em; text-transform: uppercase; }
.page-title { font-size: 22px; font-weight: 600; letter-spacing: -.01em; margin: 2px 0 0; }
.content { padding: 28px 34px 60px; max-width: 1380px; width: 100%; }

/* Theme toggle */
.tg { display: inline-flex; background: var(--surface-2); border: 1px solid var(--border-soft);
  border-radius: 9px; padding: 3px; gap: 2px; }
.tg button { border: 0; background: transparent; color: var(--text-faint); cursor: pointer;
  border-radius: 7px; padding: 6px 9px; display: flex; align-items: center; gap: 6px; font: inherit; font-size: 13px; }
.tg button.on { background: var(--surface); color: var(--text); box-shadow: var(--shadow); }

/* Stat cards */
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(190px,1fr)); gap: 16px; }
.stat { padding: 18px 20px; display: flex; flex-direction: column; gap: 6px; position: relative; overflow: hidden; }
.stat .lbl { font-size: 12.5px; color: var(--text-dim); display: flex; align-items: center; gap: 7px; }
.stat .val { font-size: 30px; font-weight: 600; letter-spacing: -.02em; font-family: var(--font-ui); }
.stat .sub { font-size: 12px; color: var(--text-faint); }

/* Section heading */
.sec-h { display: flex; align-items: baseline; justify-content: space-between; margin: 30px 0 14px; gap: 12px; }
.sec-h h2 { font-size: 16px; font-weight: 600; margin: 0; letter-spacing: -.01em; }
.sec-h .hint { font-size: 12.5px; color: var(--text-faint); }

/* Map */
.map-wrap { padding: 0; position: relative; overflow: hidden; }
.map-legend { display: flex; gap: 18px; align-items: center; flex-wrap: wrap; padding: 12px 16px 14px; font-size: 12px; color: var(--text-dim); border-top: 1px solid var(--border-soft); }
.lg-dot { display: inline-flex; align-items: center; gap: 7px; }
/* Style Leaflet controls to match the app theme */
.leaflet-container { font-family: var(--font-ui); background: var(--map-water); }
.leaflet-control-zoom a { background: color-mix(in oklch, var(--surface) 92%, transparent) !important;
  border-color: var(--border-soft) !important; color: var(--text-dim) !important; }
.leaflet-control-zoom a:hover { background: var(--surface-2) !important; color: var(--text) !important; }
.leaflet-popup-content-wrapper { background: var(--surface); border: 1px solid var(--border-soft);
  color: var(--text); box-shadow: var(--shadow); border-radius: 10px; }
.leaflet-popup-tip { background: var(--surface); }
.leaflet-control-attribution { background: color-mix(in oklch, var(--bg) 80%, transparent) !important;
  color: var(--text-faint) !important; font-size: 10px !important; }

/* Bars */
.bar-row { display: grid; grid-template-columns: 26px 1fr auto; gap: 12px; align-items: center; padding: 7px 0; }
.bar-row .flag { font-size: 12px; color: var(--text-faint); font-family: var(--font-mono); }
.bar-track { height: 9px; border-radius: 6px; background: var(--surface-2); overflow: hidden; }
.bar-fill { height: 100%; border-radius: 6px; }
.bar-meta { display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 2px; }
.bar-meta .v { color: var(--text-dim); font-family: var(--font-mono); font-size: 12.5px; }

/* Tables */
.tbl-wrap { overflow-x: auto; }
table.tbl { width: 100%; border-collapse: collapse; font-size: 13.5px; }
table.tbl th { text-align: left; font-weight: 500; color: var(--text-faint); font-size: 11.5px;
  text-transform: uppercase; letter-spacing: .05em; padding: 12px 14px; border-bottom: 1px solid var(--border-soft); white-space: nowrap; }
table.tbl th.num, table.tbl td.num { text-align: right; font-variant-numeric: tabular-nums; }
table.tbl td { padding: 13px 14px; border-bottom: 1px solid var(--border-soft); }
table.tbl tbody tr { transition: background .12s; }
table.tbl tbody tr.click { cursor: pointer; }
table.tbl tbody tr.click:hover { background: color-mix(in oklch, var(--honey) 9%, transparent); }
table.tbl tbody tr:last-child td { border-bottom: 0; }
.cid { font-family: var(--font-mono); font-weight: 600; color: var(--honey-deep); }
.camp-link { appearance: none; border: 0; background: transparent; padding: 0; cursor: pointer; }
.camp-link:hover { text-decoration: underline; text-underline-offset: 2px; }
.camp-link:focus-visible { outline: 2px solid var(--honey); outline-offset: 2px; border-radius: 4px; }
.ipcell { font-family: var(--font-mono); }
.command-detail-layout { display: grid; grid-template-columns: minmax(0, 1fr); gap: 16px; align-items: start; }
.command-detail-layout.with-panel { grid-template-columns: minmax(0, 1fr) minmax(320px, 380px); }
@media (max-width: 1100px) {
  .command-detail-layout.with-panel { grid-template-columns: minmax(0, 1fr); }
  .command-detail-panel { position: static !important; max-height: none !important; }
}

/* Badges */
.badge { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; font-weight: 600;
  padding: 4px 11px; border-radius: 999px; letter-spacing: .02em; white-space: nowrap; }
.sev-critique{ background: color-mix(in oklch,var(--c-red) 18%,transparent); color: var(--c-red); }
.sev-élevée  { background: color-mix(in oklch,var(--c-amber) 20%,transparent); color: var(--c-amber); }
.sev-moyenne { background: color-mix(in oklch,var(--honey) 20%,transparent); color: var(--honey-deep); }
.sev-faible  { background: color-mix(in oklch,var(--c-teal) 16%,transparent); color: var(--c-teal); }
.st-active{ background: color-mix(in oklch,var(--c-green) 16%,transparent); color: var(--c-green); }
.st-active .d{ width:6px;height:6px;border-radius:50%;background: var(--c-green); }
.st-clôturée,.st-archivée{ background: var(--surface-2); color: var(--text-faint); }

/* IP slide-over */
.scrim { position: fixed; inset: 0; background: rgba(0,0,0,.42); z-index: 60; opacity: 0; animation: fade .2s forwards; }
@keyframes fade { to { opacity: 1; } }
.sheet { position: fixed; top: 0; right: 0; height: 100vh; width: 420px; max-width: 92vw; z-index: 61;
  background: var(--bg); border-left: 1px solid var(--border); box-shadow: -16px 0 40px rgba(0,0,0,.3);
  display: flex; flex-direction: column; transform: translateX(100%); animation: slidein .26s cubic-bezier(.2,.7,.2,1) forwards; }
@keyframes slidein { to { transform: translateX(0); } }
.sheet-h { padding: 20px 22px; border-bottom: 1px solid var(--border-soft); display:flex; justify-content: space-between; align-items: flex-start; gap: 12px; }
.sheet-b { padding: 20px 22px; overflow-y: auto; display: flex; flex-direction: column; gap: 18px; }
.kv { display: grid; grid-template-columns: 130px 1fr; gap: 8px 14px; font-size: 13.5px; }
.kv dt { color: var(--text-faint); }
.kv dd { margin: 0; font-family: var(--font-mono); }
.iconbtn { background: var(--surface-2); border: 1px solid var(--border-soft); color: var(--text-dim);
  width: 32px; height: 32px; border-radius: 8px; display: grid; place-items: center; cursor: pointer; }
.iconbtn:hover { color: var(--text); }
.vt-btn { display: inline-flex; align-items: center; gap: 8px; background: color-mix(in oklch,var(--honey) 18%,transparent);
  color: var(--honey-deep); border: 1px solid color-mix(in oklch,var(--honey) 40%,transparent);
  padding: 9px 14px; border-radius: 10px; font-weight: 600; font-size: 13px; text-decoration: none; cursor: pointer; }
.vt-btn:hover { background: color-mix(in oklch,var(--honey) 26%,transparent); }

/* IOC */
.ioc-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(260px,1fr)); gap: 16px; }
.ioc-card { padding: 16px 18px; }
.ioc-card h4 { margin: 0 0 4px; font-size: 13px; display: flex; align-items: center; gap: 8px; }
.ioc-card .cnt { color: var(--text-faint); font-weight: 500; font-size: 12px; }
.ioc-list { list-style: none; margin: 10px 0 0; padding: 0; display: flex; flex-direction: column; gap: 2px; max-height: 230px; overflow-y: auto; }
.ioc-list li { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 6px 8px;
  border-radius: 7px; font-family: var(--font-mono); font-size: 12px; }
.ioc-list li:hover { background: var(--surface-2); }
.ioc-val { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ioc-act { display: flex; gap: 4px; flex: none; opacity: 0; transition: opacity .12s; }
.ioc-list li:hover .ioc-act { opacity: 1; }
.mini-act { cursor: pointer; color: var(--text-faint); width: 24px; height: 24px; border-radius: 6px;
  display: grid; place-items: center; border: 0; background: transparent; }
.mini-act:hover { background: var(--surface); color: var(--honey-deep); }

/* AI summary */
.ai-card { padding: 0; overflow: hidden; }
.ai-bar { display: flex; align-items: center; justify-content: space-between; gap: 10px;
  padding: 13px 18px; border-bottom: 1px solid var(--border-soft); background: var(--surface-2); }
.ai-bar .t { display: flex; align-items: center; gap: 9px; font-size: 13px; font-weight: 600; }
.ai-pending { font-size: 11.5px; color: var(--text-faint); display: flex; align-items: center; gap: 6px; }
.md { padding: 8px 24px 26px; font-size: 14px; max-height: 520px; overflow-y: auto; }
.md h1 { font-size: 19px; margin: 22px 0 6px; }
.md h2 { font-size: 15.5px; margin: 22px 0 6px; color: var(--honey-deep); }
.md h3 { font-size: 14px; margin: 16px 0 4px; }
.md p { color: var(--text-dim); margin: 8px 0; }
.md ul, .md ol { color: var(--text-dim); margin: 8px 0; padding-left: 22px; }
.md li { margin: 3px 0; }
.md code { font-family: var(--font-mono); font-size: 12px; background: var(--surface-2);
  padding: 1px 5px; border-radius: 5px; color: var(--honey-deep); }
.md pre { background: var(--bg-2); border: 1px solid var(--border-soft); border-radius: 9px;
  padding: 12px 14px; overflow-x: auto; }
.md pre code { background: none; color: var(--text-faint); padding: 0; }
.md blockquote { border-left: 3px solid color-mix(in oklch,var(--honey) 60%,transparent);
  margin: 10px 0; padding: 4px 14px; color: var(--text-faint); font-style: italic; }
.md strong { color: var(--text); }
.md hr { border: none; border-top: 1px solid var(--border-soft); margin: 18px 0; }
.md table { width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 13px; }
.md th { background: var(--surface-2); color: var(--text); font-weight: 600; text-align: left;
  padding: 7px 12px; border-bottom: 2px solid var(--border-soft); }
.md td { padding: 6px 12px; border-bottom: 1px solid var(--border-soft); color: var(--text-dim); }
.md tr:last-child td { border-bottom: none; }
.md tr:hover td { background: color-mix(in oklch, var(--honey) 5%, transparent); }

.two-col { display: grid; grid-template-columns: 1.4fr 1fr; gap: 18px; align-items: start; }
@media (max-width: 1040px){ .two-col{ grid-template-columns: 1fr; } }
.copyok { color: var(--c-green) !important; }

/* Chart axes */
.chart { display: flex; gap: 12px; }
.chart-y { display: flex; flex-direction: column; justify-content: space-between; text-align: right;
  font-size: 11px; color: var(--text-faint); font-family: var(--font-mono); min-width: 38px; padding-top: 1px; }
.chart-main { flex: 1; min-width: 0; }
.chart-x { display: flex; justify-content: space-between; font-size: 11px; color: var(--text-faint);
  font-family: var(--font-mono); margin-top: 7px; }

/* Loading / empty */
.loading-wrap { display: flex; flex-direction: column; align-items: center; justify-content: center;
  min-height: 60vh; gap: 16px; color: var(--text-faint); }
.spinner { width: 36px; height: 36px; border: 3px solid var(--border);
  border-top-color: var(--honey); border-radius: 50%; animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.error-wrap { display: flex; flex-direction: column; align-items: center; justify-content: center;
  min-height: 60vh; gap: 14px; color: var(--text-dim); text-align: center; padding: 40px; }
.retry-btn { background: color-mix(in oklch,var(--honey) 18%,transparent);
  color: var(--honey-deep); border: 1px solid color-mix(in oklch,var(--honey) 40%,transparent);
  padding: 9px 18px; border-radius: 10px; font: inherit; font-weight: 600; font-size: 13.5px; cursor: pointer; }
.retry-btn:hover { background: color-mix(in oklch,var(--honey) 26%,transparent); }
.empty-note { color: var(--text-faint); font-size: 13px; font-style: italic; padding: 18px 0; }
`;

function injectCss() {
  if (document.getElementById('hm-css')) return;
  const s = document.createElement('style');
  s.id = 'hm-css'; s.textContent = HM_CSS;
  document.head.appendChild(s);
}
injectCss();

/* ---- Icônes ---- */
function Icon({ name, className, style }) {
  const p = {
    grid: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
    layers: 'M12 2 2 7l10 5 10-5zM2 12l10 5 10-5M2 17l10 5 10-5',
    sun: 'M12 4V2M12 22v-2M4 12H2M22 12h-2M5.6 5.6 4.2 4.2M19.8 19.8l-1.4-1.4M18.4 5.6l1.4-1.4M4.2 19.8l1.4-1.4',
    moon: 'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z',
    copy: 'M9 9h11v11H9zM5 15H4V4h11v1',
    ext: 'M14 4h6v6M20 4l-9 9M19 13v6H5V5h6',
    chev: 'M9 6l6 6-6 6',
    close: 'M6 6l12 12M18 6 6 18',
    globe: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18',
    cmd: 'M4 5h16M4 12h16M4 19h10',
    file: 'M6 2h8l4 4v16H6zM14 2v4h4',
    pulse: 'M3 12h4l2-6 4 14 2-8h6',
    brain: 'M9 3a3 3 0 0 0-3 3 3 3 0 0 0-2 5 3 3 0 0 0 2 5 3 3 0 0 0 3 3M15 3a3 3 0 0 1 3 3 3 3 0 0 1 2 5 3 3 0 0 1-2 5 3 3 0 0 1-3 3M12 3v18',
    shield: 'M12 2 4 5v6c0 5 3.5 8 8 11 4.5-3 8-6 8-11V5z',
    refresh: 'M23 4v6h-6M1 20v-6h6M3.5 9a9 9 0 0 1 14.8-3.3L23 10M1 14l4.7 4.3A9 9 0 0 0 20.5 15',
    zoom_in: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.35-4.35M11 8v6M8 11h6',
    zoom_out: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.35-4.35M8 11h6',
    zoom_reset: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.35-4.35',
  }[name] || '';
  return (
    <svg className={className} style={style} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" width="20" height="20">
      <path d={p} />
    </svg>
  );
}

/* ---- Logo ---- */
function Logo({ size = 26 }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
        <polygon points="16,2 28,9 28,23 16,30 4,23 4,9"
          fill="none" stroke="var(--honey)" strokeWidth="2.2" strokeLinejoin="round" />
        <polygon points="16,9 22,12.5 22,19.5 16,23 10,19.5 10,12.5"
          fill="var(--honey)" opacity="0.92" />
      </svg>
      <span className="wordmark" style={{ fontSize: size * 0.74, fontWeight: 700, letterSpacing: '-.02em' }}>
        <span style={{ color: 'var(--honey)' }}>Honey</span><span style={{ color: 'var(--text)' }}>Mind</span>
      </span>
    </div>
  );
}

/* ---- Theme toggle ---- */
function ThemeToggle({ theme, setTheme }) {
  return (
    <div className="tg" role="group" aria-label="Thème">
      <button className={theme === 'light' ? 'on' : ''} onClick={() => setTheme('light')}>
        <Icon name="sun" /> Clair
      </button>
      <button className={theme === 'dark' ? 'on' : ''} onClick={() => setTheme('dark')}>
        <Icon name="moon" /> Sombre
      </button>
    </div>
  );
}

/* ---- Sidebar ---- */
function Sidebar({ route, go }) {
  const items = [
    { id: 'dashboard', label: 'Dashboard',  ic: 'grid'   },
    { id: 'campaigns', label: 'Campagnes',  ic: 'layers' },
    { id: 'commands',  label: 'Commandes',  ic: 'cmd'    },
    { id: 'iocs',      label: 'IOC',        ic: 'shield' },
    { id: 'cost',      label: 'Coûts IA',   ic: 'pulse'  },
  ];
  const active = route.name === 'campaign' ? 'campaigns' : route.name;
  return (
    <aside className="side">
      <div className="side-logo"><Logo /></div>
      <nav className="side-nav">
        {items.map(it => (
          <div key={it.id} className={'nav-item' + (active === it.id ? ' active' : '')}
            onClick={() => go({ name: it.id })}>
            <Icon name={it.ic} className="nav-ic" />
            <span className="side-label">{it.label}</span>
          </div>
        ))}
      </nav>
      <div className="side-foot">
        <div className="side-status">
          <span className="dot-live"></span>
          <span className="txt">Capteur en ligne</span>
        </div>
      </div>
    </aside>
  );
}

/* ---- Stat card ---- */
function Stat({ icon, label, value, sub, accent = 'var(--honey)' }) {
  return (
    <div className="card stat">
      <div className="lbl"><Icon name={icon} className="nav-ic" style={{ color: accent }} />{label}</div>
      <div className="val">{value}</div>
      {sub && <div className="sub">{sub}</div>}
    </div>
  );
}

/* ---- World map Leaflet ---- */
const TILE_DARK  = 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';
const TILE_LIGHT = 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png';
const TILE_ATTR  = '© <a href="https://openstreetmap.org">OpenStreetMap</a> © <a href="https://carto.com">CARTO</a>';

function WorldMap({ points, height = 360, onMarkerClick }) {
  const containerRef = useRef(null);
  const mapRef       = useRef(null);
  const tileRef      = useRef(null);

  // Init Leaflet map once
  useEffect(() => {
    const L = window.L;
    if (!L || !containerRef.current) return;

    const theme = document.documentElement.getAttribute('data-theme') || 'dark';
    const map = L.map(containerRef.current, {
      center: [20, 0], zoom: 2, minZoom: 1, maxZoom: 14,
      worldCopyJump: true, zoomControl: true,
    });
    mapRef.current = map;

    tileRef.current = L.tileLayer(theme === 'dark' ? TILE_DARK : TILE_LIGHT, {
      attribution: TILE_ATTR, subdomains: 'abcd', maxZoom: 19,
    }).addTo(map);

    // Swap tiles when the app theme changes
    const obs = new MutationObserver(() => {
      if (!tileRef.current) return;
      const t = document.documentElement.getAttribute('data-theme') || 'dark';
      tileRef.current.setUrl(t === 'dark' ? TILE_DARK : TILE_LIGHT);
    });
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

    return () => {
      obs.disconnect();
      map.remove();
      mapRef.current = null;
      tileRef.current = null;
    };
  }, []);

  // Refresh attack markers when points change
  useEffect(() => {
    const L = window.L;
    const map = mapRef.current;
    if (!L || !map) return;

    map.eachLayer(l => { if (l instanceof L.CircleMarker) map.removeLayer(l); });

    if (!points.length) return;
    const maxW = Math.max(...points.map(p => p.weight), 1);

    points.forEach(p => {
      if (p.lat == null || p.lon == null) return;
      const r = 5 + Math.sqrt(p.weight / maxW) * 13;
      const m = L.circleMarker([p.lat, p.lon], {
        radius: r,
        fillColor: '#e8a83c',
        color: '#b87820',
        weight: 1.2,
        opacity: 0.95,
        fillOpacity: 0.65,
      }).addTo(map);
      if (onMarkerClick) {
        m.on('click', () => onMarkerClick(p));
        m.getElement()?.style.setProperty('cursor', 'pointer');
      } else {
        m.bindPopup(
          `<div style="font-size:12px;line-height:1.5">` +
          `<strong style="font-family:monospace;color:#c47f1a">${p.ip}</strong><br/>` +
          `${p.country || ''}` +
          (p.weight ? `<br/>${p.weight} connexion${p.weight !== 1 ? 's' : ''}` : '') +
          `</div>`
        );
      }
    });
  }, [points]);

  return (
    <div className="card map-wrap">
      <div
        ref={containerRef}
        style={{ height, position: 'relative', zIndex: 0,
          borderRadius: '14px 14px 0 0', overflow: 'hidden', isolation: 'isolate' }}
      />
      <div className="map-legend">
        <span className="lg-dot">
          <span style={{ width:10, height:10, borderRadius:'50%', background:'var(--honey)', display:'inline-block' }} />
          Source d'attaque
        </span>
        <span style={{ marginLeft:'auto', color:'var(--text-faint)', fontSize:11 }}>
          Molette : zoom · Glisser : déplacer · Clic : détails
        </span>
        <span style={{ color:'var(--text-faint)' }}>{points.length} sources</span>
      </div>
    </div>
  );
}

/* ---- Bar list ---- */
function BarList({ data, colors, showFlag, maxLabelLen = 48 }) {
  const max = Math.max(...data.map(d => d.value), 1);
  return (
    <div>
      {data.map((d, i) => {
        const label = d.label && d.label.length > maxLabelLen
          ? d.label.slice(0, maxLabelLen) + '…'
          : d.label;
        return (
          <div key={i} style={{ marginBottom: 6 }}>
            <div className="bar-meta">
              <span style={{ display:'flex', gap:8, alignItems:'center', minWidth:0 }}
                title={d.label}>
                {showFlag && <span className="flag">{d.code}</span>}
                <span style={{ overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                  {label}
                </span>
              </span>
              <span className="v" style={{ flexShrink:0, marginLeft:8 }}>{d.value.toLocaleString('fr-FR')}</span>
            </div>
            <div className="bar-track">
              <div className="bar-fill" style={{ width:(d.value / max * 100) + '%', background: colors[i % colors.length] }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ---- Area chart (timeseries) ---- */
function AreaChart({ data, height = 170 }) {
  const w = 600, pad = 4;
  const rawMax = Math.max(...data.map(d => d.attacks));
  const niceMax = Math.max(100, Math.ceil(rawMax / 100) * 100);
  const ticks = [niceMax, Math.round(niceMax / 2), 0];
  const step = (w - pad * 2) / Math.max(data.length - 1, 1);
  const yOf = v => pad + (1 - v / niceMax) * (height - pad * 2);
  const pts = data.map((d, i) => [pad + i * step, yOf(d.attacks)]);
  const line = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
  const area = line + ` L ${pts[pts.length-1][0].toFixed(1)} ${height-pad} L ${pad} ${height-pad} Z`;
  const fr = n => n.toLocaleString('fr-FR');
  return (
    <div className="chart">
      <div className="chart-y" style={{ height }}>
        {ticks.map((t, i) => <span key={i}>{fr(t)}</span>)}
      </div>
      <div className="chart-main">
        <svg viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none"
          style={{ width:'100%', height, display:'block' }}>
          <defs>
            <linearGradient id="ag" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--honey)" stopOpacity="0.34" />
              <stop offset="100%" stopColor="var(--honey)" stopOpacity="0" />
            </linearGradient>
          </defs>
          {ticks.map((t, i) => {
            const y = yOf(t);
            return <line key={i} x1={pad} x2={w-pad} y1={y} y2={y}
              stroke="var(--border-soft)" strokeWidth="1" vectorEffect="non-scaling-stroke"
              strokeDasharray={t === 0 ? '' : '3 5'} />;
          })}
          <path d={area} fill="url(#ag)" />
          <path d={line} fill="none" stroke="var(--honey)" strokeWidth="2"
            strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
        </svg>
        <div className="chart-x">
          <span>J‑{data.length}</span><span>J‑{Math.round(data.length*2/3)}</span>
          <span>J‑{Math.round(data.length/3)}</span><span>Auj.</span>
        </div>
      </div>
    </div>
  );
}

/* ---- Badges ---- */
function Severity({ level }) { return <span className={'badge sev-' + level}>{level}</span>; }
function Status({ value }) {
  return <span className={'badge st-' + value}>{value === 'active' && <span className="d"></span>}{value}</span>;
}

/* ---- Copy helper ---- */
function CopyBtn({ text, title }) {
  const [ok, setOk] = useState(false);
  return (
    <button className={'mini-act' + (ok ? ' copyok' : '')} title={title || 'Copier'}
      onClick={(e) => { e.stopPropagation(); navigator.clipboard?.writeText(text); setOk(true); setTimeout(() => setOk(false), 1200); }}>
      <Icon name="copy" />
    </button>
  );
}

/* ---- IP slide-over ---- */
function IpSheet({ ip, onClose, go }) {
  useEffect(() => {
    const k = e => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k);
  }, []);

  const camps   = ip.campaigns || [];
  const cats    = ip.attackCategories || [];
  const iocCnts = ip.iocCounts || {};

  return (
    <>
      <div className="scrim" onClick={onClose}></div>
      <div className="sheet" role="dialog" aria-label={'Détails ' + ip.ip}>
        <div className="sheet-h">
          <div>
            <div className="crumb">Adresse IP</div>
            <div className="mono" style={{ fontSize:20, fontWeight:600, color:'var(--honey-deep)', marginTop:4 }}>{ip.ip}</div>
            <div style={{ color:'var(--text-dim)', fontSize:13, marginTop:4 }}>
              {[ip.country, ip.org].filter(Boolean).join(' · ')}
            </div>
          </div>
          <button className="iconbtn" onClick={onClose}><Icon name="close" /></button>
        </div>
        <div className="sheet-b">
          <a className="vt-btn" href={D.vtIpUrl(ip.ip)} target="_blank" rel="noopener">
            <Icon name="shield" width="16" height="16" /> Analyser sur VirusTotal <Icon name="ext" width="14" height="14" />
          </a>

          {/* Infos réseau */}
          <dl className="kv">
            {ip.country  && <><dt>Pays</dt><dd>{ip.country}{ip.code ? ` (${ip.code})` : ''}</dd></>}
            {ip.asn && ip.asn !== '—' && <><dt>ASN</dt><dd>{ip.asn}</dd></>}
            {ip.org && ip.org !== '—' && <><dt>Organisation</dt><dd>{ip.org}</dd></>}
            <dt>Première vue</dt><dd>{ip.firstSeen}</dd>
            <dt>Sessions</dt><dd>{ip.connections}</dd>
            {ip.success > 0 && <><dt>Réussies</dt><dd>{ip.success}</dd></>}
          </dl>



          {/* Campagnes */}
          {camps.length > 0 && (
            <div style={{ marginBottom:18 }}>
              <div className="crumb" style={{ marginBottom:8 }}>Campagnes associées</div>
              {camps.map(c => (
                <div key={c.id}
                  onClick={() => go && (go({ name:'campaign', id:c.id }), onClose())}
                  style={{ display:'flex', alignItems:'center', justifyContent:'space-between',
                    padding:'10px 14px', background:'var(--surface-2)', borderRadius:9, marginBottom:6,
                    border:'1px solid var(--border-soft)',
                    cursor: go ? 'pointer' : 'default',
                    transition:'background .12s',
                  }}
                  onMouseEnter={e => go && (e.currentTarget.style.background = 'color-mix(in oklch,var(--honey) 10%,transparent)')}
                  onMouseLeave={e => e.currentTarget.style.background = 'var(--surface-2)'}
                >
                  <div>
                    <span className="cid" style={{ fontSize:13 }}>{c.id}</span>
                    <span style={{ fontSize:12, color:'var(--text-faint)', marginLeft:8 }}>{c.name}</span>
                  </div>
                  <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                    <Status value={c.status} />
                    <Severity level={c.severity} />
                    {go && <Icon name="chev" style={{ width:14, height:14, color:'var(--text-faint)' }} />}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Commandes observées */}
          {ip.sampleCommands && ip.sampleCommands.length > 0 && (
            <div>
              <div className="crumb" style={{ marginBottom:8 }}>Commandes observées</div>
              <pre style={{ background:'var(--bg-2)', border:'1px solid var(--border-soft)', borderRadius:9,
                padding:'12px 14px', fontFamily:'var(--font-mono)', fontSize:12, color:'var(--text-dim)',
                overflowX:'auto', margin:0, whiteSpace:'pre-wrap' }}>
                {ip.sampleCommands.map(c => '$ ' + c).join('\n')}
              </pre>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

/* ---- Loading / Error views ---- */
function LoadingView({ themeToggle }) {
  return (
    <div className="main">
      <div className="topbar">
        <div><div className="crumb">HoneyMind</div><h1 className="page-title">Chargement…</h1></div>
        <div>{themeToggle}</div>
      </div>
      <div className="loading-wrap">
        <div className="spinner"></div>
        <div>Connexion à l'API…</div>
      </div>
    </div>
  );
}

function ErrorView({ message, onRetry, themeToggle }) {
  return (
    <div className="main">
      <div className="topbar">
        <div><div className="crumb">HoneyMind</div><h1 className="page-title">Erreur</h1></div>
        <div>{themeToggle}</div>
      </div>
      <div className="error-wrap">
        <Icon name="shield" style={{ color:'var(--c-red)', width:40, height:40 }} />
        <div style={{ fontSize:16, fontWeight:600, color:'var(--text)' }}>Impossible de charger les données</div>
        <div style={{ fontSize:13, maxWidth:420 }}>{message || 'Vérifiez que l\'API IOC et Loki sont accessibles via le proxy nginx.'}</div>
        {onRetry && <button className="retry-btn" onClick={onRetry}>Réessayer</button>}
      </div>
    </div>
  );
}

Object.assign(window, {
  Icon, Logo, ThemeToggle, Sidebar, Stat, WorldMap, BarList, AreaChart,
  Severity, Status, CopyBtn, IpSheet, LoadingView, ErrorView,
  useState, useEffect, useRef, useMemo, useCallback,
});
