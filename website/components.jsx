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
.side-status { display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text-faint); }
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
.map-wrap { padding: 18px; position: relative; overflow: hidden; }
.map-svg { width: 100%; height: auto; display: block; cursor: grab; touch-action: none; }
.map-svg.dragging { cursor: grabbing; }
.atk { cursor: pointer; }
.atk-core { transform-box: fill-box; transform-origin: center; }
.map-controls { position: absolute; top: 14px; right: 14px; display: flex; flex-direction: column; gap: 4px; }
.map-btn { width: 28px; height: 28px; border-radius: 7px; background: var(--surface-2);
  border: 1px solid var(--border-soft); color: var(--text-dim); cursor: pointer;
  display: grid; place-items: center; font-size: 15px; font-weight: 600; line-height: 1;
  transition: background .12s, color .12s; }
.map-btn:hover { background: var(--surface); color: var(--text); }
.map-zoom-track { width: 3px; height: 44px; background: var(--border-soft); border-radius: 2px;
  position: relative; overflow: hidden; margin: 2px auto; cursor: default; }
.map-zoom-fill { position: absolute; bottom: 0; left: 0; width: 100%; min-height: 2px;
  background: linear-gradient(to top, var(--honey-deep), var(--honey)); border-radius: 2px;
  transition: height 0.08s linear; }
.map-legend { display: flex; gap: 18px; align-items: center; flex-wrap: wrap; margin-top: 12px; font-size: 12px; color: var(--text-dim); }
.lg-dot { display: inline-flex; align-items: center; gap: 7px; }
.map-tip { position: absolute; pointer-events: none; z-index: 30; background: var(--surface);
  border: 1px solid var(--border); border-radius: 9px; padding: 8px 11px; box-shadow: var(--shadow);
  font-size: 12.5px; white-space: nowrap; }
.map-tip .ip { font-family: var(--font-mono); font-weight: 600; color: var(--honey-deep); }

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
.ipcell { font-family: var(--font-mono); }

/* Badges */
.badge { display: inline-flex; align-items: center; gap: 6px; font-size: 11.5px; font-weight: 600;
  padding: 3px 9px; border-radius: 999px; letter-spacing: .02em; white-space: nowrap; }
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
    { id: 'dashboard', label: 'Dashboard', ic: 'grid' },
    { id: 'campaigns', label: 'Campagnes', ic: 'layers' },
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

/* ---- World map avec zoom/pan ---- */
function WorldMap({ points, height = 360 }) {
  // Espace de coordonnées SVG : 1 unité = 5° lon (W) ou 4° lat (H)
  const VW = D.map.W * 5;   // 360
  const VH = D.map.H * 4;   // 144
  const MIN_W = 12;          // zoom max ≈ ×30 (zone ~6°×2.4°)
  const INIT = { x: 0, y: 0, w: VW, h: VH };

  const [vb, setVb_] = useState(INIT);
  const [drag, setDrag] = useState(false);
  const [tip, setTip]   = useState(null);

  // vbR reflète toujours vb — permet aux handlers attachés une seule fois de lire
  // l'état courant sans stale closure (useRef garde la même référence objet)
  const vbR    = useRef(INIT);
  const dragR  = useRef(null);
  const touchR = useRef(null);
  const animR  = useRef(null);
  const svgR   = useRef(null);
  const wrapR  = useRef(null);

  // Mise à jour simultanée du ref et de l'état React
  const setVb = v => { vbR.current = v; setVb_(v); };

  // Dots de terre (calculés une seule fois)
  const land = useMemo(() => {
    const dots = [];
    for (let r = 0; r < D.map.H; r++)
      for (let c = 0; c < D.map.W; c++)
        if (D.map.isLand(r, c)) dots.push({ x: c * 5 + 2.5, y: r * 4 + 2 });
    return dots;
  }, []);

  // Étiquettes pays depuis D.centroids — projetées en coordonnées SVG
  const countryLabels = useMemo(() =>
    Object.entries(D.centroids).map(([iso, d]) => {
      const p = D.map.project(d.lat, d.lon);
      return { iso, name: d.name, x: (p.x / 100) * VW, y: (p.y / 100) * VH };
    }), []);

  const maxPt = useMemo(() => Math.max(...points.map(p => p.weight), 1), [points]);

  // ── Zoom : calcule le nouveau viewbox en gardant le pivot fixe ──────────
  // factor < 1 → zoom avant (viewbox plus petit = zone plus petite, plus de détail)
  // factor > 1 → zoom arrière (viewbox plus grand = zone plus grande, moins de détail)
  function zoomAt(base, factor, px, py) {
    const w = Math.min(VW, Math.max(MIN_W, base.w * factor));
    const h = w * (VH / VW), s = w / base.w;
    return {
      x: Math.max(0, Math.min(VW - w, px - (px - base.x) * s)),
      y: Math.max(0, Math.min(VH - h, py - (py - base.y) * s)),
      w, h,
    };
  }

  // ── Animation fluide pour les boutons et le reset ──────────────────────
  function animTo(to) {
    if (animR.current) { cancelAnimationFrame(animR.current); animR.current = null; }
    const from = { ...vbR.current };
    const t0 = performance.now(), DUR = 300;
    const ease = t => t < 0.5 ? 2*t*t : -1+(4-2*t)*t; // easeInOutQuad
    const step = now => {
      const p = Math.min(1, (now - t0) / DUR), e = ease(p);
      const lp = (a, b) => a + (b - a) * e;
      setVb({ x: lp(from.x, to.x), y: lp(from.y, to.y), w: lp(from.w, to.w), h: lp(from.h, to.h) });
      animR.current = p < 1 ? requestAnimationFrame(step) : null;
    };
    animR.current = requestAnimationFrame(step);
  }

  // ── Molette : passive:false obligatoire ; tout via refs, pas de stale closure ──
  useEffect(() => {
    const el = svgR.current;
    if (!el) return;
    const onWheel = e => {
      e.preventDefault();
      if (animR.current) { cancelAnimationFrame(animR.current); animR.current = null; }
      const rect = el.getBoundingClientRect();
      const c = vbR.current;
      // Pivot = position du curseur en coordonnées SVG
      const px = c.x + (e.clientX - rect.left) / rect.width  * c.w;
      const py = c.y + (e.clientY - rect.top)  / rect.height * c.h;
      // Normalise selon deltaMode (pixels=0, lignes=1, pages=2)
      const d = e.deltaMode === 1 ? e.deltaY * 30 : e.deltaMode === 2 ? e.deltaY * 300 : e.deltaY;
      // deltaY > 0 → scroll bas → zoom arrière (factor > 1 → viewbox s'agrandit)
      // deltaY < 0 → scroll haut → zoom avant (factor < 1 → viewbox se réduit)
      setVb(zoomAt(c, Math.pow(1.001, d), px, py));
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, []); // VW,VH,MIN_W sont des constantes — closure de premier rendu toujours valide

  // ── Touch : pan 1 doigt + pinch zoom 2 doigts ─────────────────────────
  useEffect(() => {
    const el = svgR.current;
    if (!el) return;
    const onTS = e => {
      e.preventDefault();
      if (animR.current) { cancelAnimationFrame(animR.current); animR.current = null; }
      const c = vbR.current;
      if (e.touches.length === 1) {
        touchR.current = { type: 'pan', sx: e.touches[0].clientX, sy: e.touches[0].clientY,
          vbx: c.x, vby: c.y, vbw: c.w, vbh: c.h };
        setDrag(true);
      } else if (e.touches.length === 2) {
        const rect = el.getBoundingClientRect();
        const mx = (e.touches[0].clientX + e.touches[1].clientX) / 2;
        const my = (e.touches[0].clientY + e.touches[1].clientY) / 2;
        touchR.current = {
          type: 'pinch',
          sd: Math.hypot(e.touches[0].clientX - e.touches[1].clientX, e.touches[0].clientY - e.touches[1].clientY),
          sv: { ...c },
          px: c.x + (mx - rect.left) / rect.width  * c.w,
          py: c.y + (my - rect.top)  / rect.height * c.h,
        };
        setDrag(false);
      }
    };
    const onTM = e => {
      e.preventDefault();
      const t = touchR.current;
      if (!t) return;
      const rect = el.getBoundingClientRect();
      const c = vbR.current;
      if (t.type === 'pan' && e.touches.length === 1) {
        const dx = (e.touches[0].clientX - t.sx) / rect.width  * t.vbw;
        const dy = (e.touches[0].clientY - t.sy) / rect.height * t.vbh;
        setVb({ ...c, x: Math.max(0, Math.min(VW - c.w, t.vbx - dx)), y: Math.max(0, Math.min(VH - c.h, t.vby - dy)) });
      } else if (t.type === 'pinch' && e.touches.length === 2) {
        const nd = Math.hypot(e.touches[0].clientX - e.touches[1].clientX, e.touches[0].clientY - e.touches[1].clientY);
        // doigts qui s'écartent (nd > sd) → factor < 1 → zoom avant ✓
        setVb(zoomAt(t.sv, t.sd / nd, t.px, t.py));
      }
    };
    const onTE = e => { if (e.touches.length === 0) { setDrag(false); touchR.current = null; } };
    el.addEventListener('touchstart', onTS, { passive: false });
    el.addEventListener('touchmove',  onTM, { passive: false });
    el.addEventListener('touchend',   onTE);
    return () => {
      el.removeEventListener('touchstart', onTS);
      el.removeEventListener('touchmove',  onTM);
      el.removeEventListener('touchend',   onTE);
    };
  }, []);

  // ── Drag souris : listeners document pour survivre à la sortie du composant ──
  useEffect(() => {
    if (!drag) return;
    const onMove = e => {
      const d = dragR.current;
      if (!d || !svgR.current) return;
      const rect = svgR.current.getBoundingClientRect();
      // Conversion pixels→SVG basée sur les dimensions AU MOMENT du mousedown (d.vbw/d.vbh)
      const dx = (e.clientX - d.sx) / rect.width  * d.vbw;
      const dy = (e.clientY - d.sy) / rect.height * d.vbh;
      const c = vbR.current;
      setVb({ ...c, x: Math.max(0, Math.min(VW - c.w, d.vbx - dx)), y: Math.max(0, Math.min(VH - c.h, d.vby - dy)) });
    };
    const onUp = () => { setDrag(false); dragR.current = null; };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup',   onUp);
    return () => { document.removeEventListener('mousemove', onMove); document.removeEventListener('mouseup', onUp); };
  }, [drag]);

  const onMD = e => {
    if (e.button !== 0) return;
    e.preventDefault();
    if (animR.current) { cancelAnimationFrame(animR.current); animR.current = null; }
    const c = vbR.current;
    dragR.current = { sx: e.clientX, sy: e.clientY, vbx: c.x, vby: c.y, vbw: c.w, vbh: c.h };
    setDrag(true);
  };

  // Boutons : zoom centré sur le milieu de la vue actuelle
  const zIn  = () => { const c = vbR.current; animTo(zoomAt(c, 1/1.5, c.x + c.w/2, c.y + c.h/2)); };
  const zOut = () => { const c = vbR.current; animTo(zoomAt(c, 1.5,   c.x + c.w/2, c.y + c.h/2)); };
  const zRst = () => animTo(INIT);

  // ── Métriques d'affichage ──────────────────────────────────────────────
  const zoomFactor = VW / vb.w;                                        // 1.0 = monde entier
  const zoomPct    = Math.min(100, Math.round(((zoomFactor - 1) / (VW / MIN_W - 1)) * 100));
  const showLabels = zoomFactor >= 2.5;  // étiquettes pays visibles dès ×2.5

  // Taille de police en unités SVG : constante en pixels quelle que soit le zoom
  // car elle est divisée par la largeur du viewBox (même rapport que le rendu à l'écran)
  const labelSize = vb.w / 55;

  const viewBox = `${vb.x.toFixed(1)} ${vb.y.toFixed(1)} ${vb.w.toFixed(1)} ${vb.h.toFixed(1)}`;

  return (
    <div className="card map-wrap" ref={wrapR}>
      <svg ref={svgR} className={`map-svg${drag ? ' dragging' : ''}`}
        viewBox={viewBox} style={{ maxHeight: height }}
        onMouseDown={onMD} tabIndex={0} aria-label="Carte des origines d'attaques">

        {/* Fond : dots de terre */}
        {land.map((d, i) => (
          <circle key={i} cx={d.x} cy={d.y} r={1.25} fill="var(--map-land)" />
        ))}

        {/* Détail : codes pays — apparaissent à partir de ×2.5 zoom */}
        {showLabels && countryLabels.map(({ iso, x, y }) => {
          if (x < vb.x - 2 || x > vb.x + vb.w + 2 || y < vb.y - 2 || y > vb.y + vb.h + 2) return null;
          return (
            <text key={iso} x={x} y={y} fontSize={labelSize}
              fill="var(--text-faint)" textAnchor="middle" dominantBaseline="middle"
              style={{ pointerEvents: 'none', userSelect: 'none', fontFamily: 'var(--font-ui)' }}>
              {iso}
            </text>
          );
        })}

        {/* Points d'attaque */}
        {points.map((p, i) => {
          const { x, y } = D.map.project(p.lat, p.lon);
          const cx = (x / 100) * VW, cy = (y / 100) * VH;
          const r  = 1.6 + (p.weight / maxPt) * 5.2;
          return (
            <g key={i} className="atk"
              onMouseMove={e => {
                const b = wrapR.current.getBoundingClientRect();
                setTip({ x: e.clientX - b.left, y: e.clientY - b.top, below: (e.clientY - b.top) < 70, p });
              }}
              onMouseLeave={() => setTip(null)}>
              <circle cx={cx} cy={cy} r={r * 2.2} fill="var(--honey)" opacity="0.12" />
              <circle cx={cx} cy={cy} r={r} className="atk-core"
                fill="var(--honey)" stroke="var(--honey-deep)" strokeWidth="0.4" opacity="0.92" />
            </g>
          );
        })}
      </svg>

      {/* Contrôles zoom */}
      <div className="map-controls">
        <button className="map-btn" title="Zoom avant" onClick={zIn} aria-label="Zoom avant">+</button>
        <div className="map-zoom-track" title={`Zoom ×${zoomFactor.toFixed(1)}`}>
          <div className="map-zoom-fill" style={{ height: `${zoomPct}%` }} />
        </div>
        <button className="map-btn" title="Zoom arrière" onClick={zOut} aria-label="Zoom arrière">−</button>
        <button className="map-btn" title="Vue monde entier" onClick={zRst} style={{ fontSize: 11 }} aria-label="Réinitialiser">⌂</button>
      </div>

      {tip && (
        <div className="map-tip" style={{
          left: tip.x, top: tip.y,
          transform: tip.below ? 'translate(-50%, 12px)' : 'translate(-50%, -118%)',
        }}>
          <div className="ip">{tip.p.ip}</div>
          <div style={{ color: 'var(--text-dim)' }}>{tip.p.country} · {tip.p.weight} connexions</div>
        </div>
      )}

      <div className="map-legend">
        <span className="lg-dot">
          <span style={{ width:8,height:8,borderRadius:'50%',background:'var(--map-land)',display:'inline-block' }} /> Terres
        </span>
        <span className="lg-dot">
          <span style={{ width:10,height:10,borderRadius:'50%',background:'var(--honey)',display:'inline-block' }} /> IP attaquante (taille ∝ connexions)
        </span>
        <span style={{ marginLeft:'auto', color:'var(--text-faint)', fontSize: 11 }}>
          Molette / pincer : zoom &nbsp;·&nbsp; Glisser : pan
        </span>
        <span style={{ color:'var(--text-faint)' }}>{points.length} sources</span>
      </div>
    </div>
  );
}

/* ---- Bar list ---- */
function BarList({ data, colors, showFlag }) {
  const max = Math.max(...data.map(d => d.value), 1);
  return (
    <div>
      {data.map((d, i) => (
        <div key={i} style={{ marginBottom: 6 }}>
          <div className="bar-meta">
            <span style={{ display:'flex', gap:8, alignItems:'center' }}>
              {showFlag && <span className="flag">{d.code}</span>}{d.label}
            </span>
            <span className="v">{d.value.toLocaleString('fr-FR')}</span>
          </div>
          <div className="bar-track">
            <div className="bar-fill" style={{ width:(d.value / max * 100) + '%', background: colors[i % colors.length] }} />
          </div>
        </div>
      ))}
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
function IpSheet({ ip, onClose }) {
  useEffect(() => {
    const k = e => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', k); return () => window.removeEventListener('keydown', k);
  }, []);
  return (
    <>
      <div className="scrim" onClick={onClose}></div>
      <div className="sheet" role="dialog" aria-label={'Détails ' + ip.ip}>
        <div className="sheet-h">
          <div>
            <div className="crumb">Adresse IP</div>
            <div className="mono" style={{ fontSize:20, fontWeight:600, color:'var(--honey-deep)', marginTop:4 }}>{ip.ip}</div>
            <div style={{ color:'var(--text-dim)', fontSize:13, marginTop:4 }}>{ip.country} · {ip.org}</div>
          </div>
          <button className="iconbtn" onClick={onClose}><Icon name="close" /></button>
        </div>
        <div className="sheet-b">
          <a className="vt-btn" href={D.vtIpUrl(ip.ip)} target="_blank" rel="noopener">
            <Icon name="shield" width="16" height="16" /> Analyser sur VirusTotal <Icon name="ext" width="14" height="14" />
          </a>
          <dl className="kv">
            <dt>Pays</dt><dd>{ip.country} ({ip.code})</dd>
            <dt>ASN</dt><dd>{ip.asn}</dd>
            <dt>Organisation</dt><dd>{ip.org}</dd>
            <dt>Première vue</dt><dd>{ip.firstSeen}</dd>
            <dt>Connexions</dt><dd>{ip.connections}</dd>
            <dt>Réussies</dt><dd>{ip.success}</dd>
            <dt>Commandes</dt><dd>{ip.commands}</dd>
            <dt>Coordonnées</dt><dd>{ip.lat?.toFixed(1)}, {ip.lon?.toFixed(1)}</dd>
          </dl>
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
