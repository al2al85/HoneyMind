/* HoneyMind — vues (Dashboard, Campagnes, Détail campagne) */
const CH = ['var(--c-honey)','var(--c-amber)','var(--c-teal)','var(--c-violet)','var(--c-green)','var(--c-red)'];
const nf = n => (n ?? 0).toLocaleString('fr-FR');
const D = window.HM_DATA;

function useHM() { return React.useContext(window.HMContext); }

function PageHead({ crumb, title, right }) {
  return (
    <div className="topbar">
      <div>
        <div className="crumb">{crumb}</div>
        <h1 className="page-title">{title}</h1>
      </div>
      <div style={{ display:'flex', alignItems:'center', gap:12 }}>{right}</div>
    </div>
  );
}

function SecH({ title, hint }) {
  return <div className="sec-h"><h2>{title}</h2>{hint && <span className="hint">{hint}</span>}</div>;
}

/* ============ DASHBOARD ============ */
function DashboardView({ themeToggle }) {
  const { data, loading, error, reload } = useHM();

  if (loading) return <LoadingView themeToggle={themeToggle} />;
  if (error || !data) return <ErrorView message={error} onRetry={reload} themeToggle={themeToggle} />;

  const s = data.stats;
  const countriesBar = data.topCountries.map(c => ({ label: c.name, code: c.code, value: c.attacks }));
  const cmdBar = (data.topCommands || []).slice(0, 7).map(c => ({ label: c.label, value: c.count }));
  const peak = data.timeseries.length ? Math.max(...data.timeseries.map(d => d.attacks)) : 0;

  return (
    <div className="main">
      <PageHead crumb="HoneyMind · Supervision" title="Dashboard"
        right={
          <div style={{ display:'flex', gap:10, alignItems:'center' }}>
            {data.lastUpdated && (
              <span style={{ fontSize:11.5, color:'var(--text-faint)' }}>
                Mis à jour {new Date(data.lastUpdated).toLocaleTimeString('fr-FR')}
              </span>
            )}
            <button onClick={reload} title="Actualiser"
              style={{ background:'var(--surface-2)', border:'1px solid var(--border-soft)', color:'var(--text-dim)',
                width:32, height:32, borderRadius:8, display:'grid', placeItems:'center', cursor:'pointer' }}>
              <Icon name="refresh" style={{ width:15, height:15 }} />
            </button>
            {themeToggle}
          </div>
        }
      />
      <div className="content">

        <div className="card" style={{ padding:'22px 26px', marginBottom:24, display:'flex',
          gap:22, alignItems:'center', flexWrap:'wrap' }}>
          <div style={{ flex:'1 1 360px', minWidth:280 }}>
            <div style={{ display:'flex', alignItems:'center', gap:9, color:'var(--honey-deep)',
              fontSize:12.5, fontWeight:600, letterSpacing:'.04em', textTransform:'uppercase' }}>
              <Icon name="brain" style={{ width:16, height:16 }} /> Honeypot augmenté par IA
            </div>
            <p style={{ margin:'10px 0 0', fontSize:15.5, color:'var(--text-dim)', lineHeight:1.6, maxWidth:620 }}>
              HoneyMind expose des services leurres pour capturer les attaques réelles. Chaque session est
              journalisée, et une IA répond aux commandes complexes puis analyse l'ensemble des logs pour en
              extraire campagnes, indicateurs de compromission et synthèses exploitables.
            </p>
          </div>
        </div>

        <div className="stat-grid">
          <Stat icon="pulse"  label="Attaques totales"    value={nf(s.totalAttacks)}     sub="sessions enregistrées"   accent="var(--c-honey)" />
          <Stat icon="globe"  label="IP uniques"           value={nf(s.uniqueIps)}         sub="sources distinctes"      accent="var(--c-teal)" />
          <Stat icon="layers" label="Campagnes actives"    value={`${s.activeCampaigns} / ${s.totalCampaigns}`} sub="en cours de suivi" accent="var(--c-green)" />
          <Stat icon="cmd"    label="Commandes observées"  value={nf(s.totalCommands)}     sub="sessions analysées"      accent="var(--c-violet)" />
          <Stat icon="file"   label="Fichiers transférés"  value={nf(s.filesTransferred)}  sub="détectés via IOC"        accent="var(--c-amber)" />
        </div>

        <SecH title="Origine des attaques" hint="Géolocalisation des IP source" />
        {data.mapPoints.length > 0
          ? <WorldMap points={data.mapPoints} height={420} />
          : <div className="card map-wrap"><p className="empty-note">Aucune IP géolocalisée pour le moment.</p></div>
        }

        <div className="two-col" style={{ marginTop:24 }}>
          <div>
            <SecH title="Activité (30 derniers jours)" hint={peak ? 'Pic : ' + nf(peak) + ' / jour' : ''} />
            <div className="card" style={{ padding:'18px 18px 12px' }}>
              {data.timeseries.length > 1
                ? <AreaChart data={data.timeseries} height={170} />
                : <p className="empty-note">Données Loki non disponibles.</p>
              }
            </div>
          </div>
          <div>
            <SecH title="Top commandes" hint="observées dans les sessions" />
            <div className="card" style={{ padding:'16px 18px' }}>
              {cmdBar.length > 0
                ? <BarList data={cmdBar} colors={CH} />
                : <p className="empty-note">Aucune commande détectée.</p>
              }
            </div>
          </div>
        </div>

        {countriesBar.length > 0 && (
          <>
            <SecH title="Pays les plus actifs" hint="par nombre d'IP attaquantes" />
            <div className="card" style={{ padding:'18px 22px' }}>
              <BarList data={countriesBar} colors={CH} showFlag />
            </div>
          </>
        )}

      </div>
    </div>
  );
}

/* ============ LISTE DES CAMPAGNES ============ */
function CampaignsView({ go, themeToggle }) {
  const { data, loading, error, reload } = useHM();

  if (loading) return <LoadingView themeToggle={themeToggle} />;
  if (error || !data) return <ErrorView message={error} onRetry={reload} themeToggle={themeToggle} />;

  const cols = [
    { k: 'id',                   label: 'Campagne' },
    { k: 'status',               label: 'Statut' },
    { k: 'attackingIps',         label: 'IP attaq.',   num: true },
    { k: 'connectionAttempts',   label: 'Sessions',    num: true },
    { k: 'commandsRun',          label: 'Cmd. observées', num: true },
    { k: 'filesTransferred',     label: 'Fichiers',    num: true },
    { k: 'severity',             label: 'Sévérité' },
  ];

  return (
    <div className="main">
      <PageHead crumb="HoneyMind · Analyse" title="Campagnes"
        right={
          <div style={{ display:'flex', gap:10, alignItems:'center' }}>
            <button onClick={reload} title="Actualiser"
              style={{ background:'var(--surface-2)', border:'1px solid var(--border-soft)', color:'var(--text-dim)',
                width:32, height:32, borderRadius:8, display:'grid', placeItems:'center', cursor:'pointer' }}>
              <Icon name="refresh" style={{ width:15, height:15 }} />
            </button>
            {themeToggle}
          </div>
        }
      />
      <div className="content">
        <SecH title={`${data.campaigns.length} campagne${data.campaigns.length !== 1 ? 's' : ''} détectée${data.campaigns.length !== 1 ? 's' : ''}`}
          hint="Cliquez une ligne pour le détail" />
        {data.campaigns.length === 0
          ? <div className="card" style={{ padding:32, textAlign:'center' }}>
              <p className="empty-note">Aucune campagne détectée pour le moment.</p>
            </div>
          : <div className="card tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr>{cols.map(c => <th key={c.k} className={c.num ? 'num' : ''}>{c.label}</th>)}<th></th></tr>
                </thead>
                <tbody>
                  {data.campaigns.map(c => (
                    <tr key={c.id} className="click" onClick={() => go({ name: 'campaign', id: c.id })}>
                      <td>
                        <div className="cid">{c.id}</div>
                        <div style={{ color:'var(--text-faint)', fontSize:12 }}>{c.name} · {c.start}</div>
                      </td>
                      <td><Status value={c.status} /></td>
                      <td className="num">{nf(c.attackingIps)}</td>
                      <td className="num">{nf(c.connectionAttempts)}</td>
                      <td className="num">{nf(c.commandsRun)}</td>
                      <td className="num">{nf(c.filesTransferred)}</td>
                      <td><Severity level={c.severity} /></td>
                      <td style={{ color:'var(--text-faint)' }}><Icon name="chev" style={{ width:16, height:16 }} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
        }
      </div>
    </div>
  );
}

/* ============ RAPPORT IA ============ */
function AiReport({ campaignId }) {
  // ALL hooks must be declared before any conditional return
  const { fetchReport, generateReport } = useHM();
  const [report, setReport]       = React.useState(null);
  const [polling, setPolling]     = React.useState(false);
  const [fullscreen, setFullscreen] = React.useState(false);

  const load = React.useCallback(async () => {
    const r = await fetchReport(campaignId);
    setReport(r);
    setPolling(r.status === 'generating');
  }, [campaignId]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!polling) return;
    const tid = setInterval(load, 4000);
    return () => clearInterval(tid);
  }, [polling, load]);

  const onGenerate = async () => {
    setReport({ status: 'generating' });
    setPolling(true);
    try { await generateReport(campaignId); } catch (e) {
      setReport({ status: 'error', error: e.message });
      setPolling(false);
    }
  };

  const bar = (right) => (
    <div className="ai-bar">
      <span className="t">
        <Icon name="brain" style={{ width:16, height:16, color:'var(--honey-deep)' }} /> Rapport IA
      </span>
      {right}
    </div>
  );

  if (!report) return (
    <div className="card ai-card">
      {bar(null)}
      <div style={{ display:'flex', justifyContent:'center', padding:36 }}>
        <div className="spinner"></div>
      </div>
    </div>
  );

  if (report.status === 'not_found') return (
    <div className="card ai-card">
      {bar(<span className="ai-pending"><span className="dot-live" style={{ background:'var(--border)' }}></span>Non généré</span>)}
      <div style={{ padding:'36px 24px', display:'flex', flexDirection:'column', alignItems:'center', gap:16, textAlign:'center' }}>
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--border)" strokeWidth="1.5">
          <path d="M9.663 17h4.673M12 3v1m6.364 1.636-.707.707M21 12h-1M4 12H3m3.343-5.657-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"/>
        </svg>
        <p style={{ color:'var(--text-faint)', fontSize:13.5, margin:0, maxWidth:280 }}>
          Aucun rapport d'analyse IA disponible pour cette campagne.
        </p>
        <button onClick={onGenerate} style={{
          display:'inline-flex', alignItems:'center', gap:8, padding:'10px 22px',
          background:'var(--honey)', color:'#fff', border:'none', borderRadius:9,
          cursor:'pointer', fontSize:13.5, fontWeight:600,
        }}>
          <Icon name="brain" style={{ width:15, height:15 }} /> Générer le rapport
        </button>
      </div>
    </div>
  );

  if (report.status === 'generating') return (
    <div className="card ai-card">
      {bar(<span className="ai-pending"><span className="dot-live" style={{ background:'var(--c-amber)' }}></span>Analyse en cours…</span>)}
      <div style={{ padding:'32px 24px', display:'flex', flexDirection:'column', alignItems:'center', gap:14 }}>
        <div className="spinner"></div>
        <p style={{ color:'var(--text-faint)', fontSize:13, margin:0, textAlign:'center', maxWidth:300 }}>
          Le modèle analyse les sessions de la campagne.<br/>Cela peut prendre 30 à 60 secondes.
        </p>
      </div>
    </div>
  );

  if (report.status === 'error') return (
    <div className="card ai-card">
      {bar(<span className="ai-pending" style={{ color:'var(--c-red)' }}>Échec</span>)}
      <div style={{ padding:'20px 24px', display:'flex', flexDirection:'column', gap:12 }}>
        <p style={{ color:'var(--c-red)', fontSize:12.5, margin:0, fontFamily:'var(--font-mono)', wordBreak:'break-all' }}>
          {report.error || 'Erreur inconnue'}
        </p>
        <button onClick={onGenerate} style={{
          alignSelf:'flex-start', display:'inline-flex', alignItems:'center', gap:7,
          padding:'7px 16px', background:'var(--surface-2)', border:'1px solid var(--border-soft)',
          color:'var(--text-dim)', borderRadius:8, cursor:'pointer', fontSize:13,
        }}>
          <Icon name="refresh" style={{ width:13, height:13 }} /> Réessayer
        </button>
      </div>
    </div>
  );

  const ts = report.generated_at ? new Date(report.generated_at).toLocaleString('fr-FR') : '';
  const mdHtml = D.mdToHtml(report.content || '');

  const btnStyle = {
    display:'inline-flex', alignItems:'center', gap:6, padding:'4px 11px',
    background:'var(--surface-2)', border:'1px solid var(--border-soft)',
    color:'var(--text-faint)', borderRadius:7, cursor:'pointer', fontSize:12,
  };

  return (
    <>
      <div className="card ai-card">
        {bar(
          <span style={{ display:'flex', alignItems:'center', gap:8 }}>
            {ts && <span style={{ fontSize:11.5, color:'var(--text-faint)' }}>{ts}</span>}
            <button onClick={() => setFullscreen(true)} style={btnStyle} title="Plein écran">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/>
                <line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/>
              </svg>
              Plein écran
            </button>
            <button onClick={onGenerate} style={btnStyle} title="Regénérer">
              <Icon name="refresh" style={{ width:12, height:12 }} /> Regénérer
            </button>
          </span>
        )}
        <div className="md" style={{ maxHeight:480 }} dangerouslySetInnerHTML={{ __html: mdHtml }} />
      </div>

      {fullscreen && (
        <div onClick={() => setFullscreen(false)} style={{
          position:'fixed', inset:0, background:'rgba(0,0,0,.6)', backdropFilter:'blur(4px)',
          zIndex:1000, display:'flex', alignItems:'center', justifyContent:'center', padding:24,
        }}>
          <div onClick={e => e.stopPropagation()} style={{
            background:'var(--surface)', border:'1px solid var(--border-soft)', borderRadius:14,
            width:'min(900px,95vw)', maxHeight:'90vh', display:'flex', flexDirection:'column',
            boxShadow:'0 24px 80px rgba(0,0,0,.4)',
          }}>
            <div className="ai-bar" style={{ borderRadius:'14px 14px 0 0' }}>
              <span className="t">
                <Icon name="brain" style={{ width:16, height:16, color:'var(--honey-deep)' }} /> Rapport IA — plein écran
              </span>
              <button onClick={() => setFullscreen(false)} style={{
                ...btnStyle, padding:'5px 12px', fontSize:13,
              }}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/>
                  <line x1="10" y1="14" x2="3" y2="21"/><line x1="21" y1="3" x2="14" y2="10"/>
                </svg>
                Fermer
              </button>
            </div>
            <div className="md" style={{ overflowY:'auto', padding:'16px 32px 32px', maxHeight:'none' }}
              dangerouslySetInnerHTML={{ __html: mdHtml }} />
          </div>
        </div>
      )}
    </>
  );
}

/* ============ DÉTAIL D'UNE CAMPAGNE ============ */
function CampaignDetailView({ id, go, themeToggle }) {
  const { data, loading, error, reload, fetchCampaignIOCs } = useHM();
  const [sheetIp, setSheetIp] = useState(null);
  const [ioc, setIoc] = useState(null);
  const [iocLoading, setIocLoading] = useState(false);

  if (loading) return <LoadingView themeToggle={themeToggle} />;
  if (error || !data) return <ErrorView message={error} onRetry={reload} themeToggle={themeToggle} />;

  const c = data.campaigns.find(x => x.id === id);
  if (!c) return <div className="main"><div className="content">Campagne introuvable.</div></div>;

  // Charger les IOC STIX au montage
  useEffect(() => {
    if (!fetchCampaignIOCs) return;
    setIocLoading(true);
    fetchCampaignIOCs(id).then(result => {
      setIoc(result);
      setIocLoading(false);
    }).catch(() => setIocLoading(false));
  }, [id]);

  const displayIoc = ioc || {
    ips: c.ips.slice(0, 6).map(ip => ip.ip),
    domains: [], urls: [], hashes: [],
  };

  const points = c.ips.map(ip => ({
    ip: ip.ip, lat: ip.lat, lon: ip.lon,
    weight: ip.connections, country: ip.country,
  }));

  const back = (
    <button onClick={() => go({ name: 'campaigns' })} title="Retour"
      style={{ display:'inline-flex', alignItems:'center', gap:7, height:36, padding:'0 14px',
        background:'var(--surface-2)', border:'1px solid var(--border-soft)', color:'var(--text-dim)',
        borderRadius:9, cursor:'pointer', font:'inherit', fontSize:13, whiteSpace:'nowrap' }}>
      <Icon name="chev" style={{ width:15, height:15, transform:'rotate(180deg)' }} /> Campagnes
    </button>
  );

  return (
    <div className="main">
      <PageHead crumb={<span><span className="cid">{c.id}</span> · {c.start} → {c.end}</span>}
        title={c.name} right={<>{back}{themeToggle}</>} />
      <div className="content">

        <div style={{ display:'flex', gap:10, marginBottom:22, flexWrap:'wrap', alignItems:'center' }}>
          <Status value={c.status} /><Severity level={c.severity} />
          {c.confidence !== undefined && (
            <span style={{ fontSize:12, color:'var(--text-faint)' }}>
              Confiance : {(c.confidence * 100).toFixed(0)}%
            </span>
          )}
        </div>

        <div className="stat-grid" style={{ marginBottom:4 }}>
          <Stat icon="globe"  label="IP attaquantes"   value={nf(c.attackingIps)}       accent="var(--c-teal)" />
          <Stat icon="pulse"  label="Sessions"          value={nf(c.connectionAttempts)} accent="var(--c-honey)" />
          <Stat icon="cmd"    label="Cmd. observées"    value={nf(c.commandsRun)}        accent="var(--c-violet)" />
          <Stat icon="file"   label="Fichiers IOC"      value={nf(c.filesTransferred)}   accent="var(--c-amber)" />
        </div>

        {points.length > 0 && (
          <>
            <SecH title="Géographie de la campagne" />
            <WorldMap points={points} height={280} />
          </>
        )}

        <div className="two-col" style={{ marginTop:24 }}>
          {/* Liste IP */}
          <div>
            <SecH title="Adresses IP" hint="Cliquez une IP pour le détail" />
            <div className="card tbl-wrap" style={{ maxHeight:460, overflowY:'auto' }}>
              <table className="tbl">
                <thead>
                  <tr><th>IP</th><th>Pays</th><th>ASN</th><th className="num">Sessions</th><th></th></tr>
                </thead>
                <tbody>
                  {c.ips.map(ip => (
                    <tr key={ip.ip} className="click" onClick={() => setSheetIp(ip)}>
                      <td className="ipcell" style={{ color:'var(--honey-deep)', fontWeight:600 }}>{ip.ip}</td>
                      <td style={{ fontSize:12.5, color:'var(--text-dim)' }}>
                        <span className="mono" style={{ color:'var(--text-faint)', marginRight:6 }}>{ip.code}</span>{ip.country}
                      </td>
                      <td style={{ fontSize:12, color:'var(--text-faint)', fontFamily:'var(--font-mono)' }}>{ip.asn}</td>
                      <td className="num">{ip.connections}</td>
                      <td>
                        <a href={D.vtIpUrl(ip.ip)} target="_blank" rel="noopener" className="mini-act"
                          onClick={e => e.stopPropagation()} title="VirusTotal">
                          <Icon name="ext" style={{ width:14, height:14 }} />
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

        </div>

        <SecH title="Analyse IA" hint="rapport généré par le LLM" />
        <AiReport campaignId={c.id} />

        {/* IOC */}
        <SecH title="Indicateurs de compromission (IOC)"
          hint={iocLoading ? 'chargement…' : 'extraits de la base STIX'} />
        {iocLoading
          ? <div style={{ display:'flex', justifyContent:'center', padding:32 }}><div className="spinner"></div></div>
          : <div className="ioc-grid">
              <IocCard title="Adresses IP"    icon="globe" items={displayIoc.ips}     vt={D.vtIpUrl} />
              <IocCard title="Domaines"       icon="globe" items={displayIoc.domains} vt={D.vtDomainUrl} />
              <IocCard title="URL"            icon="ext"   items={displayIoc.urls} />
              <IocCard title="Hash SHA-256"   icon="file"  items={displayIoc.hashes}  vt={D.vtHashUrl} truncate />
            </div>
        }

      </div>
      {sheetIp && <IpSheet ip={sheetIp} onClose={() => setSheetIp(null)} />}
    </div>
  );
}

function IocCard({ title, icon, items, vt, truncate }) {
  return (
    <div className="card ioc-card">
      <h4>
        <Icon name={icon} style={{ width:15, height:15, color:'var(--honey-deep)' }} /> {title}
        <span className="cnt">· {items.length}</span>
      </h4>
      {items.length === 0
        ? <p className="empty-note" style={{ margin:'8px 0 0' }}>Aucun</p>
        : <ul className="ioc-list">
            {items.map((v, i) => (
              <li key={i}>
                <span className="ioc-val" title={v}>{truncate ? v.slice(0,12) + '…' + v.slice(-8) : v}</span>
                <span className="ioc-act">
                  <CopyBtn text={v} />
                  {vt && <a href={vt(v)} target="_blank" rel="noopener" className="mini-act" title="VirusTotal">
                    <Icon name="ext" style={{ width:13, height:13 }} />
                  </a>}
                </span>
              </li>
            ))}
          </ul>
      }
    </div>
  );
}

/* ============ IOC VIEW ============ */

const IOC_TYPES = [
  { id: 'ipv4-addr',   label: 'Adresses IP',  icon: 'globe' },
  { id: 'url',         label: 'URL',           icon: 'ext'   },
  { id: 'domain-name', label: 'Domaines',      icon: 'globe' },
  { id: 'file',        label: 'Fichiers',      icon: 'file'  },
];

function parseStixIndicators(bundle) {
  const out = { 'ipv4-addr': [], url: [], 'domain-name': [], file: [] };
  if (!bundle?.objects) return out;
  for (const obj of bundle.objects) {
    if (obj.type !== 'indicator') continue;
    const type = obj.x_honeymind_ioc_type;
    if (!(type in out)) continue;
    // Extract value: last quoted token in pattern (avoids matching key names like 'SHA-256')
    const matches = [...(obj.pattern || '').matchAll(/'([^']+)'/g)];
    const value = matches.length ? matches[matches.length - 1][1] : '';
    if (!value) continue;
    out[type].push({
      value,
      confidence:        obj.confidence ?? 0,
      first_seen:        obj.x_honeymind_first_seen,
      last_seen:         obj.x_honeymind_last_seen,
      source_ips:        obj.x_honeymind_source_ips || [],
      campaign_ids:      obj.x_honeymind_campaign_ids || [],
      attack_categories: (obj.labels || []).filter(l => l !== 'honeypot'),
      context:           obj.x_honeymind_context || {},
    });
  }
  return out;
}

function _dlBlob(content, filename, mime) {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

function _csvEsc(v) {
  const s = String(v ?? '');
  return s.includes(',') || s.includes('"') || s.includes('\n') ? `"${s.replace(/"/g,'""')}"` : s;
}

function exportCsv(indicators) {
  const cols = ['type','value','confidence','first_seen','last_seen',
                'source_ips','campaign_ids','attack_categories','filename','transfer_method'];
  const rows = [cols.join(',')];
  for (const [type, iocs] of Object.entries(indicators)) {
    for (const ioc of iocs) {
      rows.push([
        type,
        ioc.value,
        ioc.confidence,
        ioc.first_seen || '',
        ioc.last_seen  || '',
        ioc.source_ips.join(';'),
        ioc.campaign_ids.join(';'),
        ioc.attack_categories.join(';'),
        ioc.context.filename        || '',
        ioc.context.transfer_method || '',
      ].map(_csvEsc).join(','));
    }
  }
  _dlBlob(rows.join('\r\n'),
    `honeymind-iocs-${new Date().toISOString().slice(0,10)}.csv`, 'text/csv');
}

function exportStix(bundle) {
  _dlBlob(JSON.stringify(bundle, null, 2),
    `honeymind-iocs-${new Date().toISOString().slice(0,10)}.stix.json`,
    'application/json');
}

const ExportBtn = ({ onClick, children }) => (
  <button onClick={onClick} style={{
    display:'inline-flex', alignItems:'center', gap:7, padding:'7px 14px',
    background:'var(--surface-2)', border:'1px solid var(--border-soft)',
    color:'var(--text-dim)', borderRadius:8, cursor:'pointer', fontSize:13,
    fontFamily:'inherit',
  }}>
    {children}
  </button>
);

function IocView({ themeToggle }) {
  const [raw, setRaw]         = React.useState(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError]     = React.useState(null);
  const [tab, setTab]         = React.useState('ipv4-addr');
  const [search, setSearch]   = React.useState('');

  const doLoad = React.useCallback(() => {
    setLoading(true); setError(null);
    fetch('/api/v1/iocs')
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(b => { setRaw(b); setLoading(false); })
      .catch(e => { setError(e.message); setLoading(false); });
  }, []);

  useEffect(() => { doLoad(); }, [doLoad]);

  const indicators = React.useMemo(() => parseStixIndicators(raw), [raw]);

  const filtered = React.useMemo(() => {
    const list = indicators[tab] || [];
    if (!search.trim()) return list;
    const q = search.toLowerCase();
    return list.filter(ioc =>
      ioc.value.toLowerCase().includes(q) ||
      ioc.source_ips.some(ip => ip.includes(q)) ||
      ioc.campaign_ids.some(c => c.toLowerCase().includes(q)) ||
      (ioc.context.filename || '').toLowerCase().includes(q) ||
      ioc.attack_categories.some(c => c.includes(q))
    );
  }, [indicators, tab, search]);

  if (loading) return <LoadingView themeToggle={themeToggle} />;
  if (error)   return <ErrorView message={error} onRetry={doLoad} themeToggle={themeToggle} />;

  const total = Object.values(indicators).reduce((s, a) => s + a.length, 0);

  return (
    <div className="main">
      <PageHead crumb="HoneyMind · Menaces" title="Indicateurs de compromission"
        right={
          <div style={{ display:'flex', gap:8, alignItems:'center' }}>
            <ExportBtn onClick={() => exportCsv(indicators)}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>
              </svg>
              CSV
            </ExportBtn>
            <ExportBtn onClick={() => exportStix(raw)}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>
              </svg>
              STIX 2.1
            </ExportBtn>
            <span style={{ fontSize:11.5, color:'var(--text-faint)', paddingLeft:4 }}>{nf(total)} IOC</span>
            {themeToggle}
          </div>
        }
      />
      <div className="content">

        {/* Stats */}
        <div className="stat-grid" style={{ marginBottom:24 }}>
          {IOC_TYPES.map(t => (
            <div key={t.id} className="card stat"
              style={{ cursor:'pointer', outline: tab===t.id ? '2px solid var(--honey)' : 'none', transition:'outline .1s' }}
              onClick={() => setTab(t.id)}>
              <div className="lbl">
                <Icon name={t.icon} className="nav-ic" style={{ color: tab===t.id ? 'var(--honey-deep)' : undefined }} />
                {t.label}
              </div>
              <div className="val">{nf(indicators[t.id].length)}</div>
            </div>
          ))}
        </div>

        {/* Tab bar + search */}
        <div style={{ display:'flex', gap:10, alignItems:'center', marginBottom:16, flexWrap:'wrap' }}>
          <div className="tg">
            {IOC_TYPES.map(t => (
              <button key={t.id} className={tab === t.id ? 'on' : ''} onClick={() => setTab(t.id)}>
                <Icon name={t.icon} style={{ width:14, height:14 }} /> {t.label}
              </button>
            ))}
          </div>
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Filtrer par valeur, IP, campagne…"
            style={{
              padding:'7px 13px', borderRadius:8, border:'1px solid var(--border-soft)',
              background:'var(--surface-2)', color:'var(--text)', font:'inherit', fontSize:13,
              outline:'none', minWidth:220, flex:1, maxWidth:360,
            }}
          />
          {search && (
            <span style={{ fontSize:12.5, color:'var(--text-faint)' }}>
              {filtered.length} résultat{filtered.length !== 1 ? 's' : ''}
            </span>
          )}
        </div>

        {/* Table */}
        {filtered.length === 0
          ? <div className="card" style={{ padding:32, textAlign:'center' }}>
              <p className="empty-note">Aucun IOC{search ? ' correspondant à la recherche' : ''}.</p>
            </div>
          : <div className="card tbl-wrap">
              {tab === 'ipv4-addr'   && <IocTableIp rows={filtered} />}
              {tab === 'url'         && <IocTableUrl rows={filtered} />}
              {tab === 'domain-name' && <IocTableDomain rows={filtered} />}
              {tab === 'file'        && <IocTableFile rows={filtered} />}
            </div>
        }

      </div>
    </div>
  );
}

/* ── IOC sub-tables ─────────────────────────────────────────────────────────── */

function CampList({ ids }) {
  if (!ids.length) return <span style={{ color:'var(--text-faint)', fontSize:12 }}>—</span>;
  return (
    <span style={{ display:'flex', gap:4, flexWrap:'wrap' }}>
      {ids.map(id => <span key={id} className="cid" style={{ fontSize:11.5 }}>{id}</span>)}
    </span>
  );
}

function CatList({ cats }) {
  if (!cats.length) return <span style={{ color:'var(--text-faint)', fontSize:12 }}>—</span>;
  return (
    <span style={{ display:'flex', gap:4, flexWrap:'wrap' }}>
      {cats.map(c => (
        <span key={c} style={{ fontSize:11, padding:'2px 7px', borderRadius:999,
          background:'var(--surface-2)', color:'var(--text-dim)', fontFamily:'var(--font-mono)' }}>
          {c.replace(/_/g,'-').toLowerCase()}
        </span>
      ))}
    </span>
  );
}

function FmtDate({ iso }) {
  if (!iso) return <span style={{ color:'var(--text-faint)' }}>—</span>;
  return <span style={{ fontSize:12, color:'var(--text-faint)', fontFamily:'var(--font-mono)' }}>{iso.slice(0,10)}</span>;
}

function IocTableIp({ rows }) {
  return (
    <table className="tbl">
      <thead><tr>
        <th>Adresse IP</th><th>Campagnes</th><th>Catégories</th>
        <th>Première vue</th><th>Dernière vue</th><th></th>
      </tr></thead>
      <tbody>
        {rows.map((r,i) => (
          <tr key={i}>
            <td className="ipcell" style={{ color:'var(--honey-deep)', fontWeight:600 }}>{r.value}</td>
            <td><CampList ids={r.campaign_ids} /></td>
            <td><CatList cats={r.attack_categories} /></td>
            <td><FmtDate iso={r.first_seen} /></td>
            <td><FmtDate iso={r.last_seen} /></td>
            <td><CopyBtn text={r.value} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function IocTableUrl({ rows }) {
  return (
    <table className="tbl">
      <thead><tr>
        <th>URL</th><th>Source IPs</th><th>Campagnes</th><th>Première vue</th><th></th>
      </tr></thead>
      <tbody>
        {rows.map((r,i) => (
          <tr key={i}>
            <td style={{ fontFamily:'var(--font-mono)', fontSize:12, maxWidth:380, wordBreak:'break-all' }}>
              {r.value}
            </td>
            <td style={{ fontSize:12, color:'var(--text-faint)' }}>{r.source_ips.join(', ') || '—'}</td>
            <td><CampList ids={r.campaign_ids} /></td>
            <td><FmtDate iso={r.first_seen} /></td>
            <td><CopyBtn text={r.value} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function IocTableDomain({ rows }) {
  return (
    <table className="tbl">
      <thead><tr>
        <th>Domaine</th><th>Source IPs</th><th>Campagnes</th><th>Première vue</th><th></th>
      </tr></thead>
      <tbody>
        {rows.map((r,i) => (
          <tr key={i}>
            <td style={{ fontFamily:'var(--font-mono)', fontWeight:600, color:'var(--honey-deep)' }}>{r.value}</td>
            <td style={{ fontSize:12, color:'var(--text-faint)' }}>{r.source_ips.join(', ') || '—'}</td>
            <td><CampList ids={r.campaign_ids} /></td>
            <td><FmtDate iso={r.first_seen} /></td>
            <td><CopyBtn text={r.value} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function IocTableFile({ rows }) {
  return (
    <table className="tbl">
      <thead><tr>
        <th>SHA-256</th><th>Fichier</th><th>Méthode</th><th>Source IPs</th><th>Campagnes</th><th>Première vue</th><th></th>
      </tr></thead>
      <tbody>
        {rows.map((r,i) => (
          <tr key={i}>
            <td style={{ fontFamily:'var(--font-mono)', fontSize:11.5, color:'var(--text-dim)' }} title={r.value}>
              {r.value.slice(0,12)}…{r.value.slice(-8)}
            </td>
            <td style={{ fontFamily:'var(--font-mono)', fontSize:12 }}>{r.context.filename || '—'}</td>
            <td>
              <span style={{ fontSize:11.5, padding:'2px 8px', borderRadius:999,
                background:'var(--surface-2)', color:'var(--text-dim)' }}>
                {r.context.transfer_method || '—'}
              </span>
            </td>
            <td style={{ fontSize:12, color:'var(--text-faint)' }}>{r.source_ips.join(', ') || '—'}</td>
            <td><CampList ids={r.campaign_ids} /></td>
            <td><FmtDate iso={r.first_seen} /></td>
            <td><CopyBtn text={r.value} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

Object.assign(window, { DashboardView, CampaignsView, CampaignDetailView, IocView });
