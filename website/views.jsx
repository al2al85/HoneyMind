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

          {/* Résumé IA */}
          <div>
            <SecH title="Synthèse IA" hint="rapport généré" />
            <div className="card ai-card">
              <div className="ai-bar">
                <span className="t">
                  <Icon name="brain" style={{ width:16, height:16, color:'var(--honey-deep)' }} /> Analyse automatisée
                </span>
                <span className="ai-pending">
                  <span className="dot-live" style={{ background:'var(--c-amber)' }}></span> aperçu — rapport à venir
                </span>
              </div>
              <div className="md" dangerouslySetInnerHTML={{ __html: D.mdToHtml(c.aiSummary) }} />
            </div>
          </div>
        </div>

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

Object.assign(window, { DashboardView, CampaignsView, CampaignDetailView });
