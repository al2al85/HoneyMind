/* HoneyMind — vues */
const HMD = window.HM_DATA;
const CH = ['var(--c-honey)', 'var(--c-amber)', 'var(--c-teal)', 'var(--c-violet)', 'var(--c-green)', 'var(--c-red)'];
const nf = n => n.toLocaleString('fr-FR');

function PageHead({ crumb, title, right }) {
  return (
    <div className="topbar">
      <div>
        <div className="crumb">{crumb}</div>
        <h1 className="page-title">{title}</h1>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>{right}</div>
    </div>
  );
}

function SecH({ title, hint }) {
  return <div className="sec-h"><h2>{title}</h2>{hint && <span className="hint">{hint}</span>}</div>;
}

/* ============ DASHBOARD ============ */
function DashboardView({ themeToggle }) {
  const s = HMD.stats;
  const countriesBar = HMD.topCountries.map(c => ({ label: c.name, code: c.code, value: c.attacks }));
  const cmdBar = HMD.topCommands.slice(0, 7).map(c => ({ label: c.label, value: c.count }));
  const peak = Math.max(...HMD.timeseries.map(d => d.attacks));

  return (
    <div className="main">
      <PageHead crumb="HoneyMind · Supervision" title="Dashboard" right={themeToggle} />
      <div className="content">

        <div className="card" style={{ padding: '22px 26px', marginBottom: 24, display: 'flex',
          gap: 22, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ flex: '1 1 360px', minWidth: 280 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 9, color: 'var(--honey-deep)',
              fontSize: 12.5, fontWeight: 600, letterSpacing: '.04em', textTransform: 'uppercase' }}>
              <Icon name="brain" width="16" height="16" /> Honeypot augmenté par IA
            </div>
            <p style={{ margin: '10px 0 0', fontSize: 15.5, color: 'var(--text-dim)', lineHeight: 1.6, maxWidth: 620 }}>
              HoneyMind expose des services leurres pour capturer les attaques réelles. Chaque session est
              journalisée, et une IA répond aux commandes complexes puis analyse l'ensemble des logs pour en
              extraire campagnes, indicateurs de compromission et synthèses exploitables.
            </p>
          </div>
        </div>

        <div className="stat-grid">
          <Stat icon="pulse"  label="Attaques totales"   value={nf(s.totalAttacks)} sub="tentatives de connexion" accent="var(--c-honey)" />
          <Stat icon="globe"  label="IP uniques"          value={nf(s.uniqueIps)}    sub="sources distinctes" accent="var(--c-teal)" />
          <Stat icon="layers" label="Campagnes actives"   value={s.activeCampaigns + ' / ' + s.totalCampaigns} sub="en cours de suivi" accent="var(--c-green)" />
          <Stat icon="cmd"    label="Commandes exécutées" value={nf(s.totalCommands)} sub="dans les sessions" accent="var(--c-violet)" />
          <Stat icon="file"   label="Fichiers transférés" value={nf(s.filesTransferred)} sub="upload / download" accent="var(--c-amber)" />
        </div>

        <SecH title="Origine des attaques" hint="Géolocalisation des IP source" />
        <WorldMap points={HMD.mapPoints} height={420} />

        <div className="two-col" style={{ marginTop: 24 }}>
          <div>
            <SecH title="Activité (30 derniers jours)" hint={'Pic : ' + nf(peak) + ' / jour'} />
            <div className="card" style={{ padding: '18px 18px 12px' }}>
              <AreaChart data={HMD.timeseries} height={170} />
            </div>
          </div>
          <div>
            <SecH title="Top commandes" hint="agrégé" />
            <div className="card" style={{ padding: '16px 18px' }}>
              <BarList data={cmdBar} colors={CH} />
            </div>
          </div>
        </div>

        <SecH title="Pays les plus actifs" hint="par volume de connexions" />
        <div className="card" style={{ padding: '18px 22px' }}>
          <BarList data={countriesBar} colors={CH} showFlag />
        </div>

      </div>
    </div>
  );
}

/* ============ LISTE DES CAMPAGNES ============ */
function CampaignsView({ go, themeToggle }) {
  const cols = [
    { k: 'id', label: 'Campagne' },
    { k: 'status', label: 'Statut' },
    { k: 'attackingIps', label: 'IP attaq.', num: true },
    { k: 'connectionAttempts', label: 'Tentatives', num: true },
    { k: 'successfulConnections', label: 'Réussies', num: true },
    { k: 'commandsRun', label: 'Commandes', num: true },
    { k: 'filesTransferred', label: 'Fichiers', num: true },
    { k: 'severity', label: 'Sévérité' },
  ];
  return (
    <div className="main">
      <PageHead crumb="HoneyMind · Analyse" title="Campagnes" right={themeToggle} />
      <div className="content">
        <SecH title={HMD.campaigns.length + ' campagnes détectées'} hint="Cliquez une ligne pour le détail" />
        <div className="card tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>{cols.map(c => <th key={c.k} className={c.num ? 'num' : ''}>{c.label}</th>)}<th></th></tr>
            </thead>
            <tbody>
              {HMD.campaigns.map(c => (
                <tr key={c.id} className="click" onClick={() => go({ name: 'campaign', id: c.id })}>
                  <td>
                    <div className="cid">{c.id}</div>
                    <div style={{ color: 'var(--text-faint)', fontSize: 12 }}>{c.name} · {c.start}</div>
                  </td>
                  <td><Status value={c.status} /></td>
                  <td className="num">{nf(c.attackingIps)}</td>
                  <td className="num">{nf(c.connectionAttempts)}</td>
                  <td className="num">{nf(c.successfulConnections)}</td>
                  <td className="num">{nf(c.commandsRun)}</td>
                  <td className="num">{nf(c.filesTransferred)}</td>
                  <td><Severity level={c.severity} /></td>
                  <td style={{ color: 'var(--text-faint)' }}><Icon name="chev" width="16" height="16" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

/* ============ DÉTAIL D'UNE CAMPAGNE ============ */
function CampaignDetailView({ id, go, themeToggle }) {
  const c = HMD.campaigns.find(x => x.id === id);
  const [sheetIp, setSheetIp] = useState(null);
  if (!c) return <div className="main"><div className="content">Campagne introuvable.</div></div>;

  const points = c.ips.map(ip => ({ ip: ip.ip, lat: ip.lat, lon: ip.lon, weight: ip.connections, country: ip.country }));

  const back = (
    <button onClick={() => go({ name: 'campaigns' })} title="Retour"
      style={{ display: 'inline-flex', alignItems: 'center', gap: 7, height: 36, padding: '0 14px',
        background: 'var(--surface-2)', border: '1px solid var(--border-soft)', color: 'var(--text-dim)',
        borderRadius: 9, cursor: 'pointer', font: 'inherit', fontSize: 13, whiteSpace: 'nowrap' }}>
      <Icon name="chev" width="15" height="15" style={{ transform: 'rotate(180deg)' }} /> Campagnes
    </button>
  );

  return (
    <div className="main">
      <PageHead crumb={<span><span className="cid">{c.id}</span> · {c.start} → {c.end}</span>} title={c.name}
        right={<>{back}{themeToggle}</>} />
      <div className="content">

        <div style={{ display: 'flex', gap: 10, marginBottom: 22, flexWrap: 'wrap', alignItems: 'center' }}>
          <Status value={c.status} /><Severity level={c.severity} />
        </div>

        <div className="stat-grid" style={{ marginBottom: 4 }}>
          <Stat icon="globe"  label="IP attaquantes"   value={nf(c.attackingIps)} accent="var(--c-teal)" />
          <Stat icon="pulse"  label="Tentatives"       value={nf(c.connectionAttempts)} accent="var(--c-honey)" />
          <Stat icon="shield" label="Réussies"          value={nf(c.successfulConnections)} accent="var(--c-green)" />
          <Stat icon="cmd"    label="Commandes"         value={nf(c.commandsRun)} accent="var(--c-violet)" />
          <Stat icon="file"   label="Fichiers"          value={nf(c.filesTransferred)} accent="var(--c-amber)" />
        </div>

        <div className="two-col" style={{ marginTop: 24 }}>
          {/* Liste des IP */}
          <div>
            <SecH title="Adresses IP" hint="Cliquez une IP pour le détail" />
            <div className="card tbl-wrap" style={{ maxHeight: 460, overflowY: 'auto' }}>
              <table className="tbl">
                <thead><tr><th>IP</th><th>Pays</th><th className="num">Conn.</th><th className="num">Cmd.</th><th></th></tr></thead>
                <tbody>
                  {c.ips.map(ip => (
                    <tr key={ip.ip} className="click" onClick={() => setSheetIp(ip)}>
                      <td className="ipcell" style={{ color: 'var(--honey-deep)', fontWeight: 600 }}>{ip.ip}</td>
                      <td style={{ fontSize: 12.5, color: 'var(--text-dim)' }}><span className="mono" style={{ color: 'var(--text-faint)', marginRight: 6 }}>{ip.code}</span>{ip.country}</td>
                      <td className="num">{ip.connections}</td>
                      <td className="num">{ip.commands}</td>
                      <td><a href={HMD.vtIpUrl(ip.ip)} target="_blank" rel="noopener" className="mini-act"
                        onClick={e => e.stopPropagation()} title="VirusTotal"><Icon name="ext" /></a></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Résumé IA */}
          <div>
            <SecH title="Synthèse IA" hint="rapport .md" />
            <div className="card ai-card">
              <div className="ai-bar">
                <span className="t"><Icon name="brain" width="16" height="16" style={{ color: 'var(--honey-deep)' }} /> Analyse automatisée</span>
                <span className="ai-pending"><span className="dot-live" style={{ background: 'var(--c-amber)' }}></span> aperçu — rapport à venir</span>
              </div>
              <div className="md" dangerouslySetInnerHTML={{ __html: HMD.mdToHtml(c.aiSummary) }} />
            </div>
          </div>
        </div>

        {/* IOC */}
        <SecH title="Indicateurs de compromission (IOC)" hint="extraits par l'analyse" />
        <div className="ioc-grid">
          <IocCard title="Adresses IP" icon="globe" items={c.ioc.ips} vt={HMD.vtIpUrl} />
          <IocCard title="Domaines" icon="globe" items={c.ioc.domains} vt={HMD.vtDomainUrl} />
          <IocCard title="URL" icon="ext" items={c.ioc.urls} />
          <IocCard title="Hash SHA-256" icon="file" items={c.ioc.hashes} vt={HMD.vtHashUrl} truncate />
        </div>

      </div>
      {sheetIp && <IpSheet ip={sheetIp} onClose={() => setSheetIp(null)} />}
    </div>
  );
}

function IocCard({ title, icon, items, vt, truncate }) {
  return (
    <div className="card ioc-card">
      <h4><Icon name={icon} width="15" height="15" style={{ color: 'var(--honey-deep)' }} /> {title}
        <span className="cnt">· {items.length}</span></h4>
      <ul className="ioc-list">
        {items.map((v, i) => (
          <li key={i}>
            <span className="ioc-val" title={v}>{truncate ? v.slice(0, 12) + '…' + v.slice(-8) : v}</span>
            <span className="ioc-act">
              <CopyBtn text={v} />
              {vt && <a href={vt(v)} target="_blank" rel="noopener" className="mini-act" title="VirusTotal"><Icon name="ext" /></a>}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

Object.assign(window, { DashboardView, CampaignsView, CampaignDetailView });
