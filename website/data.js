/* HoneyMind — config statique : grille carte, centroides pays, utilitaires.
   Les données dynamiques sont chargées via l'API dans app.jsx (DataProvider). */

(function () {

  // ── Centroides pays (ISO 3166-1 alpha-2 → lat/lon approximatif + nom FR) ──
  const CENTROIDS = {
    AD:{lat:42.55,lon:1.60,name:'Andorre'},       AE:{lat:23.42,lon:53.85,name:'Émirats arabes unis'},
    AF:{lat:33.94,lon:67.71,name:'Afghanistan'},   AL:{lat:41.15,lon:20.17,name:'Albanie'},
    AM:{lat:40.07,lon:45.04,name:'Arménie'},       AO:{lat:-11.20,lon:17.87,name:'Angola'},
    AR:{lat:-38.42,lon:-63.62,name:'Argentine'},   AT:{lat:47.52,lon:14.55,name:'Autriche'},
    AU:{lat:-25.27,lon:133.78,name:'Australie'},   AZ:{lat:40.14,lon:47.58,name:'Azerbaïdjan'},
    BA:{lat:43.92,lon:17.68,name:'Bosnie-Herzégovine'},BB:{lat:13.19,lon:-59.54,name:'Barbade'},
    BD:{lat:23.68,lon:90.36,name:'Bangladesh'},    BE:{lat:50.50,lon:4.47,name:'Belgique'},
    BF:{lat:12.36,lon:-1.56,name:'Burkina Faso'},  BG:{lat:42.73,lon:25.49,name:'Bulgarie'},
    BH:{lat:26.00,lon:50.55,name:'Bahreïn'},       BI:{lat:-3.37,lon:29.92,name:'Burundi'},
    BJ:{lat:9.31,lon:2.32,name:'Bénin'},           BN:{lat:4.54,lon:114.73,name:'Brunéi'},
    BO:{lat:-16.29,lon:-63.59,name:'Bolivie'},     BR:{lat:-14.24,lon:-51.93,name:'Brésil'},
    BS:{lat:25.03,lon:-77.40,name:'Bahamas'},      BT:{lat:27.51,lon:90.43,name:'Bhoutan'},
    BW:{lat:-22.33,lon:24.68,name:'Botswana'},     BY:{lat:53.71,lon:27.95,name:'Biélorussie'},
    BZ:{lat:17.19,lon:-88.50,name:'Belize'},       CA:{lat:56.13,lon:-106.35,name:'Canada'},
    CD:{lat:-4.04,lon:21.76,name:'Congo (RDC)'},   CF:{lat:6.61,lon:20.94,name:'Centrafrique'},
    CG:{lat:-0.23,lon:15.83,name:'Congo'},         CH:{lat:46.82,lon:8.23,name:'Suisse'},
    CI:{lat:7.54,lon:-5.55,name:"Côte d'Ivoire"},  CL:{lat:-35.68,lon:-71.54,name:'Chili'},
    CM:{lat:3.85,lon:11.50,name:'Cameroun'},       CN:{lat:35.86,lon:104.20,name:'Chine'},
    CO:{lat:4.57,lon:-74.30,name:'Colombie'},      CR:{lat:9.75,lon:-83.75,name:'Costa Rica'},
    CU:{lat:21.52,lon:-77.78,name:'Cuba'},         CY:{lat:35.13,lon:33.43,name:'Chypre'},
    CZ:{lat:49.82,lon:15.47,name:'Tchéquie'},      DE:{lat:51.17,lon:10.45,name:'Allemagne'},
    DJ:{lat:11.83,lon:42.59,name:'Djibouti'},      DK:{lat:56.26,lon:9.50,name:'Danemark'},
    DO:{lat:18.74,lon:-70.16,name:'Rép. dominicaine'},DZ:{lat:28.03,lon:1.66,name:'Algérie'},
    EC:{lat:-1.83,lon:-78.18,name:'Équateur'},     EE:{lat:58.60,lon:25.01,name:'Estonie'},
    EG:{lat:26.82,lon:30.80,name:'Égypte'},        ES:{lat:40.46,lon:-3.75,name:'Espagne'},
    ET:{lat:9.15,lon:40.49,name:'Éthiopie'},       FI:{lat:61.92,lon:25.75,name:'Finlande'},
    FJ:{lat:-16.58,lon:179.41,name:'Fidji'},       FR:{lat:46.23,lon:2.21,name:'France'},
    GA:{lat:-0.80,lon:11.61,name:'Gabon'},         GB:{lat:55.38,lon:-3.44,name:'Royaume-Uni'},
    GE:{lat:42.32,lon:43.36,name:'Géorgie'},       GH:{lat:7.95,lon:-1.02,name:'Ghana'},
    GR:{lat:39.07,lon:21.82,name:'Grèce'},         GT:{lat:15.78,lon:-90.23,name:'Guatemala'},
    GY:{lat:4.86,lon:-58.93,name:'Guyana'},        HN:{lat:15.20,lon:-86.24,name:'Honduras'},
    HR:{lat:45.10,lon:15.20,name:'Croatie'},       HT:{lat:18.97,lon:-72.29,name:'Haïti'},
    HU:{lat:47.16,lon:19.50,name:'Hongrie'},       ID:{lat:-0.79,lon:113.92,name:'Indonésie'},
    IE:{lat:53.41,lon:-8.24,name:'Irlande'},       IL:{lat:31.05,lon:34.85,name:'Israël'},
    IN:{lat:20.59,lon:78.96,name:'Inde'},          IQ:{lat:33.22,lon:43.68,name:'Irak'},
    IR:{lat:32.43,lon:53.69,name:'Iran'},          IS:{lat:64.96,lon:-19.02,name:'Islande'},
    IT:{lat:41.87,lon:12.57,name:'Italie'},        JM:{lat:18.11,lon:-77.30,name:'Jamaïque'},
    JO:{lat:30.59,lon:36.24,name:'Jordanie'},      JP:{lat:36.20,lon:138.25,name:'Japon'},
    KE:{lat:-0.02,lon:37.91,name:'Kenya'},         KG:{lat:41.20,lon:74.77,name:'Kirghizstan'},
    KH:{lat:12.57,lon:104.99,name:'Cambodge'},     KP:{lat:40.34,lon:127.51,name:'Corée du Nord'},
    KR:{lat:35.91,lon:127.77,name:'Corée du Sud'}, KW:{lat:29.31,lon:47.48,name:'Koweït'},
    KZ:{lat:48.02,lon:66.92,name:'Kazakhstan'},    LA:{lat:19.86,lon:102.50,name:'Laos'},
    LB:{lat:33.85,lon:35.86,name:'Liban'},         LI:{lat:47.17,lon:9.56,name:'Liechtenstein'},
    LK:{lat:7.87,lon:80.77,name:'Sri Lanka'},      LR:{lat:6.43,lon:-9.43,name:'Libéria'},
    LS:{lat:-29.61,lon:28.23,name:'Lesotho'},      LT:{lat:55.17,lon:23.88,name:'Lituanie'},
    LU:{lat:49.82,lon:6.13,name:'Luxembourg'},     LV:{lat:56.88,lon:24.60,name:'Lettonie'},
    LY:{lat:26.34,lon:17.23,name:'Libye'},         MA:{lat:31.79,lon:-7.09,name:'Maroc'},
    MD:{lat:47.41,lon:28.37,name:'Moldavie'},      ME:{lat:42.71,lon:19.37,name:'Monténégro'},
    MG:{lat:-18.77,lon:46.87,name:'Madagascar'},   MK:{lat:41.61,lon:21.75,name:'Macédoine du Nord'},
    ML:{lat:17.57,lon:-4.00,name:'Mali'},          MM:{lat:21.91,lon:95.96,name:'Myanmar'},
    MN:{lat:46.86,lon:103.85,name:'Mongolie'},     MR:{lat:21.01,lon:-10.94,name:'Mauritanie'},
    MT:{lat:35.94,lon:14.38,name:'Malte'},         MU:{lat:-20.35,lon:57.55,name:'Maurice'},
    MV:{lat:3.20,lon:73.22,name:'Maldives'},       MW:{lat:-13.25,lon:34.30,name:'Malawi'},
    MX:{lat:23.63,lon:-102.55,name:'Mexique'},     MY:{lat:4.21,lon:101.98,name:'Malaisie'},
    MZ:{lat:-18.67,lon:35.53,name:'Mozambique'},   NA:{lat:-22.96,lon:18.49,name:'Namibie'},
    NE:{lat:17.61,lon:8.08,name:'Niger'},          NG:{lat:9.08,lon:8.68,name:'Nigéria'},
    NI:{lat:12.87,lon:-85.21,name:'Nicaragua'},    NL:{lat:52.13,lon:5.29,name:'Pays-Bas'},
    NO:{lat:60.47,lon:8.47,name:'Norvège'},        NP:{lat:28.39,lon:84.12,name:'Népal'},
    NZ:{lat:-40.90,lon:174.89,name:'Nouvelle-Zélande'},OM:{lat:21.51,lon:55.92,name:'Oman'},
    PA:{lat:8.54,lon:-80.78,name:'Panama'},        PE:{lat:-9.19,lon:-75.02,name:'Pérou'},
    PH:{lat:12.88,lon:121.77,name:'Philippines'},  PK:{lat:30.38,lon:69.35,name:'Pakistan'},
    PL:{lat:51.92,lon:19.15,name:'Pologne'},       PT:{lat:39.40,lon:-8.22,name:'Portugal'},
    PY:{lat:-23.44,lon:-58.44,name:'Paraguay'},    QA:{lat:25.35,lon:51.18,name:'Qatar'},
    RO:{lat:45.94,lon:24.97,name:'Roumanie'},      RS:{lat:44.02,lon:21.01,name:'Serbie'},
    RU:{lat:61.52,lon:105.32,name:'Russie'},       RW:{lat:-1.94,lon:29.87,name:'Rwanda'},
    SA:{lat:23.89,lon:45.08,name:'Arabie saoudite'},SB:{lat:-9.65,lon:160.16,name:'Salomon'},
    SD:{lat:12.86,lon:30.22,name:'Soudan'},        SE:{lat:60.13,lon:18.64,name:'Suède'},
    SG:{lat:1.35,lon:103.82,name:'Singapour'},     SI:{lat:46.15,lon:14.99,name:'Slovénie'},
    SK:{lat:48.67,lon:19.70,name:'Slovaquie'},     SL:{lat:8.46,lon:-11.78,name:'Sierra Leone'},
    SN:{lat:14.50,lon:-14.45,name:'Sénégal'},      SO:{lat:5.15,lon:46.20,name:'Somalie'},
    SR:{lat:3.92,lon:-56.03,name:'Suriname'},      SS:{lat:6.88,lon:31.31,name:'Soudan du Sud'},
    SV:{lat:13.79,lon:-88.90,name:'Salvador'},     SY:{lat:34.80,lon:39.00,name:'Syrie'},
    SZ:{lat:-26.52,lon:31.47,name:'Eswatini'},     TD:{lat:15.45,lon:18.73,name:'Tchad'},
    TG:{lat:8.62,lon:0.82,name:'Togo'},            TH:{lat:15.87,lon:100.99,name:'Thaïlande'},
    TJ:{lat:38.86,lon:71.28,name:'Tadjikistan'},   TM:{lat:38.97,lon:59.56,name:'Turkménistan'},
    TN:{lat:33.89,lon:9.54,name:'Tunisie'},        TR:{lat:38.96,lon:35.24,name:'Turquie'},
    TT:{lat:10.69,lon:-61.22,name:'Trinité-et-Tobago'},TZ:{lat:-6.37,lon:34.89,name:'Tanzanie'},
    UA:{lat:48.38,lon:31.17,name:'Ukraine'},       UG:{lat:1.37,lon:32.29,name:'Ouganda'},
    US:{lat:37.09,lon:-95.71,name:'États-Unis'},   UY:{lat:-32.52,lon:-55.77,name:'Uruguay'},
    UZ:{lat:41.38,lon:64.59,name:'Ouzbékistan'},   VE:{lat:6.42,lon:-66.59,name:'Venezuela'},
    VN:{lat:14.06,lon:108.28,name:'Vietnam'},      YE:{lat:15.55,lon:48.52,name:'Yémen'},
    ZA:{lat:-30.56,lon:22.94,name:'Afrique du Sud'},ZM:{lat:-13.13,lon:27.85,name:'Zambie'},
    ZW:{lat:-19.02,lon:29.15,name:'Zimbabwe'},
  };

  // ── Grille carte monde (matrice de points équirectangulaire) ────────────────
  // lon -180..180 (5°/col) ; lat 84..-60 (4°/row) ; 72×36 cellules
  const MAP_W = 72, MAP_H = 36;
  const MAP_LAT_TOP = 84, MAP_LAT_BOT = -60;
  const landRanges = {
    1:[[28,31]],2:[[10,14],[27,32]],3:[[8,16],[27,33],[44,52]],
    4:[[6,24],[27,32],[40,68]],5:[[4,9],[10,25],[37,42],[44,70]],
    6:[[5,24],[26,30],[34,44],[46,70]],7:[[6,23],[33,45],[47,70]],
    8:[[8,22],[33,46],[48,69]],9:[[10,22],[33,46],[50,68]],
    10:[[11,21],[34,38],[40,46],[52,66]],11:[[12,21],[35,38],[40,47],[52,66]],
    12:[[13,20],[33,47],[52,64],[63,65]],13:[[14,19],[32,48],[50,54],[55,63]],
    14:[[15,18],[32,47],[50,54],[56,60]],15:[[16,18],[32,46],[50,54]],
    16:[[17,19],[33,45],[51,54]],17:[[18,20],[33,44],[55,58]],
    18:[[19,28],[34,44],[56,60]],19:[[20,29],[35,44],[57,62]],
    20:[[20,29],[36,44],[57,64]],21:[[20,29],[37,43],[58,64]],
    22:[[21,29],[37,43],[59,63]],23:[[21,28],[38,43],[59,67]],
    24:[[21,28],[38,43],[60,67]],25:[[22,27],[38,43],[59,67]],
    26:[[22,27],[38,43],[59,67]],27:[[23,26],[39,43],[59,66]],
    28:[[23,26],[39,42],[60,66]],29:[[23,25],[39,42],[61,65]],
    30:[[23,25],[62,64]],31:[[23,25]],32:[[23,24]],33:[[23,24]],34:[[24,24]],
  };
  function isLand(row, col) {
    const ranges = landRanges[row];
    if (!ranges) return false;
    return ranges.some(([a, b]) => col >= a && col <= b);
  }
  function project(lat, lon) {
    const x = ((lon + 180) / 360) * 100;
    const y = ((MAP_LAT_TOP - lat) / (MAP_LAT_TOP - MAP_LAT_BOT)) * 100;
    return { x: Math.max(0, Math.min(100, x)), y: Math.max(0, Math.min(100, y)) };
  }

  // ── Mini moteur Markdown → HTML ─────────────────────────────────────────────
  function mdToHtml(md) {
    const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const inline = t => esc(t)
      .replace(/`([^`]+)`/g,'<code>$1</code>')
      .replace(/\*\*([^*]+)\*\*/g,'<strong>$1</strong>')
      .replace(/\*([^*]+)\*/g,'<em>$1</em>')
      .replace(/_([^_]+)_/g,'<em>$1</em>');

    // Pre-pass: collect table blocks (consecutive lines containing |)
    const isTableRow  = l => /^\s*\|.+\|/.test(l);
    const isSepRow    = l => /^\s*\|[\s|:-]+\|/.test(l);

    const lines = md.split('\n');
    let html = '', inUl = false, inOl = false, inCode = false, inTable = false;
    let tableHead = null;

    const closeLists = () => {
      if (inUl) { html += '</ul>'; inUl = false; }
      if (inOl) { html += '</ol>'; inOl = false; }
    };
    const closeTable = () => {
      if (inTable) { html += '</tbody></table></div>'; inTable = false; tableHead = null; }
    };
    const parseRow = (line, tag) => {
      const cells = line.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|');
      return '<tr>' + cells.map(c => `<${tag}>${inline(c.trim())}</${tag}>`).join('') + '</tr>';
    };

    for (let i = 0; i < lines.length; i++) {
      const raw = lines[i];

      // Code blocks
      if (raw.trim().startsWith('```')) {
        closeLists(); closeTable();
        if (!inCode) { html += '<pre><code>'; inCode = true; }
        else { html += '</code></pre>'; inCode = false; }
        continue;
      }
      if (inCode) { html += esc(raw) + '\n'; continue; }

      const line = raw.trim();

      // Table detection: header row followed by separator row
      if (!inTable && isTableRow(raw) && i + 1 < lines.length && isSepRow(lines[i + 1])) {
        closeLists();
        tableHead = parseRow(raw, 'th');
        i++; // skip separator
        html += `<div style="overflow-x:auto;margin:14px 0"><table style="margin:0"><thead>${tableHead}</thead><tbody>`;
        inTable = true;
        continue;
      }
      if (inTable) {
        if (isTableRow(raw)) {
          html += parseRow(raw, 'td');
          continue;
        }
        closeTable();
      }

      if (line === '') { closeLists(); continue; }
      if (/^---+$/.test(line)) { closeLists(); html += '<hr>'; continue; }
      if (line.startsWith('### ')) { closeLists(); html += `<h3>${inline(line.slice(4))}</h3>`; continue; }
      if (line.startsWith('## '))  { closeLists(); html += `<h2>${inline(line.slice(3))}</h2>`; continue; }
      if (line.startsWith('# '))   { closeLists(); html += `<h1>${inline(line.slice(2))}</h1>`; continue; }
      if (line.startsWith('> '))   { closeLists(); html += `<blockquote>${inline(line.slice(2))}</blockquote>`; continue; }
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
    closeLists(); closeTable();
    if (inCode) html += '</code></pre>';
    return html;
  }

  window.HM_DATA = {
    map: { W: MAP_W, H: MAP_H, isLand, project },
    centroids: CENTROIDS,
    mdToHtml,
    vtIpUrl:     ip => `https://www.virustotal.com/gui/ip-address/${ip}`,
    vtHashUrl:   h  => `https://www.virustotal.com/gui/file/${h}`,
    vtDomainUrl: d  => `https://www.virustotal.com/gui/domain/${d}`,
  };
})();
