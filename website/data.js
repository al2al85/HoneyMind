/* HoneyMind — config statique : grille carte, centroides pays, utilitaires.
   Les données dynamiques sont chargées via l'API dans app.jsx (DataProvider). */

(function () {

  // ── Centroides pays (ISO 3166-1 alpha-2 → lat/lon approximatif + nom FR) ──
  const CENTROIDS = {
    AD:{lat:42.5,lon:1.5,name:'Andorre'},      AE:{lat:24,lon:54,name:'Émirats arabes unis'},
    AF:{lat:33,lon:65,name:'Afghanistan'},      AL:{lat:41,lon:20,name:'Albanie'},
    AM:{lat:40,lon:45,name:'Arménie'},          AO:{lat:-12.5,lon:18.5,name:'Angola'},
    AR:{lat:-34,lon:-64,name:'Argentine'},      AT:{lat:47.3,lon:13.3,name:'Autriche'},
    AU:{lat:-27,lon:133,name:'Australie'},      AZ:{lat:40.5,lon:47.5,name:'Azerbaïdjan'},
    BA:{lat:44,lon:17,name:'Bosnie-Herzégovine'},BB:{lat:13.2,lon:-59.5,name:'Barbade'},
    BD:{lat:24,lon:90,name:'Bangladesh'},       BE:{lat:50.8,lon:4.5,name:'Belgique'},
    BF:{lat:13,lon:-2,name:'Burkina Faso'},     BG:{lat:42.7,lon:25.5,name:'Bulgarie'},
    BH:{lat:26,lon:50.5,name:'Bahreïn'},        BI:{lat:-3.5,lon:30,name:'Burundi'},
    BJ:{lat:9.3,lon:2.3,name:'Bénin'},          BN:{lat:4.5,lon:114.7,name:'Brunéi'},
    BO:{lat:-17,lon:-65,name:'Bolivie'},         BR:{lat:-10,lon:-52,name:'Brésil'},
    BS:{lat:24.3,lon:-76,name:'Bahamas'},        BT:{lat:27.5,lon:90.5,name:'Bhoutan'},
    BW:{lat:-22,lon:24,name:'Botswana'},         BY:{lat:53,lon:28,name:'Biélorussie'},
    BZ:{lat:17.3,lon:-88.7,name:'Belize'},       CA:{lat:60,lon:-95,name:'Canada'},
    CD:{lat:-4,lon:25,name:'Congo (RDC)'},       CF:{lat:7,lon:21,name:'Centrafrique'},
    CG:{lat:-1,lon:15,name:'Congo'},             CH:{lat:47,lon:8.3,name:'Suisse'},
    CI:{lat:7.5,lon:-5.5,name:"Côte d'Ivoire"}, CL:{lat:-30,lon:-71,name:'Chili'},
    CM:{lat:6,lon:12,name:'Cameroun'},           CN:{lat:35,lon:105,name:'Chine'},
    CO:{lat:4,lon:-73,name:'Colombie'},          CR:{lat:10,lon:-84,name:'Costa Rica'},
    CU:{lat:21.5,lon:-79.5,name:'Cuba'},         CY:{lat:35,lon:33,name:'Chypre'},
    CZ:{lat:50,lon:15.5,name:'Tchéquie'},        DE:{lat:51,lon:10,name:'Allemagne'},
    DJ:{lat:11.5,lon:43,name:'Djibouti'},        DK:{lat:56,lon:10,name:'Danemark'},
    DO:{lat:19,lon:-70.5,name:'Rép. dominicaine'},DZ:{lat:28,lon:3,name:'Algérie'},
    EC:{lat:-2,lon:-77.5,name:'Équateur'},       EE:{lat:59,lon:25,name:'Estonie'},
    EG:{lat:27,lon:30,name:'Égypte'},            ES:{lat:40,lon:-4,name:'Espagne'},
    ET:{lat:8,lon:38,name:'Éthiopie'},           FI:{lat:64,lon:26,name:'Finlande'},
    FJ:{lat:-18,lon:178,name:'Fidji'},           FR:{lat:46,lon:2,name:'France'},
    GA:{lat:-1,lon:11.8,name:'Gabon'},           GB:{lat:54,lon:-2,name:'Royaume-Uni'},
    GE:{lat:42,lon:43.5,name:'Géorgie'},         GH:{lat:8,lon:-1,name:'Ghana'},
    GR:{lat:39,lon:22,name:'Grèce'},             GT:{lat:15.5,lon:-90.3,name:'Guatemala'},
    GY:{lat:5,lon:-59,name:'Guyana'},            HN:{lat:15,lon:-86.5,name:'Honduras'},
    HR:{lat:45.1,lon:15.5,name:'Croatie'},       HT:{lat:19,lon:-72.5,name:'Haïti'},
    HU:{lat:47,lon:19.5,name:'Hongrie'},         ID:{lat:-2,lon:118,name:'Indonésie'},
    IE:{lat:53,lon:-8,name:'Irlande'},           IL:{lat:31.5,lon:35,name:'Israël'},
    IN:{lat:22,lon:78,name:'Inde'},              IQ:{lat:33,lon:44,name:'Irak'},
    IR:{lat:32,lon:53,name:'Iran'},              IS:{lat:65,lon:-18,name:'Islande'},
    IT:{lat:42.8,lon:12.8,name:'Italie'},        JM:{lat:18.2,lon:-77.3,name:'Jamaïque'},
    JO:{lat:31,lon:36.5,name:'Jordanie'},        JP:{lat:36,lon:138,name:'Japon'},
    KE:{lat:1,lon:38,name:'Kenya'},              KG:{lat:41,lon:75,name:'Kirghizstan'},
    KH:{lat:13,lon:105,name:'Cambodge'},         KP:{lat:40,lon:127,name:'Corée du Nord'},
    KR:{lat:36,lon:128,name:'Corée du Sud'},     KW:{lat:29.5,lon:47.8,name:'Koweït'},
    KZ:{lat:48,lon:68,name:'Kazakhstan'},        LA:{lat:18,lon:103,name:'Laos'},
    LB:{lat:33.9,lon:35.5,name:'Liban'},         LI:{lat:47.2,lon:9.5,name:'Liechtenstein'},
    LK:{lat:7.9,lon:80.7,name:'Sri Lanka'},      LR:{lat:6.5,lon:-9.5,name:'Libéria'},
    LS:{lat:-29.5,lon:28.3,name:'Lesotho'},      LT:{lat:56,lon:24,name:'Lituanie'},
    LU:{lat:49.8,lon:6.1,name:'Luxembourg'},     LV:{lat:57,lon:25,name:'Lettonie'},
    LY:{lat:25,lon:17,name:'Libye'},             MA:{lat:32,lon:-5,name:'Maroc'},
    MD:{lat:47,lon:29,name:'Moldavie'},          ME:{lat:42.8,lon:19.5,name:'Monténégro'},
    MG:{lat:-20,lon:47,name:'Madagascar'},       MK:{lat:41.6,lon:21.7,name:'Macédoine du Nord'},
    ML:{lat:17,lon:-4,name:'Mali'},              MM:{lat:22,lon:96,name:'Myanmar'},
    MN:{lat:46,lon:105,name:'Mongolie'},         MR:{lat:20,lon:-12,name:'Mauritanie'},
    MT:{lat:35.9,lon:14.4,name:'Malte'},         MU:{lat:-20.3,lon:57.6,name:'Maurice'},
    MV:{lat:4.2,lon:73.5,name:'Maldives'},       MW:{lat:-13.5,lon:34,name:'Malawi'},
    MX:{lat:23,lon:-102,name:'Mexique'},         MY:{lat:2.5,lon:112.5,name:'Malaisie'},
    MZ:{lat:-18,lon:35,name:'Mozambique'},       NA:{lat:-22,lon:17,name:'Namibie'},
    NE:{lat:16,lon:8,name:'Niger'},              NG:{lat:9,lon:8,name:'Nigéria'},
    NI:{lat:13,lon:-85,name:'Nicaragua'},        NL:{lat:52,lon:5,name:'Pays-Bas'},
    NO:{lat:62,lon:10,name:'Norvège'},           NP:{lat:28,lon:84,name:'Népal'},
    NZ:{lat:-41,lon:174,name:'Nouvelle-Zélande'},OM:{lat:22,lon:57.5,name:'Oman'},
    PA:{lat:9,lon:-80,name:'Panama'},            PE:{lat:-10,lon:-76,name:'Pérou'},
    PH:{lat:12.5,lon:122.5,name:'Philippines'}, PK:{lat:30,lon:70,name:'Pakistan'},
    PL:{lat:52,lon:19,name:'Pologne'},           PT:{lat:39.5,lon:-8,name:'Portugal'},
    PY:{lat:-23,lon:-58,name:'Paraguay'},        QA:{lat:25.5,lon:51.2,name:'Qatar'},
    RO:{lat:46,lon:25,name:'Roumanie'},          RS:{lat:44,lon:21,name:'Serbie'},
    RU:{lat:60,lon:90,name:'Russie'},            RW:{lat:-2,lon:30,name:'Rwanda'},
    SA:{lat:25,lon:45,name:'Arabie saoudite'},   SB:{lat:-8,lon:161,name:'Salomon'},
    SD:{lat:15,lon:30,name:'Soudan'},            SE:{lat:62,lon:15,name:'Suède'},
    SG:{lat:1.4,lon:103.8,name:'Singapour'},     SI:{lat:46,lon:15,name:'Slovénie'},
    SK:{lat:48.7,lon:19.5,name:'Slovaquie'},     SL:{lat:8.5,lon:-11.8,name:'Sierra Leone'},
    SN:{lat:14.5,lon:-14.5,name:'Sénégal'},      SO:{lat:6,lon:46,name:'Somalie'},
    SR:{lat:4,lon:-56,name:'Suriname'},          SS:{lat:7,lon:30,name:'Soudan du Sud'},
    SV:{lat:13.8,lon:-88.9,name:'Salvador'},     SY:{lat:35,lon:38,name:'Syrie'},
    SZ:{lat:-26.5,lon:31.5,name:'Eswatini'},     TD:{lat:15,lon:19,name:'Tchad'},
    TG:{lat:8,lon:1.1,name:'Togo'},              TH:{lat:15,lon:100,name:'Thaïlande'},
    TJ:{lat:39,lon:71,name:'Tadjikistan'},       TM:{lat:40,lon:60,name:'Turkménistan'},
    TN:{lat:34,lon:9,name:'Tunisie'},            TR:{lat:39,lon:35,name:'Turquie'},
    TT:{lat:11,lon:-61,name:'Trinité-et-Tobago'},TZ:{lat:-6,lon:35,name:'Tanzanie'},
    UA:{lat:49,lon:32,name:'Ukraine'},           UG:{lat:1,lon:32,name:'Ouganda'},
    US:{lat:38,lon:-97,name:'États-Unis'},       UY:{lat:-32.5,lon:-55.8,name:'Uruguay'},
    UZ:{lat:41,lon:64,name:'Ouzbékistan'},       VE:{lat:8,lon:-66,name:'Venezuela'},
    VN:{lat:16,lon:107,name:'Vietnam'},          YE:{lat:15.5,lon:47.5,name:'Yémen'},
    ZA:{lat:-29,lon:24,name:'Afrique du Sud'},   ZM:{lat:-15,lon:28,name:'Zambie'},
    ZW:{lat:-20,lon:30,name:'Zimbabwe'},
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
      if (inTable) { html += '</tbody></table>'; inTable = false; tableHead = null; }
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
        html += `<table><thead>${tableHead}</thead><tbody>`;
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
