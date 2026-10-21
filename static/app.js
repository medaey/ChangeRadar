'use strict';
const $ = s => document.querySelector(s);
const flat = c => c.flat(Infinity).filter(x => x != null && x !== false);
const node = x => x.nodeType ? x : document.createTextNode(String(x));
// h() construit un élément ; mount() remplace le contenu (accepte tableaux imbriqués : corrige le bug « [object HTMLElement] »)
const h = (t, a = {}, ...c) => {
  const e = document.createElement(t);
  for (const [k, v] of Object.entries(a)) {
    if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'class') e.className = v;
    else if (v !== false && v != null) e.setAttribute(k, v === true ? '' : v);
  }
  e.append(...flat(c).map(node)); return e;
};
const mount = (el, ...c) => el.replaceChildren(...flat(c).map(node));

let token = sessionStorage.getItem('cr_token') || '', S = null, tab = 'alerts', fs = 'todo', fk = 'all', q = '';
const open = new Set();
const CLS = {'CONCERNÉ': 'bad', 'À VÉRIFIER': 'warn', 'NON CONCERNÉ': 'ok'};
const KIND = {eol: 'Fin de vie / migration', cve: 'Vulnérabilité', event: 'Événement', license: 'Licence'};
const SEV = {critical: 'critique', high: 'élevée', medium: 'moyenne', low: 'faible', unknown: 'voir bulletin'};
const link = (u, t) => /^https:\/\//.test(u || '') ? h('a', {href: u, target: '_blank', rel: 'noopener noreferrer'}, t || 'Source') : null;

async function api(path, opt = {}, retry = true) {
  const r = await fetch(path, {...opt, headers: {Authorization: 'Bearer ' + token, 'X-ChangeRadar': '1', ...(opt.headers || {})}});
  if (r.status === 401 && retry) {
    const t = prompt("Jeton d'accès (CR_TOKEN)"); if (!t) throw new Error('Accès refusé');
    token = t; sessionStorage.setItem('cr_token', t); return api(path, opt, false);
  }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(j.error || r.statusText); e.details = j.details; throw e; }
  return j;
}
function toast(m, bad) {
  const t = $('#toast'); t.textContent = m; t.className = 'show' + (bad ? ' bad' : '');
  clearTimeout(toast.t); toast.t = setTimeout(() => t.className = '', 5000);
}
async function act(fn, ok) {
  try { await fn(); if (ok) toast(ok); } catch (e) { toast(e.message + (e.details ? ' — ' + e.details.join('; ') : ''), true); }
  await load();
}
async function load() { try { S = await api('/api/state'); render(); } catch (e) { toast(e.message, true); } }
const setFact = (asset, fact, value, scope = 'asset') => act(() => api('/api/facts', {method: 'POST', body: JSON.stringify({asset, fact, value, scope})}), 'Réponse enregistrée');
const saveAssets = list => act(() => api('/api/assets', {method: 'PUT', body: JSON.stringify(list)}));
async function refresh() {
  const b = $('#rf'); b.disabled = true; b.textContent = 'Actualisation…';
  await act(() => api('/api/refresh', {method: 'POST', body: '{}'}), 'Sources actualisées');
}
function ago(iso) {
  if (!iso) return 'jamais';
  const m = Math.round((Date.now() - new Date(iso)) / 60000);
  return m < 1 ? "à l'instant" : m < 60 ? `il y a ${m} min` : m < 2880 ? `il y a ${Math.round(m / 60)} h` : `il y a ${Math.round(m / 1440)} j`;
}

function render() {
  mount($('#tabs'), [['alerts', 'Veille'], ['techs', 'Technologies suivies'], ['sources', 'Sources']].map(([k, l]) =>
    h('button', {class: tab === k ? 'on' : '', onclick: () => { tab = k; render(); }}, l)));
  const stamps = [S.sources.cert?.at, ...Object.values(S.sources.eol || {}).map(v => v.at)].filter(Boolean).sort();
  $('#last').textContent = 'Sources : ' + ago(stamps[stamps.length - 1]);
  $('#rf').disabled = S.sources.offline; $('#rf').textContent = '↻ Actualiser les sources'; $('#rf').onclick = refresh;
  for (const k of ['alerts', 'techs', 'assets', 'events', 'sources']) $('#' + k).hidden = tab !== k;
  renderAlerts(); renderTechs(); renderSources();
}

function alertCard(f) {
  const key = f.event_id + '|' + f.asset_id;
  const tech = (S.techs || []).find(t => t.name === f.ref || t.name === f.product || f.asset_id.startsWith(t.name + ' '));
  const versionPanel = h('div', {class:'version-editor', hidden:true});
  const openVersionEditor = async button => {
    if (!tech) { tab = 'techs'; render(); return toast('Cette alerte ne correspond pas à une technologie suivie modifiable.', true); }
    const wasHidden = versionPanel.hidden;
    versionPanel.hidden = !wasHidden;
    if (!wasHidden) return;
    button.disabled = true; button.textContent = 'Chargement…';
    const select = h('select', {'aria-label':'Choisir une version publiée'}, h('option',{value:''},'Choisir une version depuis la source…'));
    const manual = h('input', {value:(tech.versions || []).join(', '), placeholder:'Version actuelle(s), séparées par des virgules', 'aria-label':'Version(s) installée(s)'});
    const hint = h('p',{class:'mut'},'Choisis une version publiée ou saisis une ou plusieurs versions installées.');
    const saveButton = h('button',{class:'on',onclick:async()=>{
      const value = manual.value.trim() || select.value;
      const versions = value.split(',').map(v=>v.trim()).filter(Boolean);
      if (!versions.length) return toast('Renseigne au moins une version.', true);
      const updated = S.techs.map(t => t === tech ? {...t, versions} : t);
      saveButton.disabled = true;
      await act(() => api('/api/technologies',{method:'PUT',body:JSON.stringify(updated)}), 'Version de '+tech.name+' mise à jour');
    }},'Enregistrer la version');
    select.addEventListener('change',()=>{ if (select.value) manual.value = select.value; });
    mount(versionPanel, h('div',{class:'version-editor-head'},h('strong',{},'Modifier la version — '+tech.name),h('button',{type:'button',onclick:()=>versionPanel.hidden=true},'Fermer')),
      h('div',{class:'version-editor-fields'},select,manual,saveButton),hint);
    try {
      if (tech.source_type && tech.source_id && tech.source_type !== 'cert') {
        const r = await api('/api/source-versions?type='+encodeURIComponent(tech.source_type)+'&id='+encodeURIComponent(tech.source_id));
        for (const v of (Array.isArray(r.versions) ? r.versions : [])) select.append(h('option',{value:String(v.value)},v.label || v.value));
        if (!r.versions?.length) select.disabled = true;
      } else { select.disabled = true; select.replaceChildren(h('option',{value:''},'Aucune liste de versions pour cette source')); }
    } catch (_) { select.disabled = true; select.replaceChildren(h('option',{value:''},'Versions indisponibles — saisie manuelle')); }
    button.disabled = false; button.textContent = '✎ Modifier la version';
  };
  const d = h('details', {class: 'card ' + CLS[f.status], open: open.has(key) || null,
      ontoggle: e => e.target.open ? open.add(key) : open.delete(key)},
    h('summary', {}, h('span', {class: 'badge ' + CLS[f.status]}, f.status), h('span', {class: 'pill'}, KIND[f.kind] || f.kind),
      h('strong', {}, f.title), h('code', {}, f.asset_id), h('span', {class: 'mut right'}, f.timing)),
    h('div', {class: 'body'},
      h('p', {class: 'mut'}, 'Gravité : ' + (SEV[f.severity] || f.severity)),
      !f.verified && h('p', {class: 'warnline'}, '⚠ Événement non vérifié contre la source officielle'),
      h('ul', {}, f.reasons.map(r => h('li', {}, r))),
      f.actions.map(a => h('p', {class: 'action'}, '→ ' + a)),
      f.ask && h('div', {class: 'ask'}, h('span', {}, f.ask.question),
        h('button', {onclick: () => setFact(f.ref ?? f.asset_id, f.ask.fact, true, f.scope)}, 'Oui'),
        h('button', {onclick: () => setFact(f.ref ?? f.asset_id, f.ask.fact, false, f.scope)}, 'Non')),
      link(f.source, 'Ouvrir la source'),
      h('div', {class: 'row card-actions'},
        tech && h('button', {onclick: e => openVersionEditor(e.currentTarget)}, '✎ Modifier la version'),
        h('button', {class: f.treated ? '' : 'on', onclick: () => act(() => api('/api/findings/treated', {method:'POST', body: JSON.stringify({key: key, treated: !f.treated})}), f.treated ? 'Signalement réactivé' : 'Signalement marqué comme traité')}, f.treated ? '↩ Réactiver' : '✓ Marquer comme traité')),
      versionPanel));
  return d;
}

function renderList() {
  const t = q.toLowerCase();
  const list = S.findings.filter(f =>
    (fs === 'treated' ? !!f.treated : fs === 'all' ? true : !f.treated) && (fs !== 'todo' || f.status !== 'NON CONCERNÉ') && (fk === 'all' || f.kind === fk) &&
    (!t || (f.title + ' ' + f.asset_id).toLowerCase().includes(t)));
  const noData = !S.findings.length && !S.sources.cert?.at && !Object.keys(S.sources.eol || {}).length;
  mount($('#alist'), list.length ? list.map(alertCard) :
    h('p', {class: 'empty'}, !S.techs.length ? 'Commence par déclarer les technologies utilisées par ton organisation dans « Technologies suivies ». Aucune saisie équipement par équipement n’est nécessaire.' : noData ? 'Aucune donnée pour l’instant : clique sur « Actualiser les sources » (endoflife.date, CERT Santé et releases GitHub configurées).' : 'Aucun résultat pour ces filtres.'));
}
function renderAlerts() {
  const chip = (cur, set) => ([k, l]) => h('button', {class: cur() === k ? 'on' : '', onclick: () => { set(k); renderAlerts(); }}, l);
  mount($('#alerts'),
    h('div', {class: 'toolbar'},
      h('div', {class: 'filter-group'}, h('span',{class:'filter-label'},'État du suivi'), h('div', {class: 'chips'}, [['todo', 'À traiter'], ['treated', 'Traités'], ['all', 'Tous']].map(chip(() => fs, v => fs = v)))),
      h('label',{class:'filter-select'},h('span',{class:'filter-label'},'Type d’alerte'),h('select',{value:fk, onchange:e=>{fk=e.target.value;renderAlerts();}}, [['all','Toutes les sources'],['eol','Fin de vie'],['cve','Vulnérabilités'],['event','Événements'],['ssl','Certificats SSL/TLS']].map(([v,l])=>h('option',{value:v},l)))),
      h('input', {type: 'search', placeholder: 'Filtrer (technologie, alerte)…', value: q, 'aria-label': 'Filtrer', oninput: e => { q = e.target.value; renderList(); }})),
    h('div', {id: 'alist'}));
  renderList();
}

function renderAssets() {
  const cols = ['product', 'version', 'role', 'site', 'owner', 'eol_product', 'github_repo', 'license_name', 'license_expires_at', 'license_notice_days', 'support_deadline', 'support_required_version'];
  const names = {eol_product: 'slug endoflife.date', github_repo: 'Dépôt GitHub (optionnel)', license_name: 'Licence / contrat', license_expires_at: 'Expiration licence', license_notice_days: 'Alerte licence (jours)', support_deadline: 'Échéance support', support_required_version: 'Version cible'};
  const draft = {};
  const edit = (a, k) => h('input', {value: a[k] ?? '', type: k.endsWith('_at') || k === 'support_deadline' ? 'date' : 'text', 'aria-label': k + ' ' + a.id,
    onchange: e => { const v = e.target.value.trim(); v ? a[k] = v : delete a[k]; saveAssets(S.assets); }});
  const rows = S.assets.map(a => h('tr', {}, h('td', {}, h('code', {}, a.id)), cols.map(k => h('td', {}, edit(a, k))),
    h('td', {}, Object.entries(a.facts || {}).map(([k, v]) => h('span', {class: 'fact', title: 'Cliquer pour oublier cette réponse', onclick: () => setFact(a.id, k, null)}, `${k}=${v} ✕`))),
    h('td', {}, h('button', {title: 'Supprimer', onclick: () => confirm('Supprimer ' + a.id + ' ?') && saveAssets(S.assets.filter(x => x !== a))}, '🗑'))));
  const field = (key, placeholder, type='text') => h('label', {class:'wizard-field'}, h('span', {}, names[key] || placeholder), h('input', {type, placeholder, 'aria-label': names[key] || placeholder, oninput:e => draft[key] = e.target.value.trim()}));
  const kind = h('select', {'aria-label':'Type d’actif', onchange:e => { const license = e.target.value === 'license'; $('#license-fields').hidden = !license; $('#support-fields').hidden = e.target.value !== 'software'; }},
    h('option',{value:'software'},'Logiciel / équipement'), h('option',{value:'license'},'Licence / abonnement'), h('option',{value:'service'},'Service / infrastructure'));
  const idInput = h('input', {placeholder:'ex. veeam-backup-prod', 'aria-label':'Identifiant unique', oninput:e => draft.id=e.target.value.trim()});
  const productInput = h('input', {placeholder:'ex. Veeam Backup & Replication', 'aria-label':'Produit', required:true, oninput:e => draft.product=e.target.value.trim()});
  const versionInput = h('input', {placeholder:'ex. 12.3', 'aria-label':'Version', oninput:e => draft.version=e.target.value.trim()});
  const siteInput = h('input', {placeholder:'ex. Datacenter', 'aria-label':'Site', oninput:e => draft.site=e.target.value.trim()});
  const ownerInput = h('input', {placeholder:'ex. Équipe infrastructure', 'aria-label':'Responsable', oninput:e => draft.owner=e.target.value.trim()});
  const licenseName = h('input', {placeholder:'ex. Veeam Data Platform Advanced', 'aria-label':'Nom de licence / contrat', oninput:e => draft.license_name=e.target.value.trim()});
  const licenseExpiry = h('input', {type:'date', 'aria-label':'Date d’expiration de licence', oninput:e => draft.license_expires_at=e.target.value});
  const notice = h('select', {'aria-label':'Prévenir avant expiration', onchange:e => draft.license_notice_days=Number(e.target.value)}, ...[30,60,90,180].map(n=>h('option',{value:String(n), selected:n===60},`${n} jours avant`)));
  const supportDate = h('input', {type:'date', 'aria-label':'Date limite de support / migration', oninput:e => draft.support_deadline=e.target.value});
  const targetVersion = h('input', {placeholder:'ex. 13', 'aria-label':'Version cible', oninput:e => draft.support_required_version=e.target.value.trim()});
  const eol = h('input', {placeholder:'ex. veeam, windows-server, debian', 'aria-label':'Slug endoflife.date', oninput:e => draft.eol_product=e.target.value.trim()});
  const githubRepo = h('input', {placeholder:'ex. rustdesk/rustdesk ou https://github.com/rustdesk/rustdesk', 'aria-label':'Dépôt GitHub des releases', oninput:e => draft.github_repo=e.target.value.trim()});
  const presets = h('select', {'aria-label':'Exemples de produits', onchange:e => { const p = {rustdesk:{product:'RustDesk', github_repo:'rustdesk/rustdesk'}, veeam:{product:'Veeam Backup & Replication', eol_product:'veeam'}, debian:{product:'Debian', eol_product:'debian'}, windows:{product:'Windows Server', eol_product:'windows-server'}, nginx:{product:'NGINX', eol_product:'nginx'}}[e.target.value]; if (!p) return; for (const k of ['product','github_repo','eol_product','version']) delete draft[k]; productInput.value=p.product; githubRepo.value=p.github_repo || ''; eol.value=p.eol_product || ''; versionInput.value=p.version || ''; Object.assign(draft,p); }} , h('option',{value:''},'Choisir un exemple…'), h('option',{value:'rustdesk'},'RustDesk — releases GitHub'), h('option',{value:'veeam'},'Veeam Backup & Replication'), h('option',{value:'debian'},'Debian'), h('option',{value:'windows'},'Windows Server'), h('option',{value:'nginx'},'NGINX'));
  const add = () => {
    const product = productInput.value.trim(); if (!product) return toast('Indique le nom du produit', true);
    const slug = v => v.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
    const a = {...draft, id: (idInput.value.trim() || slug(product) || 'actif')};
    if (S.assets.some(x => x.id === a.id)) return toast('Cet identifiant existe déjà', true);
    if (!a.license_expires_at) { delete a.license_expires_at; delete a.license_name; delete a.license_notice_days; }
    if (!a.support_deadline) { delete a.support_deadline; delete a.support_required_version; }
    Object.keys(a).forEach(k => { if (a[k] === '') delete a[k]; });
    saveAssets([...S.assets, a]);
  };
  mount($('#assets'), h('h2', {}, 'Ajouter un actif — assistant de saisie'),
    h('p', {class:'mut'}, 'Renseigne uniquement ce que tu connais. Les dates déclarées déclenchent des alertes automatiquement ; vérifie les dates et versions auprès de l’éditeur.'),
    h('div',{class:'wizard'}, h('div',{class:'wizard-grid'},
      h('label',{class:'wizard-field'},h('span',{},'Exemple prérempli'),presets),
      h('label',{class:'wizard-field'},h('span',{},'Type d’actif'),kind),
      h('label',{class:'wizard-field'},h('span',{},'Identifiant (facultatif)'),idInput),
      h('label',{class:'wizard-field'},h('span',{},'Produit / service *'),productInput),
      h('label',{class:'wizard-field'},h('span',{},'Version actuelle'),versionInput),
      h('label',{class:'wizard-field'},h('span',{},'Site / périmètre'),siteInput),
      h('label',{class:'wizard-field'},h('span',{},'Responsable'),ownerInput),
      h('label',{class:'wizard-field'},h('span',{},'Slug endoflife.date (facultatif)'),eol),
      h('label',{class:'wizard-field'},h('span',{},'Dépôt GitHub des releases (facultatif)'),githubRepo)),
      h('div',{id:'license-fields',class:'wizard-sub',hidden:true},h('strong',{},'Suivi de licence'),h('p',{class:'mut'},'Une alerte apparaîtra avant l’expiration selon le délai choisi, puis restera visible si la date est dépassée.'),
        h('div',{class:'wizard-grid'},h('label',{class:'wizard-field'},h('span',{},'Licence / contrat'),licenseName),h('label',{class:'wizard-field'},h('span',{},'Date d’expiration'),licenseExpiry),h('label',{class:'wizard-field'},h('span',{},'Prévenir'),notice))),
      h('div',{id:'support-fields',class:'wizard-sub'},h('strong',{},'Fin de support / migration'),h('p',{class:'mut'},'Exemple : « Veeam 12 n’est plus supporté après cette date ; migrer vers la version 13 ». Cette échéance est une règle que tu déclares, pas une vérification automatique du fournisseur.'),
        h('div',{class:'wizard-grid'},h('label',{class:'wizard-field'},h('span',{},'Date limite'),supportDate),h('label',{class:'wizard-field'},h('span',{},'Version cible'),targetVersion))),
      h('div',{class:'row'},h('button',{class:'on',onclick:add},'＋ Ajouter à l’inventaire'))),
    h('h2', {}, 'Inventaire existant'),
    h('p', {class: 'mut'}, 'Modifie une valeur puis quitte le champ pour enregistrer. Un actif dont le produit est aussi déclaré dans Technologies remplace la ligne correspondante.'),
    h('div', {class: 'scroll'}, h('table', {}, h('thead', {}, h('tr', {}, ['id', ...cols.map(c => names[c] || c), 'réponses', ''].map(c => h('th', {}, c)))), h('tbody', {}, rows))),
    h('div', {class: 'row'}, h('label', {}, 'Importer un CSV : ', h('input', {type: 'file', accept: '.csv,text/csv', onchange: e => { const f = e.target.files[0]; if (f) act(async () => { const r = await api('/api/import-csv', {method: 'POST', body: await f.text()}); toast(r.imported + ' ligne(s) importée(s)'); }); }}))),
    h('p', {class: 'mut'}, 'CSV : id,product,version,role,site,owner,eol_product,license_name,license_expires_at,license_notice_days,support_deadline,support_required_version.'));
}

const TEMPLATE = `id: mon-evenement
title: "Titre de l'événement"
category: end-of-life
source: "https://exemple.org/annonce-officielle"
announced_at: "2026-01-15"
effective_at: "2027-03-01"
severity: medium
verification_required: true
affected:
  - product: nom-du-produit
    versions: "<2.0"
    condition: "à confirmer sur l'actif"
`;
function renderEvents() {
  const ta = h('textarea', {'aria-label': 'Événement YAML', spellcheck: 'false'}); ta.value = TEMPLATE;
  mount($('#events'), h('h2', {}, 'Événements manuels'),
    h('p', {class: 'mut'}, 'Pour les annonces qui ne figurent dans aucune source automatique (changement de clé, migration interne…).'),
    S.events.map(e => h('article', {class: 'card ' + (e.errors.length ? 'bad' : 'ok')},
      h('div', {class: 'sumline'}, h('strong', {}, e.title || e.id), h('span', {class: 'mut'}, `${e.id} · échéance ${e.effective_at || '?'}`), link(e.source),
        h('button', {class: 'right', title: 'Supprimer', onclick: () => confirm('Supprimer ' + e.id + ' ?') && act(() => api('/api/events/' + encodeURIComponent(e.id), {method: 'DELETE'}))}, '🗑')),
      e.errors.map(m => h('p', {class: 'warnline'}, '✗ ' + m)), e.warnings.map(m => h('p', {class: 'warnline'}, '! ' + m)))),
    h('h2', {}, 'Ajouter un événement'), ta,
    h('div', {class: 'row'}, h('button', {class: 'on', onclick: () => act(() => api('/api/events', {method: 'POST', body: ta.value}), 'Événement ajouté')}, 'Valider et ajouter'),
      h('span', {class: 'mut'}, 'Ne renseigne verified_at qu’après relecture de la source officielle.')));
}

function renderSources() {
  const so = S.sources, eol = Object.entries(so.eol || {}), c = so.cert || {};
  const st = (ok, err) => h('span', {class: 'badge ' + (ok ? 'ok' : 'bad')}, ok ? 'OK' : 'Erreur' + (err ? ' : ' + err : ''));
  const name = h('input', {placeholder: 'Nom affiché (ex. RustDesk Server)', 'aria-label': 'Nom du dépôt'});
  const repo = h('input', {placeholder: 'https://github.com/owner/repo ou owner/repo', 'aria-label': 'Dépôt GitHub', class: 'wide'});
  const addRepo = async () => {
    const raw = repo.value.trim().replace(/\.git$/i, '').replace(/\/$/, '');
    const m = raw.match(/^(?:https:\/\/github\.com\/)?([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/i);
    if (!m) return toast('Dépôt invalide. Utilise owner/repo ou https://github.com/owner/repo.', true);
    const slug = `${m[1]}/${m[2]}`;
    if ((S.github_sources || []).some(x => x.repo.toLowerCase() === slug.toLowerCase())) return toast('Ce dépôt est déjà configuré.', true);
    await act(() => api('/api/github-sources', {method:'PUT', body:JSON.stringify([...(S.github_sources || []), {name:name.value.trim() || m[2].replace(/[-_]/g,' '), repo:slug}])}), 'Dépôt ajouté aux sources');
    await loadCatalog();
  };
  const repos = S.github_sources || [];
  const repoRows = repos.map(t => h('tr', {},
    h('td', {}, h('strong', {}, t.name)),
    h('td', {}, link('https://github.com/' + t.repo, t.repo)),
    h('td', {}, 'Tags, releases et notes de version quand disponibles'),
    h('td', {}, h('button', {onclick: () => {
      if (!confirm('Retirer la source ' + t.repo + ' ? Les technologies déjà suivies resteront enregistrées.')) return;
      act(() => api('/api/github-sources', {method:'PUT', body:JSON.stringify(repos.filter(x => x.repo !== t.repo))}), 'Source GitHub retirée').then(loadCatalog);
    }}, 'Retirer'))));
  mount($('#sources'),
    so.offline && h('p', {class: 'warnline'}, 'Mode hors-ligne (CR_OFFLINE=1) : aucune actualisation.'),
    h('article', {class: 'card'}, h('div', {class: 'sumline'}, h('strong', {}, 'endoflife.date — fins de support'), link('https://endoflife.date', 'endoflife.date')),
      h('p', {class: 'mut'}, `Catalogue de produits et cycles de support. ${eol.length} produit(s) interrogé(s) lors de la dernière actualisation.`),
      eol.length ? h('table', {}, h('tbody', {}, eol.map(([slug, v]) => h('tr', {}, h('td', {}, h('code', {}, slug)), h('td', {}, st(v.ok, v.error)), h('td', {class: 'mut'}, ago(v.at)))))) : h('p', {class: 'mut'}, 'Catalogue prêt pour la sélection ; actualise les sources pour récupérer les cycles de support.')),
    h('article', {class: 'card'}, h('div', {class: 'sumline'}, h('strong', {}, 'CERT Santé — alertes et vulnérabilités'), link('https://cyberveille.esante.gouv.fr/alertes-et-vulnerabilites', 'cyberveille.esante.gouv.fr')),
      h('p', {class: 'mut'}, `Bulletins des ${so.cve_days} derniers jours. CERT Santé ne fournit pas de catalogue normalisé des versions : la correspondance repose sur les mots-clés et la version doit être vérifiée dans le bulletin.`),
      c.at ? h('p', {}, st(c.ok, c.error), ' ', c.ok ? `${c.items} bulletins lus · ${so.cert_matched}/${so.cert_window} bulletins récents correspondent aux technologies suivies · ` : '', ago(c.at)) : h('p', {class: 'mut'}, 'Pas encore interrogé.')),
    h('h2', {}, 'Certificats SSL/TLS à surveiller'),
    h('p', {class:'mut'}, 'Ajoute le nom DNS ou l’URL HTTPS d’un service. ChangeRadar récupère le certificat présenté, sa date d’expiration et signale les échéances proches. Un certificat expiré peut toujours être inspecté, mais son statut de confiance sera signalé.'),
    (() => {
      const certs = S.certificates || [];
      const label = h('input',{placeholder:'Nom affiché (ex. Portail VPN)','aria-label':'Nom du service TLS'});
      const url = h('input',{class:'wide',placeholder:'https://vpn.exemple.fr ou vpn.exemple.fr:443','aria-label':'Adresse HTTPS à surveiller'});
      const add = () => {
        const raw=url.value.trim(); if(!raw) return toast('Renseigne une URL HTTPS ou un nom DNS.',true);
        act(()=>api('/api/certificates',{method:'PUT',body:JSON.stringify([...certs,{name:label.value.trim()||raw, url:raw}])}),'Cible SSL/TLS ajoutée');
      };
      const rows = certs.map(c=>h('tr',{},h('td',{},h('strong',{},c.name)),h('td',{},h('code',{},c.url)),h('td',{},c.last_checked ? ago(c.last_checked) : 'Pas encore vérifié'),h('td',{},h('button',{onclick:()=>confirm('Retirer la surveillance de '+c.name+' ?')&&act(()=>api('/api/certificates',{method:'PUT',body:JSON.stringify(certs.filter(x=>x.id!==c.id))}),'Cible retirée')},'Retirer'))));
      return h('div',{},h('div',{class:'wizard'},h('div',{class:'wizard-grid'},h('label',{class:'wizard-field'},h('span',{},'Nom affiché'),label),h('label',{class:'wizard-field'},h('span',{},'URL HTTPS / nom DNS'),url)),h('div',{class:'row'},h('button',{class:'on',onclick:add},'＋ Surveiller ce certificat'))),certs.length?h('div',{class:'scroll'},h('table',{},h('thead',{},h('tr',{},['Service','Adresse','Dernier contrôle',''].map(x=>h('th',{},x)))),h('tbody',{},rows))):h('p',{class:'empty'},'Aucun certificat surveillé.'));
    })(),
    h('h2', {}, 'Dépôts GitHub configurés'),
    h('p', {class: 'mut'}, 'Un dépôt est une source disponible, pas une technologie suivie automatiquement. Après ajout, sélectionne-le dans « Technologies suivies » puis choisis un tag/version récupéré depuis GitHub.'),
    h('div', {class: 'wizard'}, h('div', {class: 'wizard-grid'},
      h('label', {class: 'wizard-field'}, h('span', {}, 'Nom affiché (facultatif)'), name),
      h('label', {class: 'wizard-field'}, h('span', {}, 'URL du dépôt GitHub'), repo)),
      h('div', {class: 'row'}, h('button', {class: 'on', onclick: addRepo}, '＋ Ajouter la source GitHub'))),
    repos.length ? h('div', {class: 'scroll'}, h('table', {}, h('thead', {}, h('tr', {}, ['Source', 'Dépôt', 'Données récupérées', ''].map(x => h('th', {}, x)))), h('tbody', {}, repoRows))) : h('p', {class: 'empty'}, 'Aucun dépôt GitHub configuré.'));
}

let catalog = [];
async function loadCatalog() {
  try { const r = await api('/api/technology-catalog'); catalog = r.sources || []; if (S) renderTechs(); }
  catch (_) { catalog = []; if (S) renderTechs(); }
}
function renderTechs() {
  const csv = v => v.split(',').map(x => x.trim()).filter(Boolean);
  const save = list => act(() => api('/api/technologies', {method: 'PUT', body: JSON.stringify(list)}), 'Technologies enregistrées');
  const edit = (t, k, isList = false) => h('input', {value: isList ? (t[k] || []).join(', ') : (t[k] ?? ''), 'aria-label': k + ' ' + t.name,
    onchange: e => { const v = e.target.value.trim(); const val = isList ? csv(v) : v; (val.length ? t[k] = val : delete t[k]); save(S.techs); }});
  const sourceSelect = h('select', {'aria-label':'Source disponible', required:true},
    h('option',{value:''},'Choisir une source configurée…'),
    catalog.map(c => h('option',{value:c.type+'|'+c.id}, `${c.name} — ${c.type === 'eol' ? 'endoflife.date' : c.type === 'github' ? 'GitHub' : 'CERT Santé'}`)));
  const techName = h('input', {placeholder:'Nom précis de la technologie (ex. Veeam Backup & Replication)', 'aria-label':'Nom de la technologie'});
  const versionSelect = h('select', {'aria-label':'Version installée', required:false}, h('option',{value:''},'Choisir une version…'));
  const manualVersion = h('input', {placeholder:'Version / modèle si non listé', 'aria-label':'Version ou modèle manuel'});
  const keywords = h('input', {placeholder:'Mots-clés CERT (séparés par des virgules)', 'aria-label':'Mots-clés'});
  const owner = h('input', {placeholder:'Équipe responsable (facultatif)', 'aria-label':'Équipe responsable'});
  sourceSelect.addEventListener('change', async () => {
    versionSelect.replaceChildren(h('option',{value:''},'Chargement des versions…'));
    manualVersion.value = '';
    const [type, ...rest] = sourceSelect.value.split('|'), id = rest.join('|');
    if (!type || !id) { versionSelect.replaceChildren(h('option',{value:''},'Choisir une version…')); return; }
    try {
      const r = await api('/api/source-versions?type='+encodeURIComponent(type)+'&id='+encodeURIComponent(id));
      const versions = Array.isArray(r.versions) ? r.versions : [];
      versionSelect.replaceChildren(
        h('option', {value: ''}, versions.length ? 'Choisir une version…' : (type === 'cert' ? 'Version à renseigner manuellement (CERT)' : 'Aucune version disponible')),
        ...versions.map(v => h('option', {value: String(v.value), textContent: undefined}, v.label || v.value))
      );
      if (type !== 'cert' && versions.length === 0) {
        manualVersion.placeholder = 'Aucune version récupérée — vérifie la source ou sa disponibilité';
      }
      manualVersion.placeholder = type === 'cert' ? 'Version indiquée dans le bulletin (saisie nécessaire)' : 'Autre version / modèle (facultatif)';
    } catch(e) { versionSelect.replaceChildren(h('option',{value:''},'Versions indisponibles')); toast(e.message, true); }
  });
  const add = () => {
    const [type, ...rest] = sourceSelect.value.split('|'), id = rest.join('|');
    const sourceDef = catalog.find(c => c.type === type && c.id === id);
    if (!sourceDef) return toast('Choisis une source configurée.', true);
    const version = manualVersion.value.trim() || versionSelect.value;
    if (type !== 'cert' && !version) return toast('Choisis une version récupérée depuis la source ou renseigne une version manuellement.', true);
    if (type === 'cert' && !techName.value.trim()) return toast('Pour une technologie suivie via CERT Santé, renseigne son nom précis (ex. Veeam Backup & Replication).', true);
    if (type === 'cert' && !csv(keywords.value).length) return toast('Pour CERT Santé, renseigne au moins un mot-clé produit.', true);
    const name = techName.value.trim() || sourceDef.name;
    if (S.techs.some(t => t.name.toLowerCase() === name.toLowerCase() && (t.source_id || t.eol_product || t.github_repo) === id))
      return toast('Cette technologie / source est déjà suivie.', true);
    const t = {name, source_type:type, source_id:id, keywords:csv(keywords.value)};
    if (type === 'eol') t.eol_product = id;
    if (type === 'github') t.github_repo = id;
    if (version) t.versions = [version];
    if (owner.value.trim()) t.owner = owner.value.trim();
    save([...S.techs, t]);
  };
  const rows = S.techs.map(t => h('tr', {},
    h('td', {}, h('strong', {}, t.name), h('p',{class:'mut'}, t.source_type ? ({eol:'endoflife.date',github:'GitHub',cert:'CERT Santé'}[t.source_type] || t.source_type) : 'Source historique')),
    h('td', {}, edit(t,'versions',true)),
    h('td', {}, t.github_repo ? link('https://github.com/' + t.github_repo.replace(/^https?:\/\/github\.com\//, ''), t.github_repo) : '—'),
    h('td', {}, t.eol_product || '—'),
    h('td', {}, edit(t,'keywords',true)),
    h('td', {}, edit(t,'owner')),
    h('td', {}, h('button',{title:'Ne plus suivre cette technologie',onclick:()=>confirm('Ne plus suivre '+t.name+' ?')&&save(S.techs.filter(x=>x!==t))},'Retirer'))));
  mount($('#techs'),
    h('h2',{},'Technologies de l’organisation'),
    h('p',{class:'mut'},'Choisis une source configurée, puis une version réellement exposée par cette source. Un dépôt GitHub doit être ajouté dans Sources avant de pouvoir être sélectionné.'),
    h('div',{class:'wizard'},h('div',{class:'wizard-grid'},
      h('label',{class:'wizard-field'},h('span',{},'Source / technologie *'),sourceSelect),
      h('label',{class:'wizard-field'},h('span',{},'Nom de la technologie (facultatif)'),techName),
      h('label',{class:'wizard-field'},h('span',{},'Version depuis la source'),versionSelect),
      h('label',{class:'wizard-field'},h('span',{},'Version / modèle alternatif'),manualVersion),
      h('label',{class:'wizard-field'},h('span',{},'Mots-clés CERT'),keywords),
      h('label',{class:'wizard-field'},h('span',{},'Équipe responsable'),owner)),
      h('p',{class:'mut'},'CERT Santé ne publie pas de liste de versions sélectionnables : indique le produit par mots-clés et la version vérifiée dans le bulletin.'),
      h('div',{class:'row'},h('button',{class:'on',onclick:add},'＋ Suivre cette technologie'))),
    S.techs.length ? h('div',{class:'scroll'},h('table',{},h('thead',{},h('tr',{},['Technologie / source','Versions suivies','Dépôt GitHub','Identifiant endoflife.date','Mots-clés CERT','Responsable',''].map(x=>h('th',{},x)))),h('tbody',{},rows))) : h('p',{class:'empty'},'Aucune technologie suivie. Choisis une source configurée ci-dessus.'),
    h('p',{class:'mut'},'Les versions proposées proviennent des tags GitHub ou des cycles endoflife.date. Les alertes CERT sont rapprochées par mots-clés ; vérifie toujours les versions affectées dans le bulletin officiel.'));
}

load();
loadCatalog();
