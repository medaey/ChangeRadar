#!/usr/bin/env python3
"""ChangeRadar — serveur web self-hosted (stdlib + PyYAML). Voir README.md.

Env : CR_DATA (défaut ./data) · CR_HOST (127.0.0.1) · CR_PORT (8080) · CR_TOKEN (jeton d'accès)
Refuse d'écouter hors loopback sans CR_TOKEN (sauf CR_INSECURE=1).
"""
import csv, hashlib, hmac, io, json, os, re, shutil, socket, ssl, sys, tempfile, threading, time
from dataclasses import asdict
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import yaml
import changeradar as cr
import feeds

HERE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("CR_DATA", HERE / "data"))
TOKEN = os.environ.get("CR_TOKEN", "")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
FIELDS = ("product", "version", "role", "site", "owner", "eol_product", "license_name", "license_expires_at", "license_notice_days", "support_deadline", "support_required_version", "github_repo")
MAX_BODY = 1_000_000
LOCK = threading.Lock()
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8"),
          "/favicon.svg": ("favicon.svg", "image/svg+xml; charset=utf-8")}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class HttpError(Exception):
    def __init__(self, code, msg, details=None):
        self.code, self.msg, self.details = code, msg, details


# ----------------------------------------------------------------- données
def bootstrap():
    (DATA / "events").mkdir(parents=True, exist_ok=True)
    inv = DATA / "inventory.yaml"
    if not inv.exists():
        shutil.copy(HERE / "inventory.yaml", inv)
    if not any((DATA / "events").glob("*.y*ml")):
        for p in (HERE / "events").glob("*.y*ml"):
            shutil.copy(p, DATA / "events" / p.name)


def atomic_write(path: Path, text: str):
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def load_assets():
    try:
        return cr.load_inventory(DATA / "inventory.yaml")
    except ValueError as e:
        raise HttpError(500, f"Inventaire invalide: {e}")


def save_assets(assets):
    if not isinstance(assets, list):
        raise HttpError(400, "liste d'actifs attendue")
    seen = set()
    for a in assets:
        if not isinstance(a, dict) or not ID_RE.match(str(a.get("id", ""))):
            raise HttpError(400, f"id d'actif invalide: {a.get('id') if isinstance(a, dict) else a!r}")
        if a["id"] in seen:
            raise HttpError(400, f"id en double: {a['id']}")
        seen.add(a["id"])
    atomic_write(DATA / "inventory.yaml",
                 yaml.safe_dump({"assets": assets}, allow_unicode=True, sort_keys=False))


NAME_RE = re.compile(r"^\w[\w .+/#()&-]{0,79}$")


def load_techs():
    p = DATA / "technologies.yaml"
    d = (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.exists() else {}
    return [t for t in d.get("technologies", []) if isinstance(t, dict) and t.get("name")]


def save_techs(techs):
    if not isinstance(techs, list):
        raise HttpError(400, "liste attendue")
    out, seen = [], set()
    for t in techs:
        name = str(t.get("name", "")).strip() if isinstance(t, dict) else ""
        if not NAME_RE.match(name):
            raise HttpError(400, f"nom de technologie invalide: {name!r}")
        if name.lower() in seen:
            raise HttpError(400, f"technologie en double: {name}")
        seen.add(name.lower())
        c = {"name": name}
        for k in ("versions", "keywords"):
            v = [str(x).strip() for x in (t.get(k) or []) if str(x).strip()]
            if v:
                c[k] = v
        slug = str(t.get("eol_product") or "").strip().lower()
        if slug:
            if not feeds.SLUG_RE.match(slug):
                raise HttpError(400, f"slug endoflife.date invalide: {slug!r}")
            c["eol_product"] = slug
        for k in ("github_repo", "source_url", "source_type", "source_id"):
            value = str(t.get(k) or "").strip()
            if value:
                if k == "source_url" and not value.startswith(("https://", "http://")):
                    raise HttpError(400, "URL de source invalide")
                c[k] = value
        if str(t.get("owner") or "").strip():
            c["owner"] = str(t["owner"]).strip()
        if isinstance(t.get("facts"), dict) and t["facts"]:
            c["facts"] = {str(k): bool(v) for k, v in t["facts"].items() if ID_RE.match(str(k))}
        out.append(c)
    atomic_write(DATA / "technologies.yaml", yaml.safe_dump({"technologies": out}, allow_unicode=True, sort_keys=False))


def load_github_sources():
    p = DATA / "github-sources.yaml"
    d = (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.exists() else {}
    return [x for x in d.get("sources", []) if isinstance(x, dict) and x.get("repo")]


def save_github_sources(sources):
    if not isinstance(sources, list):
        raise HttpError(400, "liste de dépôts attendue")
    out, seen = [], set()
    for item in sources:
        if not isinstance(item, dict):
            raise HttpError(400, "dépôt invalide")
        raw = str(item.get("repo") or "").strip().removesuffix(".git").rstrip("/")
        m = re.fullmatch(r"(?:https://github\.com/)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", raw, re.I)
        if not m:
            raise HttpError(400, "Dépôt GitHub invalide : utilise owner/repo")
        repo = f"{m.group(1)}/{m.group(2)}"
        key = repo.lower()
        if key in seen:
            raise HttpError(400, f"Dépôt déjà configuré : {repo}")
        seen.add(key)
        label = str(item.get("name") or m.group(2).replace("-", " ")).strip()
        if not NAME_RE.match(label):
            raise HttpError(400, f"nom de dépôt invalide : {label}")
        out.append({"name": label, "repo": repo})
    atomic_write(DATA / "github-sources.yaml", yaml.safe_dump({"sources": out}, allow_unicode=True, sort_keys=False))


def source_versions(source_type, source_id):
    """Retourne les versions réelles d'une source ; aucune version synthétique n'est créée."""
    if source_type == "github":
        src = next((x for x in load_github_sources() if x["repo"].lower() == source_id.lower()), None)
        if not src:
            raise HttpError(404, "dépôt GitHub non configuré")
        owner, repo = src["repo"].split("/", 1)
        try:
            tags = json.loads(feeds.fetch(f"https://api.github.com/repos/{owner}/{repo}/tags?per_page=100", 1_000_000))
            return [{"value": x["name"], "label": x["name"]} for x in tags if isinstance(x, dict) and x.get("name")]
        except Exception as e:
            raise HttpError(502, f"Impossible de lire les tags GitHub : {str(e)[:120]}")
    if source_type == "eol":
        if not feeds.SLUG_RE.match(source_id):
            raise HttpError(400, "identifiant endoflife.date invalide")
        cache = DATA / "cache" / f"eol-{source_id}.json"
        try:
            if cache.exists():
                data = json.loads(cache.read_text(encoding="utf-8"))
            else:
                response = json.loads(feeds.fetch(feeds.EOL_API.format(source_id)))
                data = response.get("result", response)
            # L'API v1 expose les cycles sous result.releases ; les anciens caches
            # peuvent contenir directement une liste. Accepter les deux formats.
            if isinstance(data, dict):
                data = data.get("releases", data.get("result", []))
            if not isinstance(data, list):
                raise ValueError("format de réponse endoflife.date inattendu")
            versions = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                name = item.get("name") or item.get("cycle")
                if name is not None:
                    value = str(name).strip()
                    if value:
                        versions.append({"value": value, "label": value})
            # Garder l'ordre fourni par la source et éliminer les doublons.
            unique, seen = [], set()
            for version in versions:
                if version["value"] not in seen:
                    seen.add(version["value"])
                    unique.append(version)
            return unique
        except Exception as e:
            raise HttpError(502, f"Versions endoflife.date indisponibles pour {source_id} : {str(e)[:120]}")
    if source_type == "cert":
        # CERT publie des bulletins, pas un catalogue officiel de versions : le champ reste manuel.
        return []
    raise HttpError(400, "type de source inconnu")


def load_certificates():
    p = DATA / "certificates.yaml"
    d = (yaml.safe_load(p.read_text(encoding="utf-8")) or {}) if p.exists() else {}
    return [x for x in d.get("certificates", []) if isinstance(x, dict) and x.get("url")]


def normalize_tls_target(raw):
    raw = str(raw or "").strip()
    if not raw:
        raise HttpError(400, "URL ou nom DNS requis")
    parsed = urlsplit(raw if "://" in raw else "https://" + raw)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise HttpError(400, "Utilise une URL HTTPS ou un nom DNS avec port facultatif, sans chemin")
    try:
        port = parsed.port or 443
    except ValueError:
        raise HttpError(400, "port TLS invalide")
    if not 1 <= port <= 65535:
        raise HttpError(400, "port TLS invalide")
    host = parsed.hostname.lower().rstrip(".")
    return f"https://{host}" + (f":{port}" if port != 443 else "")


def save_certificates(items):
    if not isinstance(items, list) or len(items) > 500:
        raise HttpError(400, "liste de certificats invalide (500 maximum)")
    old = {x.get("id"): x for x in load_certificates()}
    out, seen = [], set()
    for item in items:
        if not isinstance(item, dict):
            raise HttpError(400, "cible TLS invalide")
        url = normalize_tls_target(item.get("url"))
        ident = hashlib.sha256(url.encode()).hexdigest()[:16]
        if ident in seen:
            raise HttpError(400, f"cible TLS déjà configurée : {url}")
        seen.add(ident)
        name = str(item.get("name") or url).strip()[:120]
        previous = old.get(ident, {})
        out.append({"id": ident, "name": name, "url": url,
                    **{k: previous[k] for k in ("last_checked", "expires_at", "days_left", "issuer", "subject", "ok", "error", "verified") if k in previous}})
    atomic_write(DATA / "certificates.yaml", yaml.safe_dump({"certificates": out}, allow_unicode=True, sort_keys=False))


def check_tls_certificate(target):
    """Inspecte le certificat présenté sans ignorer le résultat de validation TLS."""
    parsed = urlsplit(target)
    host, port = parsed.hostname, parsed.port or 443
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result = {"last_checked": now, "ok": False, "url": target}
    try:
        # Inspection en lecture seule : permet de récupérer la date même si le certificat est expiré.
        context = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        # Analyse le DER directement sur stdin : aucun fichier temporaire n'est nécessaire.
        # C'est important dans les conteneurs en lecture seule ou sans /tmp utilisable.
        import subprocess
        proc = subprocess.run(
            ["openssl", "x509", "-inform", "DER", "-noout", "-enddate", "-issuer", "-subject"],
            input=der, capture_output=True, timeout=5,
        )
        if proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            raise ValueError("impossible de décoder le certificat présenté" + (f" : {detail[:120]}" if detail else ""))
        decoded = {}
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            key, sep, value = line.partition("=")
            if sep:
                decoded[key.strip()] = value.strip()
        not_after = decoded.get("notAfter")
        if not not_after:
            raise ValueError("la date d'expiration est absente du certificat")
        expiry_ts = ssl.cert_time_to_seconds(not_after)
        expiry = datetime.fromtimestamp(expiry_ts, timezone.utc)
        result.update(expires_at=expiry.isoformat(timespec="seconds"), days_left=(expiry.date() - date.today()).days,
                      issuer=decoded.get("issuer", ""), subject=decoded.get("subject", ""), ok=True)
        # Vérification séparée : un certificat expiré/auto-signé peut être lu, mais pas déclaré valide.
        try:
            verified_context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=8) as sock:
                with verified_context.wrap_socket(sock, server_hostname=host):
                    result["verified"] = True
        except Exception as e:
            result["verified"] = False
            result["verification_error"] = str(e)[:180]
    except Exception as e:
        result["error"] = str(e)[:180]
    return result


def refresh_certificates():
    items = load_certificates()
    if not items:
        return []
    results = []
    for item in items:
        checked = check_tls_certificate(item["url"])
        results.append({**item, **checked})
    atomic_write(DATA / "certificates.yaml", yaml.safe_dump({"certificates": results}, allow_unicode=True, sort_keys=False))
    return results


def tech_subjects(techs, assets):
    """Une technologie devient un « sujet » par version déclarée (l'inventaire détaillé prime s'il couvre le produit)."""
    covered = {cr.norm(a.get("product", "")) for a in assets}
    out = []
    for t in techs:
        if cr.norm(t["name"]) in covered:
            continue
        for v in t.get("versions") or [None]:
            out.append({"id": f"{t['name']} {v}" if v else t["name"], "product": t["name"], "version": v,
                        "eol_product": t.get("eol_product"), "keywords": t.get("keywords") or [], "owner": t.get("owner"),
                        "facts": t.get("facts") or {}, "github_repo": t.get("github_repo"),
                        "source_url": t.get("source_url"), "source_type": t.get("source_type"),
                        "source_id": t.get("source_id"), "scope": "tech", "ref": t["name"]})
    return out


def all_subjects():
    # Veille organisationnelle : suivre les technologies et leurs versions, pas chaque machine.
    return tech_subjects(load_techs(), [])


def read_events():
    out = []
    for p in sorted((DATA / "events").glob("*.y*ml")):
        try:
            ev = yaml.safe_load(p.read_text(encoding="utf-8"))
            if not isinstance(ev, dict):
                raise ValueError("un mapping YAML est attendu")
            errs, warns = cr.validate_event(ev)
        except Exception as e:
            ev, errs, warns = {}, [f"YAML illisible: {e}"], []
        ev.setdefault("id", p.stem)
        ev.update(_file=p.name, _errors=errs, _warnings=warns)
        out.append(ev)
    return out


def load_treated():
    path = DATA / "treated-findings.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_treated(data):
    atomic_write(DATA / "treated-findings.json", json.dumps(data, ensure_ascii=False, indent=2))


def mark_finding(body):
    key = body.get("key")
    treated = body.get("treated", True)
    if not isinstance(key, str) or not key or len(key) > 300 or not isinstance(treated, bool):
        raise HttpError(400, "clé de signalement ou état invalide")
    with LOCK:
        data = load_treated()
        if treated:
            data[key] = {"treated_at": datetime.now().astimezone().isoformat(timespec="seconds")}
        else:
            data.pop(key, None)
        save_treated(data)


def build_state():
    events = read_events()
    valid = [e for e in events if not e["_errors"]]
    assets = load_assets()
    techs = load_techs()
    # L'inventaire détaillé historique est conservé pour compatibilité, mais ne pilote plus la veille.
    subjects = tech_subjects(techs, [])
    today, by, amap = date.today(), {e["id"]: e for e in valid}, {a["id"]: a for a in subjects}
    findings = []
    for f in cr.correlate(subjects, valid):
        ev, a, d = by[f.event_id], amap[f.asset_id], asdict(f)
        d.update(title=ev["title"], severity=ev["severity"], source=ev["source"],
                 timing=cr.timing(ev, today), verified=bool(ev.get("verified_at")), kind="event", scope=a.get("scope", "asset"), ref=a.get("ref", a["id"]))
        if f.status == cr.VERIFY:
            for t in ev["affected"]:
                c = t.get("check")
                if c and cr.match_target(a, t) and c["fact"] not in (a.get("facts") or {}):
                    d["ask"] = {"fact": c["fact"], "question": c.get("question") or c["fact"]}
                    break
        findings.append(d)
    # La veille est pilotée par les technologies déclarées, pas par les actifs individuels.
    ff = feeds.findings(subjects, DATA / "cache", today)
    findings += ff
    # Contrôle des certificats TLS configurés (résultats du dernier rafraîchissement).
    certs = load_certificates()
    for cert in certs:
        if cert.get("expires_at"):
            days = int(cert.get("days_left", 9999))
            if days <= 30:
                status = cr.AFFECTED
            elif days <= 60 or not cert.get("verified", False):
                status = cr.VERIFY
            else:
                status = cr.NOT_AFFECTED
            timing = "expiré" if days < 0 else (f"expire dans {days} j" if days <= 60 else f"expiration le {cert['expires_at'][:10]}")
            reasons = [f"Expiration du certificat présenté : {cert['expires_at']}", f"Jours restants : {days}"]
            if not cert.get("verified", False):
                reasons.append("La validation de confiance/nom TLS a échoué : " + str(cert.get("verification_error") or "cause inconnue"))
            findings.append({"event_id": "tls-" + cert["id"], "asset_id": cert["name"], "status": status,
                "reasons": reasons, "actions": ["Renouveler le certificat et vérifier la chaîne TLS"] if status != cr.NOT_AFFECTED else [],
                "title": f"Certificat SSL/TLS : {cert['name']}", "severity": "high" if days <= 30 else "medium",
                "source": cert["url"], "timing": timing, "verified": bool(cert.get("verified")), "kind": "ssl", "scope": "asset", "ref": cert["name"]})
        elif cert.get("error"):
            findings.append({"event_id": "tls-" + cert["id"], "asset_id": cert["name"], "status": cr.VERIFY,
                "reasons": ["Échec de récupération du certificat : " + str(cert["error"])], "actions": ["Vérifier l’URL, le port, le DNS et l’accès réseau depuis ChangeRadar"],
                "title": f"Certificat SSL/TLS inaccessible : {cert['name']}", "severity": "medium", "source": cert["url"],
                "timing": "contrôle en échec", "verified": False, "kind": "ssl", "scope": "asset", "ref": cert["name"]})
    # Dernière release GitHub connue, récupérée uniquement lors de l'actualisation des sources.
    releases_path = DATA / "cache" / "github-releases.json"
    try:
        github_releases = json.loads(releases_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        github_releases = {}
    for a in subjects:
        repo = str(a.get("github_repo") or "").strip().rstrip("/")
        if not repo:
            continue
        rel = github_releases.get(a["id"])
        if not isinstance(rel, dict) or not rel.get("tag_name"):
            continue
        current = re.sub(r"^[vV]", "", str(a.get("version") or "").strip())
        latest = re.sub(r"^[vV]", "", str(rel["tag_name"]).strip())
        if current and current == latest:
            continue
        reasons = [f"Version installée : {a.get('version') or 'non renseignée'}",
            f"Dernière version publiée : {rel['tag_name']}",
            "Source GitHub structurée : comparaison de la version installée avec la release ou le tag." ]
        if rel.get("published_at"):
            reasons.append(f"Date de publication : {rel['published_at']}")
        if rel.get("body"):
            notes = re.sub(r"\s+", " ", str(rel["body"])).strip()
            reasons.append("Notes de version : " + notes[:900] + ("…" if len(notes) > 900 else ""))
        if rel.get("source_type") == "tag":
            reasons.append("Aucune GitHub Release trouvée : le tag est utilisé comme indication de version, sans notes de version ni date de publication confirmées.")
        else:
            reasons.append("Vérifie les notes de version et la compatibilité avant mise à jour.")
        findings.append({"event_id": f"github-release-{a['id']}", "asset_id": a["id"],
            "status": cr.VERIFY, "reasons": reasons,
            "actions": ["Consulter la source et planifier la mise à jour si elle est pertinente"],
            "title": f"{a.get('product') or a['id']} : nouvelle version GitHub {rel['tag_name']}",
            "severity": "medium", "source": rel.get("html_url") or f"https://github.com/{repo}/releases",
            "timing": "version disponible", "verified": True, "kind": "event", "scope": a.get("scope", "tech"), "ref": a.get("ref", a["id"])})
    sources = feeds.sources_status(DATA / "cache")
    sources.update(cert_window=feeds.cert_window_count(DATA / "cache", today),
                   cert_matched=len({f["event_id"] for f in ff if f["kind"] == "cve"}))
    treated = load_treated()
    for finding in findings:
        finding["treated"] = f"{finding.get('event_id')}|{finding.get('asset_id')}" in treated
    rank = {cr.AFFECTED: 0, cr.VERIFY: 1, cr.NOT_AFFECTED: 2}
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda d: (rank[d["status"]], sev.get(d["severity"], 2)))
    return {"today": str(today), "assets": assets, "findings": findings, "sources": sources, "techs": techs,
            "treated_findings": treated, "github_sources": load_github_sources(), "certificates": certs, "events": [{"id": e["id"], "title": e.get("title", ""), "severity": e.get("severity", ""),
                        "effective_at": str(e.get("effective_at", "")), "source": str(e.get("source", "")),
                        "verified": bool(e.get("verified_at")), "file": e["_file"],
                        "errors": e["_errors"], "warnings": e["_warnings"]} for e in events]}


def set_fact(body):
    ref, fact, val, scope = body.get("asset"), body.get("fact"), body.get("value"), body.get("scope", "asset")
    if not isinstance(fact, str) or not ID_RE.match(fact) or val not in (True, False, None) or scope not in ("asset", "tech"):
        raise HttpError(400, "requête invalide (fact: identifiant, value: true/false/null)")
    with LOCK:
        items = load_techs() if scope == "tech" else load_assets()
        key = "name" if scope == "tech" else "id"
        a = next((x for x in items if x[key] == ref), None)
        if not a:
            raise HttpError(404, f"élément inconnu: {ref}")
        facts = a.setdefault("facts", {})
        if val is None:
            facts.pop(fact, None)
            if not facts:
                a.pop("facts")
        else:
            facts[fact] = val
        (save_techs if scope == "tech" else save_assets)(items)


def import_csv(text):
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows or "id" not in rows[0]:
        raise HttpError(400, "CSV: colonne 'id' requise (colonnes: id,product,version,role,site,owner)")
    with LOCK:
        cur = {a["id"]: a for a in load_assets()}
        for r in rows:
            i = (r.get("id") or "").strip()
            if not ID_RE.match(i):
                raise HttpError(400, f"CSV: id invalide {i!r}")
            a = cur.setdefault(i, {"id": i})
            for k in FIELDS:
                if (r.get(k) or "").strip():
                    a[k] = r[k].strip()
        save_assets(list(cur.values()))
    return len(rows)


def add_event(text):
    try:
        ev = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise HttpError(400, "YAML invalide", [str(e)])
    if not isinstance(ev, dict):
        raise HttpError(400, "un mapping YAML est attendu")
    errs, _ = cr.validate_event(ev)
    if not errs and not ID_RE.match(str(ev["id"])):
        errs.append("id invalide (lettres, chiffres, . _ -)")
    if errs:
        raise HttpError(400, "Événement invalide", errs)
    with LOCK:
        atomic_write(DATA / "events" / f"{ev['id']}.yaml",
                     yaml.safe_dump(ev, allow_unicode=True, sort_keys=False))


def delete_event(eid):
    with LOCK:
        for e in read_events():
            if e["id"] == eid:
                (DATA / "events" / e["_file"]).unlink()
                return
    raise HttpError(404, "événement inconnu")


REFRESH = threading.Lock()


def do_refresh():
    if not REFRESH.acquire(blocking=False):
        raise HttpError(409, "actualisation déjà en cours")
    try:
        result = feeds.refresh(all_subjects(), DATA / "cache")
        result["tls"] = [{"id": c["id"], "ok": bool(c.get("ok")), "expires_at": c.get("expires_at"), "error": c.get("error")} for c in refresh_certificates()]
        return result
    finally:
        REFRESH.release()


def refresher(hours):
    time.sleep(3)
    while True:
        try:
            do_refresh()
        except Exception as e:  # noqa
            sys.stderr.write(f"actualisation: {e!r}\n")
        time.sleep(hours * 3600)


# --------------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    server_version = "ChangeRadar"

    def log_message(self, fmt, *a):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % a))

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        b = body if isinstance(body, bytes) else json.dumps(body, default=str, ensure_ascii=False).encode()
        self.send_response(code)
        for k, v in (("Content-Type", ctype), ("Content-Length", str(len(b))), ("Cache-Control", "no-store"),
                     ("X-Content-Type-Options", "nosniff"), ("Content-Security-Policy", CSP),
                     ("Referrer-Policy", "no-referrer")):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def _guard(self, write):
        if not TOKEN:  # anti DNS-rebinding en mode loopback sans jeton
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0] if not (self.headers.get("Host") or "").startswith("[") else "[::1]"
            if host not in ("localhost", "127.0.0.1", "[::1]"):
                raise HttpError(403, "Host non autorisé")
        else:
            got = (self.headers.get("Authorization") or "")[7:]
            if not hmac.compare_digest(got.encode(), TOKEN.encode()):
                raise HttpError(401, "jeton requis")
        if write and self.headers.get("X-ChangeRadar") != "1":
            raise HttpError(403, "en-tête X-ChangeRadar manquant")

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise HttpError(413, "corps trop gros")
        return self.rfile.read(n).decode("utf-8-sig")

    def _handle(self, method):
        try:
            path = self.path.split("?")[0]
            if method == "GET" and path in STATIC:
                name, ctype = STATIC[path]
                return self._send(200, (HERE / "static" / name).read_bytes(), ctype)
            if not path.startswith("/api/"):
                raise HttpError(404, "introuvable")
            self._guard(write=method != "GET")
            if method == "GET" and path == "/api/state":
                return self._send(200, build_state())
            if method == "PUT" and path == "/api/assets":
                with LOCK:
                    save_assets(json.loads(self._body()))
                return self._send(200, {"ok": True})
            if method == "POST" and path == "/api/findings/treated":
                mark_finding(json.loads(self._body()))
                return self._send(200, {"ok": True})
            if method == "POST" and path == "/api/facts":
                set_fact(json.loads(self._body()))
                return self._send(200, {"ok": True})
            if method == "POST" and path == "/api/import-csv":
                return self._send(200, {"imported": import_csv(self._body())})
            if method == "POST" and path == "/api/events":
                add_event(self._body())
                return self._send(200, {"ok": True})
            if method == "PUT" and path == "/api/technologies":
                with LOCK:
                    save_techs(json.loads(self._body()))
                return self._send(200, {"ok": True})
            if method == "GET" and path == "/api/eol-products":
                return self._send(200, {"products": feeds.catalog(DATA / "cache")})
            if method == "GET" and path == "/api/technology-catalog":
                products = feeds.catalog(DATA / "cache")
                if not products and os.environ.get("CR_OFFLINE") != "1":
                    try:
                        feeds.refresh_catalog(DATA / "cache")
                        products = feeds.catalog(DATA / "cache")
                    except Exception:
                        pass
                repos = load_github_sources()
                return self._send(200, {"sources": ([{"type": "eol", "id": p["name"], "name": p.get("label") or p["name"]} for p in products] +
                    [{"type": "github", "id": r["repo"], "name": r["name"]} for r in repos] +
                    [{"type": "cert", "id": "cert-keyword", "name": "CERT Santé — correspondance par mots-clés"}])})
            if method == "GET" and path == "/api/source-versions":
                from urllib.parse import parse_qs, urlsplit
                q = parse_qs(urlsplit(self.path).query)
                typ, sid = (q.get("type") or [""])[0], (q.get("id") or [""])[0]
                return self._send(200, {"versions": source_versions(typ, sid), "manual": typ == "cert"})
            if method == "PUT" and path == "/api/certificates":
                with LOCK:
                    save_certificates(json.loads(self._body()))
                return self._send(200, {"ok": True})
            if method == "PUT" and path == "/api/github-sources":
                with LOCK:
                    save_github_sources(json.loads(self._body()))
                return self._send(200, {"ok": True})
            if method == "POST" and path == "/api/refresh":
                return self._send(200, do_refresh())
            if method == "DELETE" and path.startswith("/api/events/"):
                delete_event(path.rsplit("/", 1)[1])
                return self._send(200, {"ok": True})
            raise HttpError(404, "route inconnue")
        except HttpError as e:
            self._send(e.code, {"error": e.msg, "details": e.details})
        except json.JSONDecodeError:
            self._send(400, {"error": "JSON invalide"})
        except Exception as e:  # noqa
            sys.stderr.write(f"erreur interne: {e!r}\n")
            self._send(500, {"error": "erreur interne"})

    do_GET = lambda s: s._handle("GET")
    do_PUT = lambda s: s._handle("PUT")
    do_POST = lambda s: s._handle("POST")
    do_DELETE = lambda s: s._handle("DELETE")


def main():
    host, port = os.environ.get("CR_HOST", "127.0.0.1"), int(os.environ.get("CR_PORT", "8080"))
    if host not in ("127.0.0.1", "localhost", "::1") and not TOKEN and os.environ.get("CR_INSECURE") != "1":
        sys.exit("Refus : écoute hors loopback sans CR_TOKEN. Définir CR_TOKEN (ou CR_INSECURE=1).")
    bootstrap()
    hours = float(os.environ.get("CR_REFRESH_HOURS", "6"))
    if hours > 0 and os.environ.get("CR_OFFLINE") != "1":
        threading.Thread(target=refresher, args=(hours,), daemon=True).start()
    print(f"ChangeRadar sur http://{host}:{port}  (données: {DATA})", flush=True)
    ThreadingHTTPServer((host, port), H).serve_forever()


if __name__ == "__main__":
    main()
