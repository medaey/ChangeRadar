"""Collecteurs de sources : endoflife.date (fins de support) et CERT Santé (alertes/vulnérabilités).

Principe inchangé : on ne conclut « CONCERNÉ » que sur des faits établis.
- endoflife.date : version de l'actif rattachée à un cycle -> fait établi (date de fin de support).
- CERT Santé     : simple correspondance de NOM de produit -> toujours « À VÉRIFIER » tant que
                   l'utilisateur n'a pas répondu (le flux RSS ne donne pas les versions affectées).
"""
import html, json, os, re, tempfile, urllib.error, urllib.request
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

import changeradar as cr

EOL_API = "https://endoflife.date/api/v1/products/{}/"
EOL_PAGE = "https://endoflife.date/{}"
CERT_RSS = "https://cyberveille.esante.gouv.fr/alertes-et-vulnerabilites/rss.xml"
CERT_HOST = "https://cyberveille.esante.gouv.fr/"
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,60}$")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
ALIASES = {"red-hat-enterprise-linux": "rhel", "redhat": "rhel"}
HORIZON = int(os.environ.get("CR_EOL_HORIZON_DAYS", "180"))
CVE_DAYS = int(os.environ.get("CR_CVE_DAYS", "45"))


def fetch(url: str, limit: int = 5_000_000) -> bytes:
    if os.environ.get("CR_OFFLINE") == "1":
        raise RuntimeError("mode hors-ligne (CR_OFFLINE=1)")
    if not url.startswith("https://"):
        raise ValueError("https requis")
    req = urllib.request.Request(url, headers={"User-Agent": "ChangeRadar/1.0 (self-hosted)"})
    with urllib.request.urlopen(req, timeout=20) as r:
        body = r.read(limit + 1)
    if len(body) > limit:
        raise ValueError("réponse trop volumineuse")
    return body


def write_json(path: Path, obj):
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False)
    os.replace(tmp, path)


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def term_hit(term, hay: str) -> bool:
    """Tous les mots du terme doivent figurer (mots entiers) dans le texte normalisé."""
    n = cr.norm(term)
    toks = [t for t in n.split("-") if t]
    return len(n) >= 3 and all(re.search(rf"(?<![a-z0-9]){re.escape(t)}(?![a-z0-9])", hay) for t in toks)


def refresh_catalog(cache: Path):
    data = json.loads(fetch("https://endoflife.date/api/v1/products"))
    write_json(cache / "eol-catalog.json", [{"name": p["name"], "label": p.get("label") or p["name"]}
                                           for p in data["result"] if SLUG_RE.match(p.get("name", ""))])


def catalog(cache: Path) -> list:
    return read_json(cache / "eol-catalog.json", [])


def cert_window_count(cache: Path, today: date) -> int:
    n = 0
    for it in read_json(cache / "cert.json", []):
        try:
            n += (today - date.fromisoformat(it["date"])).days <= CVE_DAYS
        except (TypeError, ValueError):
            pass
    return n


def slug_for(asset: dict):
    # Une source GitHub/CERT ne doit jamais être interprétée comme un slug endoflife.date.
    source_type = str(asset.get("source_type") or "").lower()
    if source_type and source_type != "eol" and not asset.get("eol_product"):
        return None
    base = cr.norm(asset.get("product", ""))
    s = str(asset.get("eol_product") or ALIASES.get(base, base)).strip().lower()
    return s if SLUG_RE.match(s) else None


# ------------------------------------------------------------------ collecte
def parse_cert(body: bytes) -> list[dict]:
    out = []
    for it in ET.fromstring(body).iter("item"):
        title = (it.findtext("title") or "").strip()
        m = CVE_RE.search(title)
        try:
            pub = parsedate_to_datetime(it.findtext("pubDate")).date().isoformat()
        except Exception:
            pub = None
        text = html.unescape(re.sub(r"<[^>]+>", " ", it.findtext("description") or ""))
        link = (it.findtext("link") or "").strip()
        out.append({"title": title, "cve": m.group(0).upper() if m else None, "date": pub,
                    "link": link if link.startswith(CERT_HOST) else "",
                    "text": re.sub(r"\s+", " ", text).strip()})
    return out


def refresh(assets: list[dict], cache: Path) -> dict:
    cache.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    st = {"eol": {}, "cert": {}}
    try:
        refresh_catalog(cache)
    except Exception:
        pass  # liste d'autocomplétion : non bloquant
    for slug in sorted({s for a in assets if (s := slug_for(a))}):
        try:
            write_json(cache / f"eol-{slug}.json", json.loads(fetch(EOL_API.format(slug)))["result"])
            st["eol"][slug] = {"at": now, "ok": True}
        except urllib.error.HTTPError as e:
            st["eol"][slug] = {"at": now, "ok": False, "error":
                               "produit inconnu d'endoflife.date : renseigner eol_product" if e.code == 404 else f"HTTP {e.code}"}
        except Exception as e:
            st["eol"][slug] = {"at": now, "ok": False, "error": str(e)[:150]}
    try:
        body = fetch(CERT_RSS)
        if re.search(rb"<!(DOCTYPE|ENTITY)", body, re.I):
            raise ValueError("flux XML refusé (DTD/entités)")
        items = parse_cert(body)
        write_json(cache / "cert.json", items)
        st["cert"] = {"at": now, "ok": True, "items": len(items)}
    except Exception as e:
        st["cert"] = {"at": now, "ok": False, "error": str(e)[:150]}
    # Releases GitHub publiques : un seul appel par actif configuré, sans jeton.
    github = {}
    for a in assets:
        raw = str(a.get("github_repo") or "").strip().rstrip("/")
        m = re.fullmatch(r"(?:https://github\.com/)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", raw)
        if not m:
            continue
        owner, repo = m.group(1), m.group(2)
        if repo.endswith(".git"):
            repo = repo[:-4]
        try:
            api = f"https://api.github.com/repos/{owner}/{repo}"
            # GitHub Releases est structuré : tags, date, notes et indicateur de prérelease.
            # On choisit la release stable la plus récente, sans dépendre d'un nom de tag précis.
            releases = json.loads(fetch(api + "/releases?per_page=20", limit=1_500_000))
            if not isinstance(releases, list):
                raise ValueError("réponse GitHub Releases inattendue")
            release = next((r for r in releases if not r.get("draft") and not r.get("prerelease")
                            and r.get("tag_name")), None)
            if release:
                tag = str(release.get("tag_name") or "")
                html_url = str(release.get("html_url") or f"https://github.com/{owner}/{repo}/releases")
                if tag and html_url.startswith("https://github.com/"):
                    github[a["id"]] = {"tag_name": tag, "html_url": html_url,
                        "published_at": release.get("published_at"),
                        "name": str(release.get("name") or tag),
                        "body": str(release.get("body") or "")[:12000],
                        "prerelease": False, "source_type": "release", "at": now}
                    continue
            # Certains dépôts publient des tags sans créer de GitHub Release.
            # On garde alors le tag comme signal faible, sans inventer de notes de version.
            tags = json.loads(fetch(api + "/tags?per_page=1", limit=200_000))
            if isinstance(tags, list) and tags and tags[0].get("name"):
                tag = str(tags[0]["name"])
                github[a["id"]] = {"tag_name": tag,
                    "html_url": f"https://github.com/{owner}/{repo}/tree/{tag}",
                    "name": tag, "body": "", "published_at": None,
                    "prerelease": None, "source_type": "tag", "at": now}
            else:
                github[a["id"]] = {"error": "aucune release stable ni tag trouvé", "at": now}
        except Exception as e:
            # Une panne GitHub ne doit pas invalider les autres sources.
            github[a["id"]] = {"error": str(e)[:120], "at": now}
    write_json(cache / "github-releases.json", github)
    write_json(cache / "status.json", st)
    return st


def sources_status(cache: Path) -> dict:
    st = read_json(cache / "status.json", {"eol": {}, "cert": {}})
    st.update(offline=os.environ.get("CR_OFFLINE") == "1", horizon=HORIZON, cve_days=CVE_DAYS)
    return st


# --------------------------------------------------------------- corrélation
def match_release(version, releases):
    m = re.match(r"^v?(\d+(?:\.\d+)*)", str(version or "").strip())
    if not m:
        return None
    names = {r["name"]: r for r in releases}
    parts = m.group(1).split(".")
    for n in range(len(parts), 0, -1):
        if ".".join(parts[:n]) in names:
            return names[".".join(parts[:n])]
    return None


def eol_findings(a: dict, slug: str, res: dict, today: date) -> dict:
    label, rels, page = res.get("label") or slug, res.get("releases", []), EOL_PAGE.format(slug)
    f = {"event_id": f"eol-{slug}", "asset_id": a["id"], "kind": "eol", "source": page,
         "verified": True, "severity": "medium", "title": f"{label} : fin de support", "ask": None,
         "scope": a.get("scope", "asset"), "ref": a.get("ref", a["id"])}
    rel = match_release(a.get("version"), rels)
    if not rel:
        f.update(status=cr.VERIFY, timing="cycle inconnu",
                 reasons=[f"version {a.get('version') or 'non renseignée'} non rattachable à un cycle {label} "
                          f"(cycles connus : {', '.join(r['name'] for r in rels[:6])}…)"],
                 actions=[f"Renseigner la version exacte de {a['id']}"])
        return f
    eol = date.fromisoformat(rel["eolFrom"]) if rel.get("eolFrom") else None
    maint = next((r["name"] for r in rels if r.get("isMaintained")), None)
    f["title"] = f"{label} {rel['name']} : fin de support"
    f["reasons"] = [f"version {a.get('version')} ↔ cycle {rel['name']} (source : endoflife.date)"]
    pol = (res.get("links") or {}).get("releasePolicy")
    if pol:
        f["reasons"].append(f"politique éditeur à consulter : {pol}")
    if rel.get("isEol") or (eol and eol <= today):
        f.update(status=cr.AFFECTED, severity="high",
                 timing=f"fin de support depuis {(today - eol).days} j ({eol})" if eol else "fin de support (date non précisée)",
                 actions=[f"Planifier la migration de {a['id']}" + (f" vers un cycle maintenu (ex. {maint})" if maint else "")])
    elif eol and (eol - today).days <= HORIZON:
        f.update(status=cr.AFFECTED, timing=f"dans {(eol - today).days} j ({eol})",
                 actions=[f"Planifier la migration de {a['id']} avant le {eol}"])
    else:
        f.update(status=cr.NOT_AFFECTED, actions=[],
                 timing=f"supporté jusqu'au {eol}" if eol else "aucune fin de support annoncée")
    return f


def fact_key(it: dict) -> str:
    return ("affected_" + re.sub(r"[^a-z0-9]+", "_", (it["cve"] or it["title"]).lower()).strip("_"))[:70]


def findings(assets: list[dict], cache: Path, today: date) -> list[dict]:
    out = []
    for a in assets:
        slug = slug_for(a)
        res = read_json(cache / f"eol-{slug}.json", None) if slug else None
        if res:
            out.append(eol_findings(a, slug, res, today))
    for it in read_json(cache / "cert.json", []):
        try:
            age = (today - date.fromisoformat(it["date"])).days
        except (TypeError, ValueError):
            continue
        if age > CVE_DAYS:
            continue
        hay = cr.norm(it["title"] + " " + it["text"])
        for a in assets:
            terms = [a.get("product", "")] + list(a.get("keywords") or [])
            hit = next((t for t in terms if term_hit(t, hay)), None)
            if not hit:
                continue
            key, facts, name = fact_key(it), a.get("facts") or {}, it["cve"] or it["title"]
            f = {"event_id": key, "asset_id": a["id"], "kind": "cve", "title": it["title"], "severity": "unknown",
                 "source": it["link"], "verified": True, "timing": f"publié il y a {age} j ({it['date']})",
                 "reasons": [f"le bulletin CERT Santé mentionne « {hit} »",
                             "correspondance par nom de produit uniquement : les versions affectées sont à lire dans le bulletin"],
                 "ask": None, "scope": a.get("scope", "asset"), "ref": a.get("ref", a["id"])}
            if key in facts:
                ok = bool(facts[key])
                f.update(status=cr.AFFECTED if ok else cr.NOT_AFFECTED,
                         actions=[f"Appliquer le correctif ou le contournement du bulletin sur {a['id']}"] if ok else [])
                f["reasons"].append("réponse enregistrée : " + ("affecté" if ok else "non affecté"))
            else:
                f.update(status=cr.VERIFY,
                         actions=[f"Lire le bulletin et comparer à la version de {a['id']} ({a.get('version', '?')})"],
                         ask={"fact": key, "question": f"{name} : la version de {a['id']} est-elle dans le périmètre affecté ?"})
            out.append(f)
    return out
