#!/usr/bin/env python3
"""ChangeRadar V1 — corrélation locale entre événements technologiques et inventaire.

Principe : un produit présent dans l'inventaire n'est PAS automatiquement concerné.
Le moteur ne conclut "concerné" que si les faits connus le prouvent ; sinon il
demande une vérification explicite.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import date
from pathlib import Path

import yaml

SEVERITIES = ("low", "medium", "high", "critical")
REQUIRED_EVENT_FIELDS = ("id", "title", "category", "source", "effective_at", "severity", "affected")

# Statuts de corrélation
AFFECTED = "CONCERNÉ"                 # les faits connus établissent la condition
VERIFY = "À VÉRIFIER"                 # produit/rôle correspond, mais faits insuffisants
NOT_AFFECTED = "NON CONCERNÉ"         # les faits connus infirment la condition
NO_MATCH = "HORS PÉRIMÈTRE"           # ni produit ni rôle ne correspondent


# ---------------------------------------------------------------- chargement
def load_yaml(path: Path):
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def parse_date(value, label: str) -> date | None:
    if value in (None, ""):
        return None
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError:
        raise ValueError(f"{label}: date ISO attendue (AAAA-MM-JJ), reçu {value!r}")


def validate_event(ev: dict) -> tuple[list[str], list[str]]:
    """Retourne (erreurs, avertissements)."""
    errors, warnings = [], []
    for f in REQUIRED_EVENT_FIELDS:
        if f not in ev:
            errors.append(f"champ requis manquant: {f}")
    if errors:
        return errors, warnings
    if ev["severity"] not in SEVERITIES:
        errors.append(f"severity invalide: {ev['severity']!r} (attendu: {', '.join(SEVERITIES)})")
    if not str(ev["source"]).startswith("https://"):
        errors.append("source doit être une URL https://")
    for key in ("announced_at", "effective_at", "verified_at"):
        try:
            parse_date(ev.get(key), key)
        except ValueError as exc:
            errors.append(str(exc))
    if not isinstance(ev["affected"], list) or not ev["affected"]:
        errors.append("affected doit être une liste non vide")
    else:
        for i, a in enumerate(ev["affected"]):
            if not (a.get("product") or a.get("role")):
                errors.append(f"affected[{i}]: 'product' ou 'role' requis")
    if ev.get("verification_required") and not ev.get("verified_at"):
        warnings.append("événement non vérifié à la source (verified_at absent)")
    return errors, warnings


def load_events(directory: Path) -> list[dict]:
    events = []
    for p in sorted(directory.glob("*.y*ml")):
        ev = load_yaml(p)
        ev["_file"] = str(p)
        events.append(ev)
    return events


def load_inventory(path: Path) -> list[dict]:
    data = load_yaml(path)
    assets = data.get("assets", []) if isinstance(data, dict) else []
    seen = set()
    for a in assets:
        if "id" not in a:
            raise ValueError("actif sans 'id'")
        if a["id"] in seen:
            raise ValueError(f"id d'actif en double: {a['id']}")
        seen.add(a["id"])
    return assets


# ------------------------------------------------------------ normalisation
def norm(s) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")


def parse_version(v) -> tuple[int, ...] | None:
    """'1.19.2' -> (1,19,2). Retourne None si inexploitable (ex: 'version-connue')."""
    m = re.match(r"^v?(\d+(?:\.\d+)*)", str(v).strip())
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def version_in_range(version, spec: str) -> bool | None:
    """spec: '<1.19', '>=1.0,<2.0'. None = indéterminable."""
    pv = parse_version(version)
    if pv is None:
        return None
    ops = {"<=": lambda a, b: a <= b, ">=": lambda a, b: a >= b,
           "<": lambda a, b: a < b, ">": lambda a, b: a > b, "==": lambda a, b: a == b}
    for clause in spec.split(","):
        m = re.match(r"^\s*(<=|>=|==|<|>)\s*(.+?)\s*$", clause)
        if not m:
            raise ValueError(f"contrainte de version invalide: {clause!r}")
        bound = parse_version(m.group(2))
        n = max(len(pv), len(bound))
        a, b = pv + (0,) * (n - len(pv)), bound + (0,) * (n - len(bound))
        if not ops[m.group(1)](a, b):
            return False
    return True


# ---------------------------------------------------------------- corrélation
@dataclass
class Finding:
    event_id: str
    asset_id: str
    status: str
    reasons: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)


def match_target(asset: dict, target: dict) -> bool:
    by_product = target.get("product") and norm(target["product"]) == norm(asset.get("product", ""))
    by_role = target.get("role") and norm(target["role"]) == norm(asset.get("role", ""))
    return bool(by_product or by_role)


def evaluate(asset: dict, event: dict) -> Finding | None:
    """Évalue un actif contre un événement. None si aucune cible ne correspond."""
    for target in event["affected"]:
        if not match_target(asset, target):
            continue
        f = Finding(event["id"], asset["id"], VERIFY)
        f.reasons.append(
            f"correspondance sur {'produit' if target.get('product') and norm(target['product']) == norm(asset.get('product','')) else 'rôle'}"
            f" ({target.get('product') or target.get('role')})")
        facts = asset.get("facts", {}) or {}
        verdicts = []  # True = condition remplie, False = infirmée, None = inconnue

        # 1) contrainte de version
        if target.get("versions"):
            r = version_in_range(asset.get("version"), target["versions"])
            if r is None:
                f.reasons.append(f"version {asset.get('version')!r} inexploitable (contrainte {target['versions']})")
            else:
                f.reasons.append(f"version {asset['version']} {'dans' if r else 'hors de'} {target['versions']}")
            verdicts.append(r)

        # 2) condition machine-vérifiable : check: {fact: ..., equals: ...}
        chk = target.get("check")
        if chk:
            if chk["fact"] in facts:
                ok = facts[chk["fact"]] == chk["equals"]
                f.reasons.append(f"fait {chk['fact']}={facts[chk['fact']]!r} → condition {'remplie' if ok else 'non remplie'}")
                verdicts.append(ok)
            else:
                f.reasons.append(f"fait '{chk['fact']}' inconnu dans l'inventaire")
                verdicts.append(None)
        elif target.get("condition"):
            f.reasons.append(f"condition non automatisable: {target['condition']}")
            verdicts.append(None)

        if any(v is False for v in verdicts):
            f.status = NOT_AFFECTED
        elif verdicts and all(v is True for v in verdicts):
            f.status = AFFECTED
        else:
            f.status = VERIFY  # aucune condition établie ou au moins une inconnue

        if f.status == VERIFY:
            f.actions.append(f"Vérifier sur {asset['id']} ({asset.get('owner', 'propriétaire inconnu')}): "
                             f"{target.get('condition', 'configuration réelle')}")
        elif f.status == AFFECTED:
            f.actions.append(f"Planifier la remédiation sur {asset['id']} ({asset.get('owner', '?')})")
        return f
    return None


def correlate(assets: list[dict], events: list[dict]) -> list[Finding]:
    out = []
    for ev in events:
        for a in assets:
            f = evaluate(a, ev)
            if f:
                out.append(f)
    return out


def timing(event: dict, today: date) -> str:
    eff = parse_date(event.get("effective_at"), "effective_at")
    if not eff:
        return "échéance inconnue"
    d = (eff - today).days
    if d > 0:
        return f"dans {d} j ({eff})"
    if d == 0:
        return f"AUJOURD'HUI ({eff})"
    return f"passé depuis {-d} j ({eff}) — contrôle post-événement"


# ------------------------------------------------------------------------ CLI
def cmd_validate(args) -> int:
    rc = 0
    for ev in load_events(Path(args.events)):
        errs, warns = validate_event(ev)
        tag = "ERREUR" if errs else "ok"
        print(f"[{tag}] {ev.get('id', ev['_file'])}")
        for m in errs:
            print(f"    ✗ {m}")
        for m in warns:
            print(f"    ! {m}")
        rc |= bool(errs)
    return rc


def cmd_check(args) -> int:
    today = date.fromisoformat(args.today) if args.today else date.today()
    events = load_events(Path(args.events))
    bad = [(e.get("id", e["_file"]), validate_event(e)[0]) for e in events if validate_event(e)[0]]
    if bad:
        for eid, errs in bad:
            print(f"Événement invalide {eid}: {'; '.join(errs)}", file=sys.stderr)
        return 2
    assets = load_inventory(Path(args.inventory))
    by_id = {e["id"]: e for e in events}
    findings = [f for f in correlate(assets, events) if args.all or f.status != NOT_AFFECTED]

    if args.json:
        print(json.dumps([{**asdict(f), "source": by_id[f.event_id]["source"],
                           "timing": timing(by_id[f.event_id], today),
                           "event_verified": bool(by_id[f.event_id].get("verified_at"))}
                          for f in findings], ensure_ascii=False, indent=2))
    else:
        if not findings:
            print("Aucun actif concerné ou à vérifier.")
        for f in findings:
            ev = by_id[f.event_id]
            print(f"\n[{f.status}] {ev['title']}  (gravité: {ev['severity']})")
            print(f"  actif    : {f.asset_id}")
            print(f"  échéance : {timing(ev, today)}")
            print(f"  source   : {ev['source']}")
            if not ev.get("verified_at"):
                print("  ⚠ événement NON vérifié contre la source officielle")
            for r in f.reasons:
                print(f"  - {r}")
            for a in f.actions:
                print(f"  → {a}")
    # Code retour : 1 si au moins un actif concerné (utile en CI)
    return 1 if args.fail_on_affected and any(f.status == AFFECTED for f in findings) else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="changeradar", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="valider le format des événements")
    v.add_argument("--events", default="events")
    v.set_defaults(func=cmd_validate)
    c = sub.add_parser("check", help="corréler événements et inventaire")
    c.add_argument("--inventory", default="inventory.yaml")
    c.add_argument("--events", default="events")
    c.add_argument("--today", help="date de référence AAAA-MM-JJ (tests)")
    c.add_argument("--all", action="store_true", help="afficher aussi les NON CONCERNÉ")
    c.add_argument("--json", action="store_true")
    c.add_argument("--fail-on-affected", action="store_true")
    c.set_defaults(func=cmd_check)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
