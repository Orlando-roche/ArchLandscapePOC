#!/usr/bin/env python3
import argparse, csv, io, json, os, re, sys
from typing import Dict, List, Tuple, Optional

# ---------- Utils ----------
def read_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def write_json(path: str, data):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def q(s: str) -> str:
    return (s or "").replace('"', '\\"')

def kebab(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", (s or "")).strip("-").lower() or "x"

def norm_pkg_key(s: str) -> str:
    """Normalize keys for matching: trim, lower, unify to '/' separators."""
    s = (s or "").strip()
    s = s.replace("\\", "/").replace(".", "/")
    s = re.sub(r"/+", "/", s)
    return s.lower()

# ---------- CSV parsing ----------
PKG_KEYS = ["package", "component", "name", "path", "id", "artifact"]
VER_KEYS = ["version", "ver", "pkg_version"]

def parse_packages_csv(path: str) -> List[Dict]:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    try:
        dialect = csv.Sniffer().sniff(text.splitlines()[0] if text else "")
    except Exception:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    # Lower-case fieldnames for robust access
    fieldmap = [h.lower() for h in (reader.fieldnames or [])]
    rows = []
    for row in reader:
        raw = {}
        for k, v in (row or {}).items():
            if not k: continue
            raw[k.lower()] = (v or "").strip()
        # Package candidate
        pkg = next((raw[k] for k in PKG_KEYS if k in raw and raw[k]), "")
        # Version candidate
        ver = next((raw[k] for k in VER_KEYS if k in raw and raw[k]), "")
        # Fallback: parse from a joined string
        joined = " ".join([raw.get(k, "") for k in PKG_KEYS + ["gav"] if raw.get(k)])
        if not ver:
            m = re.search(r"(?<!\d)(\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9\.-]+)?)$", joined)
            if m: ver = m.group(1)
        if not pkg and raw.get("gav"):
            mg = re.search(r"([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+)", raw["gav"])
            if mg: pkg = f"{mg.group(1)}:{mg.group(2)}"
        # Last resort: take any non-empty field
        if not pkg:
            for v in raw.values():
                if v: pkg = v; break
        rows.append({"raw": raw, "name": pkg, "version": ver or None})
    return rows

def build_package_version_index(csv_path: Optional[str]) -> Dict[str, str]:
    """Build normalized key -> version from CSV; supports dots/slashes and varied headers."""
    if not csv_path or not os.path.exists(csv_path):
        return {}
    idx: Dict[str, str] = {}
    for row in parse_packages_csv(csv_path):
        ver = (row.get("version") or "").strip()
        if not ver:
            continue
        raw = row.get("raw", {}) or {}
        candidates = [raw.get(k, "") for k in PKG_KEYS] + [row.get("name", "")]
        for c in candidates:
            if not c: continue
            key = norm_pkg_key(c)
            if key: idx[key] = ver
    return idx

def lookup_version(version_map: Dict[str, str], package_path: str) -> Optional[str]:
    """Exact normalized match, then suffix fuzzy match as fallback."""
    key = norm_pkg_key(package_path)
    if key in version_map:
        return version_map[key]
    # Fuzzy: allow suffix matches (e.g., map '.../storage' to 'com/roche/.../storage')
    candidates = [v for k, v in version_map.items() if k.endswith(key)]
    if len(candidates) == 1:
        return candidates[0]
    return None

# ---------- Library mapping from CSV (optional) ----------
LIB_RULES = [
    ("lib-appauth",      "AppAuth",           [r"\bappauth\b", r"net\.openid:appauth"]),
    ("lib-retrofit",     "Retrofit",          [r"\bretrofit\b", r"com\.squareup\.retrofit2:retrofit"]),
    ("lib-okhttp",       "OkHttp",            [r"\bokhttp\b", r"com\.squareup\.okhttp3:okhttp"]),
    ("lib-room",         "Room",              [r"\broom\b", r"androidx\.room:room-(runtime|ktx)"]),
    ("lib-sqlite",       "SQLite",            [r"\bsqlite\b", r"androidx\.sqlite\b"]),
    ("lib-sec-crypto",   "AndroidX Security", [r"(androidx\.security:security-crypto|encryptedsharedpreferences|security-crypto)"]),
]

def map_to_library(name_or_gav: str) -> Optional[Tuple[str, str]]:
    s = (name_or_gav or "").strip().lower()
    for lib_id, canon, pats in LIB_RULES:
        for p in pats:
            if re.search(p, s):
                return lib_id, canon
    return None

# ---------- AFM helpers ----------
def mermaid_from_afm(afm: dict) -> str:
    import re

    SAFE = re.compile(r'[^A-Za-z0-9_-]+')
    STRIP_TRAIL = re.compile(r'[%\uFF05]+$')   # strip ASCII % and full-width ％ at end

    def mid(s: str) -> str:
        return STRIP_TRAIL.sub('', SAFE.sub('-', (s or ''))).strip('-')

    # Build consistent id map for all nodes
    id_map = {}
    for c in afm.get("components", []):
        raw_id = c["id"]
        id_map[raw_id] = mid(raw_id)

    lines = ["graph LR"]

    # Nodes
    for c in afm.get("components", []):
        nid = id_map[c["id"]]
        md = c.get("metadata") if isinstance(c.get("metadata"), dict) else {}
        ver = md.get("version") if isinstance(md, dict) else None

        if c.get("type") == "Package":
            # label shows the path + (version), id stays kebab for wiring
            base = c.get("name", c.get("id"))
            label = f"{base} ({ver})" if ver else base
        else:
            label = f'{c.get("name","?")} ({c.get("type","?")})'

        lines.append(f'  {nid}["{q(label)}"]')

    # Edges
    for r in afm.get("relations", []):
        f_raw, t_raw = r["from"], r["to"]
        f = id_map.get(f_raw, mid(f_raw))
        t = id_map.get(t_raw, mid(t_raw))
        # belt & suspenders: strip trailing %/％ again
        f = STRIP_TRAIL.sub('', f)
        t = STRIP_TRAIL.sub('', t)

        through = r.get("through", {}) or {}
        lab = through.get("protocol") or r.get("verb", "uses")

        # show clean arrow for classification edges
        if through.get("protocol") == "classification":
            lines.append(f'  {f} --> {t}')
        else:
            lines.append(f'  {f} -->|{q(lab)}| {t}')

    return "\n".join(lines)

def add_component(afm: dict, comp: dict):
    afm.setdefault("components", [])
    if not any(c["id"] == comp["id"] for c in afm["components"]):
        afm["components"].append(comp)

def add_relation(afm: dict, rel: dict):
    afm.setdefault("relations", [])
    def _key(r):
        return (r["from"], r["to"], (r.get("through") or {}).get("protocol",""), r.get("verb",""))
    if not any(_key(r) == _key(rel) for r in afm["relations"]):
        afm["relations"].append(rel)

def find_components(afm: dict, pred):
    return [c for c in afm.get("components", []) if pred(c)]

def guess_app_component_id(afm: dict) -> str:
    comps = afm.get("components", [])
    for c in comps:
        if c.get("type","").lower() == "mobileapp":
            return c["id"]
    return comps[0]["id"] if comps else "app"

def ensure_package_component(afm: dict, package_path: str, version_map: Dict[str,str]) -> str:
    # Wire with a safe id; show the human path in the label
    comp_id = re.sub(r'[^A-Za-z0-9_-]+', '-', package_path).strip('-')  # e.g., com-roche-rpm-productizedplatform-authentication
    comp_name = package_path                                            # e.g., com/roche/rpm/productizedplatform/authentication
    ver = lookup_version(version_map, package_path)

    add_component(afm, {
        "id": comp_id,
        "name": comp_name,
        "type": "Package",
        "tech": None,
        "metadata": None,
        "evidence": [{"source":"mapping","path":"rules"}]
    })

    # attach version
    for c in afm.get("components", []):
        if c["id"] == comp_id:
            md = c.get("metadata") if isinstance(c.get("metadata"), dict) else {}
            if ver:
                md["version"] = ver
            c["metadata"] = md if md else None
            break

    return comp_id

# ---------- Custom package mapping ----------
def host_key(name: str) -> str:
    return kebab(name)

def enrich_with_packages_mapping(afm: dict, version_map: Dict[str, str]):
    # SQLite DB -> storage package
    sqlite_nodes = find_components(afm, lambda c: c.get("type") == "DB" and "sqlite" in c.get("name","").lower())
    if sqlite_nodes:
        pkg_id = ensure_package_component(afm, "com/roche/rpm/productizedplatform/storage", version_map)
        for node in sqlite_nodes:
            add_relation(afm, {
                "from": node["id"], "to": pkg_id, "verb": "belongs to",
                "through": {"protocol": "classification"},
                "evidence":[{"source":"mapping","path":"rules","note":"SQLite -> storage"}],
                "confidence": 1.0
            })

    # roche-com -> upload package
    # www-roche-com -> authentication package
    service_nodes = find_components(afm, lambda c: c.get("type") == "Service")
    for svc in service_nodes:
        hk = host_key(svc.get("name",""))
        if hk == "roche-com":
            pkg_id = ensure_package_component(afm, "com/roche/rpm/productizedplatform/upload", version_map)
            add_relation(afm, {
                "from": svc["id"], "to": pkg_id, "verb": "belongs to",
                "through": {"protocol": "classification"},
                "evidence":[{"source":"mapping","path":"rules","note":"HTTPS roche-com -> upload"}],
                "confidence": 1.0
            })
        if hk == "www-roche-com":
            pkg_id = ensure_package_component(afm, "com/roche/rpm/productizedplatform/authentication", version_map)
            #print(hk, pkg_id)
            add_relation(afm, {
                "from": svc["id"], "to": pkg_id, "verb": "belongs to",
                "through": {"protocol": "classification"},
                "evidence":[{"source":"mapping","path":"rules","note":"HTTPS www-roche-com -> authentication"}],
                "confidence": 1.0
            })

# ---------- Pipeline ----------
def enrich(afm_path: str, packages_csv: Optional[str], out_path: str, diagram_path: Optional[str] = None):
    afm = read_json(afm_path)
    version_map = build_package_version_index(packages_csv) if packages_csv else {}

    # (Optional) library enrichment from CSV
    if packages_csv and os.path.exists(packages_csv):
        rows = parse_packages_csv(packages_csv)
        app_id = guess_app_component_id(afm)
        comps = afm.get("components", [])
        auth_id   = next((c["id"] for c in comps if c.get("type")=="Auth"), None)
        room_id   = next((c["id"] for c in comps if "room" in c.get("name","").lower()), None)
        sqlite_id = next((c["id"] for c in comps if "sqlite" in c.get("name","").lower()), None)
        enc_id    = next((c["id"] for c in comps if "encryptedsharedpreferences" in c.get("name","").lower()), None)
        service_ids = [c["id"] for c in comps if c.get("type") == "Service"]

        for row in rows:
            lib_map = map_to_library(row["name"])
            if not lib_map:
                continue
            lib_id, canon = lib_map
            lib_ver = row.get("version")
            comp = {"id": lib_id, "name": canon, "type": "Library", "tech": "Android",
                    "metadata": {"version": lib_ver} if lib_ver else None,
                    "evidence": [{"source":"packages","path": os.path.basename(packages_csv),
                                  "note": row["name"] + (f"@{lib_ver}" if lib_ver else "")}]}
            add_component(afm, comp)
            add_relation(afm, {"from": app_id, "to": lib_id, "verb": "uses",
                               "through": {"protocol": "in-process"},
                               "evidence": [{"source":"packages","path": os.path.basename(packages_csv)}],
                               "confidence": 1.0 if lib_ver else 0.8})
            if lib_id == "lib-appauth" and auth_id:
                add_relation(afm, {"from": lib_id, "to": auth_id, "verb": "enables",
                                   "through": {"protocol":"OAuth 2.0"},
                                   "evidence":[{"source":"packages","path": os.path.basename(packages_csv)}],
                                   "confidence": 0.9})
            if lib_id in ("lib-retrofit","lib-okhttp"):
                for svc in service_ids:
                    add_relation(afm, {"from": lib_id, "to": svc, "verb": "client for",
                                       "through": {"protocol":"HTTPS"},
                                       "evidence":[{"source":"packages","path": os.path.basename(packages_csv)}],
                                       "confidence": 0.7})
            if lib_id == "lib-room" and room_id:
                add_relation(afm, {"from": lib_id, "to": room_id, "verb": "ORM for",
                                   "through": {"protocol":"in-process"},
                                   "evidence":[{"source":"packages","path": os.path.basename(packages_csv)}],
                                   "confidence": 0.9})
            if lib_id in ("lib-room","lib-sqlite") and sqlite_id:
                add_relation(afm, {"from": lib_id, "to": sqlite_id, "verb": "DB access",
                                   "through": {"protocol":"in-process"},
                                   "evidence":[{"source":"packages","path": os.path.basename(packages_csv)}],
                                   "confidence": 0.9 if lib_id=="lib-sqlite" else 0.6})
            if lib_id == "lib-sec-crypto" and enc_id:
                add_relation(afm, {"from": lib_id, "to": enc_id, "verb": "secures",
                                   "through": {"protocol":"in-process"},
                                   "evidence":[{"source":"packages","path": os.path.basename(packages_csv)}],
                                   "confidence": 0.9})

    # Package mapping (with versions)
    enrich_with_packages_mapping(afm, version_map)

    write_json(out_path, afm)
    if diagram_path:
        with open(diagram_path, "w", encoding="utf-8") as f:
            f.write(mermaid_from_afm(afm))

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="Enrich AFM with currentPackages.csv, map to Packages (with versions), and rebuild diagram.")
    ap.add_argument("--afm", required=True, help="Input AFM JSON")
    ap.add_argument("--packages", help="CSV with package list (currentPackages.csv)")
    ap.add_argument("--out", required=True, help="Output AFM JSON (enriched)")
    ap.add_argument("--diagram", help="Optional Mermaid .mmd output")
    args = ap.parse_args()
    enrich(args.afm, args.packages, args.out, args.diagram)
    print(f"[enrich] wrote {args.out}" + (f" and {args.diagram}" if args.diagram else ""))

if __name__ == "__main__":
    sys.exit(main())
