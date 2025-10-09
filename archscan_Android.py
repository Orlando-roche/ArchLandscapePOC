#!/usr/bin/env python3
"""
archscan_android.py
Minimal Android architecture fact extractor (AFM) for a central scanner repo.

Signals (deterministic, lightweight):
- full system scan
- Kotlin/Java patterns:
    * Auth (AppAuth classes/imports)
    * Upload (Retrofit.baseUrl(...), @Multipart, MultipartBody.Builder)
    * Persistence (Room annotations / databaseBuilder, EncryptedSharedPreferences)

Outputs:
- AFM JSON with components, relations, evidence, and confidence
- Mermaid diagram (.mmd) with quoted labels (safe for parentheses)

Example:
  python archscan_android.py --repo ~/code/my-android --out outputs/afm.json --diagram outputs/diagram.mmd
"""

import argparse, json, os, re, sys, xml.etree.ElementTree as ET
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional

TEXT_EXTS = {
    ".kt",
    ".kts",
    ".java",
    ".xml",
    ".gradle",
    ".gradle.kts",
    ".properties",
    ".md",
    ".txt",
}
SKIP_DIRS = {".git", ".gradle", ".idea", "build", "out"}

# Kotlin/Java code indicators
AUTH_CODE_PATTERNS = [
    r"\bAuthorizationServiceConfiguration\b",
    r"\bAuthorizationRequest\.Builder\b",
    r"\bAuthorizationService\b",
    r"\bTokenRequest\b",
    r"\bimport\s+net\.openid\.appauth\b",
]

UPLOAD_CODE_PATTERNS = [
    r"\.baseUrl\(\s*\"(https?://[^\"]+)\"\s*\)",  # Capture literal baseUrl
    r"@Multipart\b",
    r"\bMultipartBody\.Builder\b",
]

# SQLite usage
SQLITE_CODE_PATTERNS = [
     r"\bandroid\.database\.sqlite\.SQLiteDatabase\b",
     r"\bSQLiteOpenHelper\b",
     r"\bgetWritableDatabase\(",
     r"\bgetReadableDatabase\(",
     r"\bopenDatabase\(",
     r"\bexecSQL\(",
     r"\brawQuery\(",
 ]

ENC_PREFS_PATTERN = (
    r"\bandroidx\.security\.crypto\.EncryptedSharedPreferences\.create\b"
)

KNOWN_IDP_HOSTS = [
    ("accounts.google.com", "Google Identity"),
    ("login.microsoftonline.com", "Azure AD"),
    ("okta.com", "Okta"),
    ("auth0.com", "Auth0"),
    ("cognito-idp", "Amazon Cognito"),
    ("keycloak", "Keycloak"),
]

def walk_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        # prune
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def read_text(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return None

def grep_patterns(
    root: str, patterns: List[str], exts: Optional[set] = None
) -> List[str]:
    hits = []
    exts = exts or {".kt", ".java", ".xml", ".kts"}
    regex = re.compile("|".join(patterns))
    for p in walk_files(root):
        if os.path.splitext(p)[1].lower() not in exts:
            continue
        txt = read_text(p) or ""
        if regex.search(txt):
            hits.append(p)
    return sorted(set(hits))

def find_base_urls(root: str) -> Tuple[List[str], List[str]]:
    """Return (urls, evidence paths). Finds literal Retrofit .baseUrl("https://...") and fallback http(s) URLs."""
    urls, evidence = [], []
    baseurl_re = re.compile(r'\.baseUrl\(\s*"(?P<url>https?://[^"\s]+)"\s*\)')
    http_re = re.compile(r'https?://[^\s"\'<>]+')
    for p in walk_files(root):
        ext = os.path.splitext(p)[1].lower()
        if ext not in {".kt", ".java", ".xml", ".properties"}:
            continue
        txt = read_text(p) or ""
        for m in baseurl_re.finditer(txt):
            urls.append(m.group("url"))
            evidence.append(p)
        # fallback: pick obvious API base URLs from strings.xml or config
        if ("strings.xml" in p) or ("buildConfig" in txt) or ("BASE_URL" in txt):
            for u in http_re.findall(txt):
                urls.append(u)
                evidence.append(p)
    # normalize
    norm = []
    for u in urls:
        try:
            parsed = urlparse(u)
            if parsed.scheme in ("http", "https") and parsed.netloc:
                norm.append(f"{parsed.scheme}://{parsed.netloc}")
        except Exception:
            continue
    norm = sorted(set(norm))
    return norm, sorted(set(evidence))

def pick_app_name_and_id(root: str) -> Tuple[str, str]:
    """Try to derive a display name and stable id from Gradle or fallback to folder name."""
    app_id = None
    # read applicationId "com.example.app" from app/build.gradle*
    app_gradles = []
    for p in walk_files(root):
        low = p.lower()
        if "app/" in low and (low.endswith(".gradle") or low.endswith(".gradle.kts")):
            app_gradles.append(p)
    for g in app_gradles:
        txt = read_text(g) or ""
        m = re.search(r'applicationId\s+["\']([^"\']+)["\']', txt)
        if m:
            app_id = m.group(1)
            break
    name = app_id or os.path.basename(os.path.abspath(root))
    # id: kebab-case
    nid = re.sub(r"[^a-zA-Z0-9_-]+", "-", name).strip("-").lower()
    return name, (nid or "android-app")


def choose_auth_name_from_urls(urls: List[str]) -> str:
    hosts = []
    for u in urls:
        try:
            hosts.append(urlparse(u).hostname or "")
        except Exception:
            pass
    for h in hosts:
        for key, label in KNOWN_IDP_HOSTS:
            if key in (h or ""):
                return label
    return "Authentication/Authorisation"

# Move out to Utils 
def mermaid_from_afm(afm: Dict) -> str:  # re-declare to correct accidental quote
    def q(s: str) -> str:
        return (s or "").replace('"', '\\"')

    lines = ["graph LR"]
    for c in afm.get("components", []):
        nid = c["id"].replace(" ", "_")
        label = f'{c.get("name","?")} ({c.get("type","?")})'
        lines.append(f'  {nid}["{q(label)}"]')
    for r in afm.get("relations", []):
        f = r["from"].replace(" ", "_")
        t = r["to"].replace(" ", "_")
        lab = (r.get("through") or {}).get("protocol") or r.get("verb", "uses")
        flows = (r.get("through") or {}).get("flows") or []
        if flows:
            lab = f'{lab} / {", ".join(flows)}'
        lines.append(f"  {f} -->|{q(lab)}| {t}")
    return "\n".join(lines)

# ---- Add these helpers to archscan_android.py ----
from typing import Set
import pathlib

# Known libraries we care about -> how to recognize them
KNOWN_COORD_PREFIXES = {
    # lib        -> list of prefixes that identify it
    "retrofit":   ["com.squareup.retrofit2:retrofit"],
    "okhttp":     ["com.squareup.okhttp3:okhttp"],
    "room":       ["androidx.room:room-runtime", "androidx.room:room-ktx"],
    "appauth":    ["net.openid:appauth"],
    "sec_crypto": ["androidx.security:security-crypto"],
}

# Import patterns that imply a lib (works even if build files hide the GAV)
IMPORT_TO_LIB = {
    r"\bimport\s+retrofit2\.": "retrofit",
    r"\bimport\s+okhttp3\.": "okhttp",
    r"\bimport\s+androidx\.room\.": "room",
    r"\bimport\s+net\.openid\.appauth\.": "appauth",
    r"\bandroidx\.security\.crypto\.": "sec_crypto",
}

def _all_files(root: str, exts: Set[str]) -> List[str]:
    out = []
    for p in walk_files(root):
        if os.path.splitext(p)[1].lower() in exts:
            out.append(p)
    return out

def _read(p: str) -> str:
    return read_text(p) or ""

def _classify_gav(gav: str) -> Optional[str]:
    """Map a GAV (group:artifact[:version]) to one of our known libs."""
    if not gav: return None
    base = ":".join(gav.split(":")[:2]).lower()
    for lib, prefixes in KNOWN_COORD_PREFIXES.items():
        for pref in prefixes:
            if base.startswith(pref):
                return lib
    return None

def _dedupe(seq):
    seen = set(); out = []
    for x in seq:
        if x not in seen:
            seen.add(x); out.append(x)
    return out

# 1) Parse version catalogs: gradle/libs.versions.toml
def _parse_version_catalogs(root: str) -> Tuple[Dict[str,str], List[str]]:
    """
    Returns: (alias -> 'group:artifact:version', evidence_paths)
      e.g., 'libs.retrofit' -> 'com.squareup.retrofit2:retrofit:2.9.0'
    """
    alias_to_gav, ev = {}, []
    # Support multiple catalogs (Gradle allows catalogs/*.toml)
    tomls = []
    for p in walk_files(root):
        low = p.lower()
        if low.endswith(".toml") and ("/gradle/libs.versions.toml" in low or "/gradle/" in low and "versions" in os.path.basename(p).lower()):
            tomls.append(p)
    # Python 3.11 has tomllib
    try:
        import tomllib as toml
    except Exception:
        try:
            import tomli as toml
        except Exception:
            toml = None
    for t in tomls:
        try:
            data = toml.loads(_read(t)) if toml else {}
        except Exception:
            data = {}
        libs = (data.get("libraries") or {})
        versions = (data.get("versions") or {})
        for alias, spec in libs.items():
            # forms:
            # alias = { group = "...", name = "...", version = "1.2.3" }
            # alias = { module = "group:name", version.ref = "x" }
            if not isinstance(spec, dict): continue
            group = spec.get("group"); name = spec.get("name")
            module = spec.get("module")
            ver = spec.get("version")
            if not ver and "version.ref" in spec:
                ref = spec["version.ref"]; ver = versions.get(ref)
            if module and ":" in module:
                g, n = module.split(":", 1)
                group, name = g, n
            if group and name:
                gav = f"{group}:{name}" + (f":{ver}" if ver else "")
                alias_to_gav[f"libs.{alias}"] = gav
                ev.append(t)
    return alias_to_gav, sorted(set(ev))

# 2) Parse buildSrc/Dependencies.kt (and similar) for constants/objects
def _parse_buildsrc_constants(root: str) -> Tuple[Dict[str,str], List[str]]:
    """
    Returns: (symbol -> 'group:artifact:version', evidence_paths)
      e.g., 'Deps.Retrofit.core' => 'com.squareup.retrofit2:retrofit:2.9.0'
    Handles simple const vals and nested objects.
    """
    symbol_to_gav, ev = {}, []
    kt_files = [p for p in _all_files(root, {".kt", ".kts"}) if "/buildsrc" in p.lower() or "/build-src" in p.lower() or "/build_logic" in p.lower()]
    # Simple const pattern: const val X = "group:artifact:version"
    const_re = re.compile(r'const\s+val\s+([A-Za-z0-9_\.]+)\s*=\s*["\']([A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+(?::[A-Za-z0-9+_.\-]+)?)["\']')
    # Object path capture: object Deps { object Retrofit { const val core = "g:a:v" } }
    path_stack_re = re.compile(r'^\s*object\s+([A-Za-z0-9_]+)\s*\{?')
    end_brace_re  = re.compile(r'^\s*}\s*$')
    for fp in kt_files:
        txt = _read(fp)
        if not txt: continue
        ev.append(fp)
        # flat consts
        for m in const_re.finditer(txt):
            key = m.group(1); gav = m.group(2)
            symbol_to_gav[key] = gav
            # Also provide a namespaced alias like Deps.key if file declares object Deps { const val key = ... }
        # naive nested path reconstruction
        stack = []
        for line in txt.splitlines():
            if path_stack_re.search(line):
                stack.append(path_stack_re.search(line).group(1))
                continue
            if end_brace_re.search(line):
                if stack: stack.pop()
                continue
            m = re.search(r'const\s+val\s+([A-Za-z0-9_]+)\s*=\s*["\']([^"\']+)["\']', line)
            if m and stack:
                sym = ".".join(stack + [m.group(1)])
                gav = m.group(2)
                # Normalize e.g. Deps.Retrofit.core
                symbol_to_gav[sym] = gav
    return symbol_to_gav, sorted(set(ev))

# 3) Sweep all build.gradle(.kts) for direct coords AND alias calls
def _parse_build_gradle_everywhere(root: str) -> Tuple[Set[str], Set[str], Set[str], List[str]]:
    """
    Returns:
      direct_gavs: {'group:artifact:version', ...}
      lib_aliases: {'libs.retrofit', 'libs.okhttp.logging', ...}
      symbols:     {'Deps.Retrofit.core', 'Dependencies.Retrofit', ...}
      evidence:    [file paths]
    """
    direct_gavs, lib_aliases, symbols, ev = set(), set(), set(), []
    gradles = [p for p in _all_files(root, {".gradle", ".kts"}) if os.path.basename(p) in ("build.gradle","build.gradle.kts") or p.endswith(".gradle") or p.endswith(".gradle.kts")]
    if not gradles:
        gradles = [p for p in _all_files(root, {".gradle", ".kts"})]  # fallback
    # patterns
    # implementation "g:a:v" OR 'g:a:v'
    gav_call = re.compile(r'\b(?:implementation|api|compileOnly|runtimeOnly|kapt|ksp|testImplementation|androidTestImplementation)\s*\(?\s*["\']([A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+(?::[A-Za-z0-9+_.\-]+)?)["\']')
    # implementation(libs.xyz) OR implementation ( libs.xyz )
    libs_call = re.compile(r'\b(?:implementation|api|compileOnly|runtimeOnly|kapt|ksp|testImplementation|androidTestImplementation)\s*\(?\s*(libs\.[A-Za-z0-9_.-]+)\s*\)?')
    # implementation(Deps.Retrofit.core) / implementation(Dependencies.Retrofit.core)
    symbol_call = re.compile(r'\b(?:implementation|api|compileOnly|runtimeOnly|kapt|ksp|testImplementation|androidTestImplementation)\s*\(?\s*([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)\s*\)?')
    for fp in gradles:
        txt = _read(fp)
        if not txt: continue
        ev.append(fp)
        for m in gav_call.finditer(txt):
            direct_gavs.add(m.group(1))
        for m in libs_call.finditer(txt):
            lib_aliases.add(m.group(1))
        for m in symbol_call.finditer(txt):
            # Avoid mistaking method calls; keep likely constants/objects with dots
            sym = m.group(1)
            # Ignore when it's obvious code like retrofit2.Retrofit(...) etc.
            if ":" in sym: continue
            if sym.startswith("libs."):  # covered by libs_call
                lib_aliases.add(sym); continue
            symbols.add(sym)
    return direct_gavs, lib_aliases, symbols, sorted(set(ev))

# 4) Imports in source: infer library usage even if GAV is hidden
def _imports_imply_libs(root: str) -> Tuple[Set[str], List[str]]:
    implied, ev = set(), []
    kt_java = _all_files(root, {".kt",".java"})
    if not kt_java: return implied, ev
    regexes = [(re.compile(p), lib) for p, lib in IMPORT_TO_LIB.items()]
    for fp in kt_java:
        txt = _read(fp)
        if not txt: continue
        for rx, lib in regexes:
            if rx.search(txt):
                implied.add(lib); ev.append(fp); break
    return implied, sorted(set(ev))

def detect_dependencies_agnostic(root: str) -> Tuple[Dict[str, List[str]], List[str]]:
    """
    Aggregates dependencies from:
      - direct coords in any build.gradle(.kts)
      - version catalogs (libs.versions.toml) for libs.alias indirection
      - buildSrc constants/objects (Dependencies.kt, Deps.*, etc.)
      - import usage in Kotlin/Java
    Returns: (deps dict, evidence paths)
    """
    deps: Dict[str, List[str]] = {"appauth": [], "retrofit": [], "okhttp": [], "room": [], "sec_crypto": []}
    evidence: List[str] = []

    # Collect everywhere
    alias_map, ev1 = _parse_version_catalogs(root)
    sym_map,   ev2 = _parse_buildsrc_constants(root)
    direct_gavs, lib_aliases, symbols, ev3 = _parse_build_gradle_everywhere(root)
    implied_libs, ev4 = _imports_imply_libs(root)

    evidence.extend(ev1 + ev2 + ev3 + ev4)

    # Resolve aliases -> GAV
    resolved_from_alias = [alias_map[a] for a in lib_aliases if a in alias_map]
    # Resolve symbols -> GAV
    resolved_from_sym   = [sym_map[s]   for s in symbols     if s in sym_map]

    all_gavs = set(direct_gavs) | set(resolved_from_alias) | set(resolved_from_sym)

    # Classify GAVs into buckets
    for gav in all_gavs:
        lib = _classify_gav(gav)
        if lib:
            deps[lib].append(gav)

    # Add implied libs (imports) as weak evidence even if GAV couldn’t be resolved
    for lib in implied_libs:
        if not deps[lib]:
            deps[lib] = []  # keep list type
    # De-dupe and sort
    for k in deps:
        deps[k] = sorted(set(deps[k]))

    return deps, sorted(set(evidence))


def main():
    ap = argparse.ArgumentParser(
        description="Android AFM scanner (central repo friendly)"
    )
    ap.add_argument("--repo", required=True, help="Path to local Android project")
    ap.add_argument("--out", required=True, help="Path to write AFM JSON")
    ap.add_argument("--diagram", help="Optional path to write Mermaid .mmd")
    args = ap.parse_args()

    root = os.path.abspath(args.repo)

    # Basic identity
    app_name, app_id = pick_app_name_and_id(root)

    gradle_deps, gradle_ev = detect_dependencies_agnostic(root)
    #print(gradle_deps)
    #print()
    #print(gradle_ev)

    # Revisit auth !! 
    auth_ev = grep_patterns(root, AUTH_CODE_PATTERNS, {".kt", ".java", ".kts"})    
    enc_ev = grep_patterns(root, [ENC_PREFS_PATTERN], {".kt", ".java"})
    upload_ev = grep_patterns(root, UPLOAD_CODE_PATTERNS, {".kt", ".java"})

    # confirmed 
    api_urls, url_ev = find_base_urls(root)
    sqlite_ev  = grep_patterns(root, SQLITE_CODE_PATTERNS, {".kt",".java"})

    components, relations = [], []

    # Main app node
    components.append(
        {
            "id": app_id,
            "name": app_name,
            "type": "MobileApp",
            "tech": "Android (Kotlin/Java)",
            "metadata": {
            "gradle": gradle_deps
            }
        }
    )
    
    # API / Upload target (if URL or upload patterns)
    if api_urls or upload_ev:        
        # one component per host
        for u in api_urls or []:
            host = urlparse(u).netloc
            svc_id = (
                re.sub(r"[^a-zA-Z0-9_-]+", "-", host).strip("-").lower() or "backend"
            )
            svc_name = host or "Backend API"
            if not any(c["id"] == svc_id for c in components):
                components.append(
                    {
                        "id": svc_id,
                        "name": svc_name,
                        "type": "Service",
                        "tech": "HTTPS API",
                        "evidence": [{"source": "code", "path": p} for p in url_ev],
                    }
                )
            relations.append(
                {
                    "from": app_id,
                    "to": svc_id,
                    "verb": "calls",
                    "through": {"protocol": "HTTPS"},
                    "evidence": [{"source": "code", "path": p} for p in url_ev]
                    + [{"source": "code", "path": p} for p in upload_ev]
                }
            )
        # If no literal URLs but upload libs/signals exist, add a generic API node once
        if not api_urls:
            svc_id = "backend-api"
            if not any(c["id"] == svc_id for c in components):
                components.append(
                    {
                        "id": svc_id,
                        "name": "Backend API",
                        "type": "Service",
                        "tech": "HTTPS API",
                        "evidence": [{"source": "code", "path": p} for p in upload_ev],
                    }
                )
            relations.append(
                {
                    "from": app_id,
                    "to": svc_id,
                    "verb": "calls",
                    "through": {"protocol": "HTTPS"},
                    "evidence": [{"source": "code", "path": p} for p in upload_ev],
                }
            )

     # NEW: Persistence — direct SQLite (no Room)
    if sqlite_ev:
        comp_id = "sqlite-db"
        components.append({
            "id": comp_id,
            "name": "SQLite (SQLiteDatabase)",
            "type": "DB",
            "tech": "Android SQLiteDatabase",
            "evidence": [{"source":"code","path":p} for p in sqlite_ev]
        })
        relations.append({
            "from": app_id,
            "to": comp_id,
            "verb": "reads/writes",
            "through": {"protocol":"in-process"},
            "evidence": [{"source":"code","path":p} for p in sqlite_ev],
        })

    # Encrypted preferences
    if enc_ev:
        comp_id = "encrypted-shared-prefs"
        components.append(
            {
                "id": comp_id,
                "name": "EncryptedSharedPreferences",
                "type": "Storage",
                "tech": "AES-GCM (AndroidX Security Crypto)",
                "evidence": [{"source": "code", "path": p} for p in enc_ev]
                + [{"source": "gradle", "path": p} for p in gradle_ev],
            }
        )
        relations.append(
            {
                "from": app_id,
                "to": comp_id,
                "verb": "stores",
                "through": {"protocol": "in-process"},
                "evidence": [{"source": "code", "path": p} for p in enc_ev],
            }
        )

    afm = {"components": components, "relations": relations}

    # Write outputs
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(afm, f, indent=2)

    if args.diagram:
        os.makedirs(
            os.path.dirname(os.path.abspath(args.diagram)) or ".", exist_ok=True
        )
        with open(args.diagram, "w", encoding="utf-8") as f:
            f.write(mermaid_from_afm(afm))

    # tiny summary
    print(
        f"[archscan-android] {app_name!r} components={len(components)} relations={len(relations)}"
    )
    if any(r.get("through", {}).get("protocol") == "OAuth 2.0" for r in relations):
        print("[archscan-android] Auth: OAuth 2.0 detected")
    if any(c["type"] in ("DB", "Storage") for c in components):
        print("[archscan-android] Persistence detected")
    if any((r.get("through", {}).get("protocol") == "HTTPS") for r in relations):
        print("[archscan-android] API/Upload calls detected")


if __name__ == "__main__":
    sys.exit(main())

