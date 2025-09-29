#!/usr/bin/env python3
"""
archscan_android.py
Minimal Android architecture fact extractor (AFM) for a central scanner repo.

Signals (deterministic, lightweight):
- Gradle deps: AppAuth, Retrofit/OkHttp, Room, Encrypted SharedPrefs
- AndroidManifest.xml: INTERNET permission, redirect schemes (for OIDC)
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

# ---- Patterns ----
APP_AUTH_DEPS = ("net.openid:appauth",)
RETROFIT_DEPS = ("com.squareup.retrofit2:retrofit",)
OKHTTP_DEPS = ("com.squareup.okhttp3:okhttp",)
ROOM_DEPS = ("androidx.room:room-runtime", "androidx.room:room-ktx")
SEC_CRYPTO = ("androidx.security:security-crypto",)

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

ROOM_CODE_PATTERNS = [
    r"@androidx\.room\.Entity\b",
    r"@androidx\.room\.Dao\b",
    r"@androidx\.room\.Database\b",
    r"\bRoom\.databaseBuilder\b",
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


def detect_gradle_deps(root: str) -> Tuple[Dict[str, List[str]], List[str]]:
    deps = {"appauth": [], "retrofit": [], "okhttp": [], "room": [], "sec_crypto": []}
    evidence = []
    for p in walk_files(root):
        low = p.lower()
        if low.endswith(".gradle") or low.endswith(".gradle.kts"):
            txt = read_text(p) or ""
            hit = False
            for s in APP_AUTH_DEPS:
                if s in txt:
                    deps["appauth"].append(s)
                    hit = True
            for s in RETROFIT_DEPS:
                if s in txt:
                    deps["retrofit"].append(s)
                    hit = True
            for s in OKHTTP_DEPS:
                if s in txt:
                    deps["okhttp"].append(s)
                    hit = True
            for s in ROOM_DEPS:
                if s in txt:
                    deps["room"].append(s)
                    hit = True
            for s in SEC_CRYPTO:
                if s in txt:
                    deps["sec_crypto"].append(s)
                    hit = True
            if hit:
                evidence.append(p)
    # dedupe
    for k in deps:
        deps[k] = sorted(set(deps[k]))
    evidence = sorted(set(evidence))
    return deps, evidence


def parse_manifest(root: str) -> Tuple[Dict, List[str]]:
    info = {"internet": False, "redirect_schemes": []}
    evidence = []
    # attempt common locations first
    candidates = []
    for p in walk_files(root):
        if p.endswith("AndroidManifest.xml"):
            candidates.append(p)
    for path in candidates:
        try:
            xml = ET.parse(path)
            ns = {"android": "http://schemas.android.com/apk/res/android"}
            root_el = xml.getroot()
            # INTERNET permission
            for up in root_el.findall("./uses-permission"):
                name = up.get("{http://schemas.android.com/apk/res/android}name", "")
                if name.endswith("INTERNET"):
                    info["internet"] = True
                    evidence.append(path)
            # Redirect schemes (intent-filter data)
            for act in root_el.findall(".//activity"):
                for intent in act.findall("./intent-filter"):
                    hasView = any(
                        el.get("{http://schemas.android.com/apk/res/android}name", "")
                        == "android.intent.action.VIEW"
                        for el in intent.findall("./action")
                    )
                    if not hasView:
                        continue
                    for data in intent.findall("./data"):
                        scheme = data.get(
                            "{http://schemas.android.com/apk/res/android}scheme"
                        )
                        host = data.get(
                            "{http://schemas.android.com/apk/res/android}host"
                        )
                        if scheme:
                            info["redirect_schemes"].append(
                                {"scheme": scheme, "host": host or ""}
                            )
                            evidence.append(path)
        except Exception:
            continue
    # dedupe schemes
    seen = set()
    uniq = []
    for d in info["redirect_schemes"]:
        key = (d["scheme"], d.get("host", ""))
        if key not in seen:
            seen.add(key)
            uniq.append(d)
    info["redirect_schemes"] = uniq
    return info, sorted(set(evidence))


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


def confidence_score(categories: List[bool]) -> float:
    return (
        round(sum(1 for c in categories if c) / float(len(categories)), 2)
        if categories
        else 0.0
    )


def mermaid_from_afm(afm: Dict) -> str:
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
    return "\n'.join(lines)"  # fixed below


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

    # Signals
    gradle_deps, gradle_ev = detect_gradle_deps(root)
    manifest_info, manifest_ev = parse_manifest(root)

    auth_ev = grep_patterns(root, AUTH_CODE_PATTERNS, {".kt", ".java", ".kts"})
    room_ev = grep_patterns(root, ROOM_CODE_PATTERNS, {".kt", ".java"})
    enc_ev = grep_patterns(root, [ENC_PREFS_PATTERN], {".kt", ".java"})
    upload_ev = grep_patterns(root, UPLOAD_CODE_PATTERNS, {".kt", ".java"})

    api_urls, url_ev = find_base_urls(root)

    components = []
    relations = []

    # Main app node
    components.append(
        {
            "id": app_id,
            "name": app_name,
            "type": "MobileApp",
            "tech": "Android (Kotlin/Java)",
            "metadata": {"manifest": manifest_info, "gradle": gradle_deps},
            "evidence": [{"source": "manifest", "path": p} for p in manifest_ev]
            + [{"source": "gradle", "path": p} for p in gradle_ev],
        }
    )

    # Auth node (if detected)
    auth_detected = bool(
        gradle_deps["appauth"] or auth_ev or manifest_info["redirect_schemes"]
    )
    if auth_detected:
        # Try infer IdP label from any URLs seen (baseUrls or code/strings)
        auth_name = choose_auth_name_from_urls(api_urls)
        auth_id = (
            re.sub(r"[^a-zA-Z0-9_-]+", "-", auth_name).strip("-").lower() or "auth"
        )
        components.append(
            {
                "id": auth_id,
                "name": auth_name,
                "type": "Auth",
                "tech": "OAuth 2.0 (OIDC)",
                "metadata": {
                    "redirect_schemes": manifest_info["redirect_schemes"],
                    "libs": gradle_deps["appauth"],
                },
                "evidence": [{"source": "code", "path": p} for p in auth_ev]
                + [{"source": "manifest", "path": p} for p in manifest_ev],
            }
        )
        relations.append(
            {
                "from": app_id,
                "to": auth_id,
                "verb": "uses",
                "through": {"protocol": "OAuth 2.0"},
                "evidence": [{"source": "code", "path": p} for p in auth_ev]
                + [{"source": "manifest", "path": p} for p in manifest_ev],
                "confidence": confidence_score([True]),
            }
        )

    # API / Upload target (if URL or upload patterns)
    if api_urls or upload_ev or gradle_deps["retrofit"] or gradle_deps["okhttp"]:
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
                    + [{"source": "code", "path": p} for p in upload_ev],
                    "confidence": confidence_score([bool(api_urls), bool(upload_ev)]),
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
                        "evidence": [{"source": "code", "path": p} for p in upload_ev]
                        + [{"source": "gradle", "path": p} for p in gradle_ev],
                    }
                )
            relations.append(
                {
                    "from": app_id,
                    "to": svc_id,
                    "verb": "calls",
                    "through": {"protocol": "HTTPS"},
                    "evidence": [{"source": "code", "path": p} for p in upload_ev]
                    + [{"source": "gradle", "path": p} for p in gradle_ev],
                    "confidence": confidence_score(
                        [
                            bool(upload_ev),
                            bool(gradle_deps["retrofit"] or gradle_deps["okhttp"]),
                        ]
                    ),
                }
            )

    # Persistence nodes
    if room_ev or gradle_deps["room"]:
        comp_id = "room-sqlite"
        components.append(
            {
                "id": comp_id,
                "name": "Room (SQLite)",
                "type": "DB",
                "tech": "SQLite via Room",
                "evidence": [{"source": "code", "path": p} for p in room_ev]
                + [{"source": "gradle", "path": p} for p in gradle_ev],
            }
        )
        relations.append(
            {
                "from": app_id,
                "to": comp_id,
                "verb": "reads/writes",
                "through": {"protocol": "in-process"},
                "evidence": [{"source": "code", "path": p} for p in room_ev],
                "confidence": confidence_score([True]),
            }
        )
    if enc_ev or gradle_deps["sec_crypto"]:
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
                "confidence": confidence_score([True]),
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

