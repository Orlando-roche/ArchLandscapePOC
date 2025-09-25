#!/usr/bin/env python3
import argparse, json, os, re, sys, yaml
from urllib.parse import urlparse
from typing import Optional, Dict, List, Tuple
TEXT_EXTS = {".md",".txt",".yaml",".yml",".json",".py",".js",".ts",".tsx",".jsx",".env",".ini",".toml",".html",".css"}
OAUTH_JS_PATTERNS = [
    r"\bmsalInstance\.loginRedirect\(",
    r"\bmsalInstance\.loginPopup\(",
    r"\bloginWithRedirect\(",
    r"\bcreateAuth0Client\(",
    r"\bauth0\.loginWithRedirect\(",
    r"\bUserManager\(",
    r"\bgoogle\.accounts\.oauth2\.initTokenClient\(",
    r"\bgoogle\.accounts\.oauth2\.revoke\(",
    r"\brequestAccessToken\(",
]
OAUTH_CONF_KEYS = ["issuer","authority","oauth","oidc","okta","auth0","cognito","keycloak","azuread","azure_ad","google","client_id"]
KNOWN_IDP_HOST_MAP = [
    ("auth0.com","Auth0"),
    ("okta.com","Okta"),
    ("login.microsoftonline.com","Azure AD"),
    ("cognito-idp","Amazon Cognito"),
    ("keycloak","Keycloak"),
    ("accounts.google.com","Google Identity"),
    ("openidconnect.googleapis.com","Google Identity"),
    ("googleapis.com","Google Identity")
]
def walk_files(root: str):
    for dirpath, _dirnames, filenames in os.walk(root):
        parts = set(dirpath.lower().split(os.sep))
        if any(p in parts for p in {".git","node_modules",".venv","venv","__pycache__","dist","build"}): continue
        for fn in filenames: yield os.path.join(dirpath, fn)
def read_text(path: str):
    try:
        with open(path,"r",encoding="utf-8",errors="ignore") as f: return f.read()
    except Exception: return None
def scan_openapi(root: str):
    hits, evidence = [], []
    for path in walk_files(root):
        low = path.lower()
        if not (low.endswith(".yaml") or low.endswith(".yml") or low.endswith(".json")): continue
        if "openapi" in low or "swagger" in low:
            raw = read_text(path); 
            if raw is None: continue
            try: data = yaml.safe_load(raw)
            except Exception:
                try: data = json.loads(raw)
                except Exception: continue
            if not isinstance(data, dict): continue
            comps = data.get("components",{}); sec = comps.get("securitySchemes",{})
            for name, scheme in (sec or {}).items():
                if isinstance(scheme, dict) and scheme.get("type") == "oauth2":
                    flows = scheme.get("flows",{}) or {}
                    flow_names = [k for k,v in flows.items() if isinstance(v,dict)]
                    hits.append({"scheme_name":name,"flows":flow_names}); evidence.append(path)
    return hits, sorted(set(evidence))
def extract_html_title_and_h1(root: str):
    title, h1 = None, None
    for path in walk_files(root):
        if path.lower().endswith(".html"):
            txt = read_text(path) or ""
            m = re.search(r"<title>\s*([^<]+)\s*</title>", txt, flags=re.I)
            if m: title = m.group(1).strip()
            m2 = re.search(r"<h1[^>]*>\s*([^<]+)\s*</h1>", txt, flags=re.I)
            if m2: h1 = m2.group(1).strip()
            if title or h1: break
    return title, h1
def scan_dependencies(root: str):
    py_hits, js_hits, evidence = [], [], []
    for path in walk_files(root):
        if path.lower().endswith("package.json"):
            try: data = json.loads(read_text(path) or "{}")
            except Exception: data = {}
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            dl = {k.lower(): v for k,v in deps.items()}
            for lib in ["@azure/msal-browser","@auth0/auth0-spa-js","oidc-client","next-auth","openid-client"]:
                if lib.lower() in dl: js_hits.append(lib); evidence.append(path)
    return py_hits, sorted(set(js_hits)), sorted(set(evidence))
def scan_configs_and_urls(root: str):
    urls, evidence = [], []
    for path in walk_files(root):
        ext = os.path.splitext(path)[1].lower()
        if ext not in TEXT_EXTS: continue
        content = read_text(path) or ""; lowered = content.lower()
        if any(k in lowered for k in OAUTH_CONF_KEYS) or ext in {".html",".js"}:
            found = re.findall(r"https?://[^\s\"'>)]+", content)
            for u in found:
                if any(tok in u.lower() for tok in ["auth","oauth","oidc","okta","cognito","keycloak","microsoftonline","googleapis.com","accounts.google.com"]):
                    urls.append(u); evidence.append(path)
            if "apps.googleusercontent.com" in lowered:
                urls.append("https://accounts.google.com"); evidence.append(path)
    return sorted(set(urls)), sorted(set(evidence))
def scan_code_patterns(root: str):
    ev = []; pat = re.compile("|".join(OAUTH_JS_PATTERNS))
    for path in walk_files(root):
        ext = os.path.splitext(path)[1].lower()
        if ext not in TEXT_EXTS: continue
        if ext in {".js",".ts",".tsx",".jsx",".html"}:
            txt = read_text(path) or ""
            if pat.search(txt): ev.append(path)
    return (len(ev) > 0), sorted(set(ev))
def pick_component_name(root: str, hints: dict) -> str:
    if hints.get("component",{}).get("name"): return hints["component"]["name"]
    title, h1 = extract_html_title_and_h1(root)
    if title: return title
    if h1: return h1
    return os.path.basename(os.path.abspath(root))
def choose_auth_name(issuer_urls: List[str]) -> str:
    hosts = []
    for u in issuer_urls:
        try: hosts.append(urlparse(u).hostname or "")
        except Exception: pass
    for h in hosts:
        for key, label in KNOWN_IDP_HOST_MAP:
            if key in (h or ""): return label
    return "Authentication/Authorisation"
def load_hints(hints_path: Optional[str], repo: str) -> dict:
    path = hints_path or (os.path.join(repo,"landscape.yaml"))
    if os.path.exists(path):
        try:
            import yaml as _yaml
            return _yaml.safe_load(read_text(path) or "") or {}
        except Exception: return {}
    return {}
def confidence_from_signals(openapi_hits, dep_hits, config_hits, code_hits) -> float:
    return round(sum(1 for c in [bool(openapi_hits), bool(dep_hits), bool(config_hits), bool(code_hits)]) / 4.0, 2)
def to_mermaid(afm: dict) -> str:
    lines = ["graph LR"]
    for c in afm.get("components", []):
        nid = c["id"].replace(" ","_"); 
        # NEW (quotes make special chars safe in Mermaid)
        label = f'{c.get("name","?")} ({c.get("type","?")})'
        safe_label = label.replace('"', '\\"')
        lines.append(f'  {nid}["{safe_label}"]')
        #lines.append(f'  {nid}[{c["name"]} -{c["type"]}-]')
    for r in afm.get("relations", []):
        f = r["from"].replace(" ","_"); t = r["to"].replace(" ","_")
        through = r.get("through",{}); lab = through.get("protocol") or r.get("verb","uses")
        flows = through.get("flows") or []; 
        if flows: lab = f'{lab} / {", ".join(flows)}'
        lines.append(f'  {f} -->|{lab}| {t}')
    return "\n".join(lines)
def main():
    ap = argparse.ArgumentParser(description="AFM scanner (HTML + GIS aware)")
    ap.add_argument("--repo", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--diagram"); ap.add_argument("--hints")
    args = ap.parse_args()
    repo = os.path.abspath(args.repo); hints = load_hints(args.hints, repo)
    component_name = pick_component_name(repo, hints)
    component_id = re.sub(r"[^a-zA-Z0-9_-]+","-", component_name).strip("-").lower() or "main-app"
    openapi_hits, openapi_ev = scan_openapi(repo)
    py_hits, js_hits, dep_ev = scan_dependencies(repo)
    issuer_urls, cfg_ev = scan_configs_and_urls(repo)
    code_hit, code_ev = scan_code_patterns(repo)
    oauth_detected = any([openapi_hits, js_hits, issuer_urls, code_hit])
    components = [{
        "id": component_id, "name": component_name, "type": hints.get("component",{}).get("type","Application"),
        "tech": hints.get("component",{}).get("tech",""), "owners": hints.get("component",{}).get("owners",[]),
        "evidence": []
    }]
    relations = []
    if oauth_detected:
        auth_name = choose_auth_name(issuer_urls)
        auth_id = re.sub(r"[^a-zA-Z0-9_-]+","-", auth_name).strip("-").lower() or "auth"
        components.append({
            "id": auth_id, "name": auth_name, "type": "Auth", "tech": "OAuth 2.0 (OIDC)",
            "metadata": {"issuer_urls": issuer_urls, "libraries": {"python": [], "javascript": js_hits}, "openapi_oauth_schemes": openapi_hits},
            "evidence": [{"source":"config","path":p} for p in cfg_ev] + [{"source":"openapi","path":p} for p in openapi_ev] + [{"source":"code","path":p} for p in code_ev] + [{"source":"dependencies","path":p} for p in dep_ev]
        })
        flows = sorted({f for hit in openapi_hits for f in hit.get("flows", [])}) or []
        relations.append({
            "from": component_id, "to": auth_id, "verb": "uses",
            "through": {"protocol":"OAuth 2.0", "flows": flows},
            "evidence": [{"source":"openapi","path":p} for p in openapi_ev] + [{"source":"code","path":p} for p in code_ev],
            "confidence": round(sum(1 for c in [bool(openapi_hits), bool(js_hits), bool(issuer_urls), bool(code_hit)]) / 4.0, 2)
        })
    afm = {"components": components, "relations": relations}
    with open(args.out,"w",encoding="utf-8") as f: json.dump(afm, f, indent=2)
    if args.diagram:
        mmd = to_mermaid(afm); os.makedirs(os.path.dirname(os.path.abspath(args.diagram)), exist_ok=True)
        with open(args.diagram,"w",encoding="utf-8") as f: f.write(mmd)
    print(f"[archscan] {component_name}  oauth_detected={oauth_detected}  components={len(components)} relations={len(relations)}")
if __name__ == "__main__":
    sys.exit(main())
