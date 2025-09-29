#!/usr/bin/env python3
import argparse, json, os, sys
from urllib.parse import urlparse
from jsonschema import Draft202012Validator
def load_json(p): 
    with open(p,"r",encoding="utf-8") as f: 
        return json.load(f)
def read_lines(p):
    if not os.path.exists(p): return set()
    with open(p,"r",encoding="utf-8") as f:
        return set([ln.strip().lower() for ln in f if ln.strip() and not ln.strip().startswith("#")])
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--afm", required=True)
    ap.add_argument("--schema", required=True)
    ap.add_argument("--allowlist", default="config/allowedIdProviders.txt")
    args = ap.parse_args()
    afm = load_json(args.afm)
    schema = load_json(args.schema)
    errs = sorted(Draft202012Validator(schema).iter_errors(afm), key=lambda e: e.path)
    if errs:
        for e in errs:
            print(f"[schema] {e.message} at {'/'.join([str(x) for x in e.path])}")
        sys.exit(2)
    id2type = {c["id"]: c.get("type") for c in afm.get("components",[])}
    for rel in afm.get("relations",[]):
        prot = (rel.get("through") or {}).get("protocol","").lower()
        if prot == "oauth 2.0":
            tgt = rel.get("to")
            if id2type.get(tgt) != "Auth":
                print(f"[rule] OAuth relation targets non-Auth component id={tgt} type={id2type.get(tgt)}")
                sys.exit(3)
    allow = read_lines(args.allowlist)
    if allow:
        for c in afm.get("components",[]):
            if c.get("type") == "Auth":
                urls = (c.get("metadata") or {}).get("issuer_urls",[]) or []
                for u in urls:
                    host = (urlparse(u).hostname or "").lower()
                    if host and not any(host == a or host.endswith("." + a) for a in allow):
                        print(f"[rule] Issuer host {host!r} not allowed (see {args.allowlist})")
                        sys.exit(4)
    print("[validate_afm] OK"); return 0
if __name__ == "__main__":
    sys.exit(main())
