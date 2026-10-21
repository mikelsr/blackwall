# Walks Anubis's stock config imports in order and prints every regex a
# request is checked against, as JSON: [{rule, kind, header, pattern}].
import json, sys, yaml, os
DATA = sys.argv[1]
out = []
def load(path):
    with open(path) as f:
        doc = yaml.safe_load(f)
    return doc if isinstance(doc, list) else doc.get("bots", doc)
def walk(rules):
    for r in rules:
        if "import" in r:
            walk(load(os.path.join(DATA, r["import"].replace("(data)/", ""))))
            continue
        if "user_agent_regex" in r:
            out.append({"rule": r["name"], "kind": "ua", "header": "User-Agent", "pattern": r["user_agent_regex"].strip()})
        if "path_regex" in r:
            out.append({"rule": r["name"], "kind": "path", "header": "", "pattern": r["path_regex"].strip()})
        for h, p in (r.get("headers_regex") or {}).items():
            out.append({"rule": r["name"], "kind": "header", "header": h, "pattern": p.strip()})
        if "expression" in r:
            out.append({"rule": r["name"], "kind": "cel", "header": "", "pattern": json.dumps(r["expression"])})
walk(load(os.path.join(DATA, "meta/default-config.yaml")))
json.dump(out, sys.stdout, indent=1)
