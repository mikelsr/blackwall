"""Counts the rules of Anubis's stock configuration by matcher and action,
following its imports. Usage: countrules.py <data dir>, e.g.
bench/anubis/data or Blackwall's copy."""
import sys, yaml, os
root = sys.argv[1]
def load(path):
    with open(path) as f: return yaml.safe_load(f)
def expand(items, kinds):
    for it in items or []:
        if isinstance(it, dict) and "import" in it:
            p = it["import"].replace("(data)", root)
            d = load(p)
            expand(d if isinstance(d, list) else d.get("bots", []), kinds)
        elif isinstance(it, dict):
            k = "+".join(sorted(x for x in ("user_agent_regex","path_regex","headers_regex","remote_addresses","expression","asns","geoip") if x in it)) or "other"
            kinds.append((it.get("name"), k, it.get("action")))
kinds = []
expand(load(os.path.join(root, "meta/default-config.yaml")), kinds)
from collections import Counter
print(root, "rules:", len(kinds))
print(" by matcher:", dict(Counter(k for _, k, _ in kinds)))
print(" by action:", dict(Counter(a for _, _, a in kinds)))
