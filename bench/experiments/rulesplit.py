# Splits the "policy rules" part of a Blackwall perf profile (perf script
# -F period,ip,sym on stdin) by the leaf-most frame that is regex, CEL
# evaluation, building the CEL context, or anything else.
import re, sys
RULES = re.compile(r"shared::policy|cel::|regex|ipnet")
tot = 0; parts = {}
def flush(w, stack):
    global tot
    if w is None: return
    tot += w
    if not any(RULES.search(s) for s in stack): return
    kind = "other"
    for s in stack:  # leaf first
        if "regex" in s: kind = "regex"; break
        if "cel_context" in s or "canonical_header_name" in s: kind = "cel context"; break
        if "cel::" in s: kind = "cel eval"; break
        if "malloc" in s or "free" in s: kind = "malloc/free"; break
    parts[kind] = parts.get(kind, 0) + w
w = None; stack = []
for line in sys.stdin:
    t = line.strip()
    if not t: flush(w, stack); w = None; stack = []; continue
    if w is None and t.isdigit(): w = int(t); continue
    stack.append(t.split(None, 1)[1] if " " in t else t)
flush(w, stack)
for k, v in sorted(parts.items(), key=lambda x: -x[1]): print(f"{k:12} {v*100/tot:5.1f}%")
print(f"rules total {sum(parts.values())*100/tot:.1f}% of {tot/1e9:.1f}G cycles")
