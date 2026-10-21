# Top leaf functions of the "policy rules" samples that are neither regex nor
# CEL (perf script -F period,ip,sym on stdin).
import re, sys, collections
RULES = re.compile(r"shared::policy|cel::|regex|ipnet")
leaf = collections.Counter(); w = None; stack = []
def flush():
    if w is None or not any(RULES.search(s) for s in stack): return
    if any("regex" in s or "cel::" in s for s in stack): return
    leaf[stack[0][:110]] += w
for line in sys.stdin:
    t = line.strip()
    if not t: flush(); w = None; stack = []; continue
    if w is None and t.isdigit(): w = int(t); continue
    stack.append(t.split(None, 1)[1] if " " in t else t)
flush()
tot = sum(leaf.values())
for k, v in leaf.most_common(12): print(f"{v*100/tot:5.1f}%  {k}")
