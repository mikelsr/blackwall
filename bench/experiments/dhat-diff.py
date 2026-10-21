"""Allocations per request by call site: (run 2N - run N) / N, grouped by the
innermost frame from Blackwall's own crates. Usage: dhat-diff.py <N.json>
<2N.json> N <frames per key> <rows> (profiles from dhat-profile.sh)."""
import json, re, sys
from collections import Counter

def load(path, depth):
    d = json.load(open(path))
    ftbl = d["ftbl"]
    blocks, nbytes = Counter(), Counter()
    for pp in d["pps"]:
        frames = [ftbl[i] for i in pp["fs"]]
        ours = [f for f in frames if re.search(r"\b(shared|proxy|cli)::", f)]
        key = " <- ".join(re.sub(r"^0x[0-9a-f]+: ", "", f)[:110] for f in ours[:depth]) or "(other) " + frames[min(3, len(frames)-1)][:100]
        blocks[key] += pp["tbk"]; nbytes[key] += pp["tb"]
    return blocks, nbytes

small, large, n, depth = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
b1, y1 = load(small, depth); b2, y2 = load(large, depth)
rows = sorted(((b2[k]-b1[k])/n, (y2[k]-y1[k])/n, k) for k in b2)
total = sum(r[0] for r in rows)
print(f"total {total:.1f} allocs/req")
for a, y, k in reversed(rows[-int(sys.argv[5]):]):
    if a >= 0.5: print(f"{a:7.1f} {y:8.0f}B  {k}")
