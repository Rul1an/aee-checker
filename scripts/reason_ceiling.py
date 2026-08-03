"""Reason-parity ceiling: how much of the corpus's condition vocabulary this
checker's prose can reach at all.

Verdict parity is the weaker half of a conformance result. A reject naming the
wrong condition scores as agreement under it. This checker emits prose and no
condition codes, so a reason score requires a prose->code map, and a map is a
construction rather than a reading of the data: two independent constructions
over this same run disagreed (175/178 here, 167/178 from a reviewer), which is
a fact about the constructions and not about the run.

What is construction-independent, and what this script reports, is the shape of
the ambiguity: how many distinct strings the checker emits, how many of them
cover more than one declared condition, and how many corpus codes are reachable
from more than one string. Those numbers are recomputable from published files
by anyone. The ceiling it prints is the best a per-string map can do under THIS
construction and is reported as such, never as a measured reason parity.

Inputs are both published: reports/v0.7-directed-run.json and the corpus
MANIFEST.json at the pinned commit.
"""
import json,re,collections
man={v['id']:v for v in json.load(open('corpus/vectors/MANIFEST.json'))['vectors']}
run=json.load(open('checker/reports/v0.7-directed-run.json'))['vectors']
norm=lambda s: re.sub(r'\[\d+\]','[i]',s or '')
pairs=[]
for v in run:
    m=man.get(v['id']);
    if not m or m.get('kind')=='accept': continue
    codes=set((m['expected'].get('codes') or [])+(m['expected'].get('alsoCarries') or []))
    pairs.append((norm(v.get('reason')), codes, v['id']))
by=collections.defaultdict(list)
for r,c,i in pairs: by[r].append((c,i))
amb=[(r,v) for r,v in by.items() if len({frozenset(c) for c,_ in v})>1]
# best achievable: for each prose string, pick the code set covering most vectors
best=0
for r,v in by.items():
    cnt=collections.Counter()
    for c,_ in v:
        for code in c: cnt[code]+=1
    best += max(cnt.values()) if cnt else 0
print(f"reject+indeterminate vectors: {len(pairs)}")
print(f"distinct emitted reason strings: {len(by)}")
print(f"ambiguous strings (>=2 distinct declared code sets): {len(amb)} covering {sum(len(v) for _,v in amb)} vectors")
codes_multi=collections.defaultdict(set)
for r,v in by.items():
    for c,_ in v:
        for code in c: codes_multi[code].add(r)
print(f"corpus codes reachable from >1 prose string: {sum(1 for k,x in codes_multi.items() if len(x)>1)} of {len(codes_multi)}")
print(f"CEILING under any deterministic prose->code map: {best}/{len(pairs)} ({100*best/len(pairs):.1f}%)")
print(f"unreachable by construction: {len(pairs)-best}")
