import pathlib, hashlib, csv, json, collections
ROOT = pathlib.Path(r"C:\Users\DARK\Desktop\wild clude\SentientAI")
raw = ROOT / "datasets/raw/web/csic_database.csv"
h = hashlib.sha256()
with open(raw, "rb") as f:
    for c in iter(lambda: f.read(1<<20), b""):
        h.update(c)
sha = h.hexdigest()
print(f"SHA256:{sha}")
print(f"BYTES:{raw.stat().st_size}")
with open(raw, encoding="utf-8", newline="") as f:
    r = csv.reader(f)
    hdr = next(r)
    print(f"COLS:{json.dumps(hdr)}")
    ncols = len(hdr)
    malformed = 0
    n = 0
    methods = collections.Counter()
    cls = collections.Counter()
    missing = {c:0 for c in hdr}
    by_label = {"0": collections.Counter(), "1": collections.Counter()}
    for row in r:
        n += 1
        if len(row) != ncols:
            malformed += 1
        for i,c in enumerate(hdr):
            v = row[i] if i < len(row) else ""
            if v == "":
                missing[c] += 1
                lab = row[15] if len(row) > 15 else "?"
                lab = lab.strip()
                if lab in by_label:
                    by_label[lab][c] += 1
        if len(row) > 1:
            methods[row[1]] += 1
        if len(row) > 15:
            cls[row[15].strip()] += 1
print(f"ROWS:{n}")
print(f"MALFORMED:{malformed}")
print(f"MISSING:{json.dumps(missing)}")
print(f"BY_LABEL_0_MISSING:{json.dumps(dict(by_label['0']))}")
print(f"BY_LABEL_1_MISSING:{json.dumps(dict(by_label['1']))}")
print(f"METHODS:{json.dumps(dict(methods))}")
print(f"CLASS_DIST:{json.dumps(dict(cls))}")
# duplicate check by full row hash
import hashlib as hl
seen = set()
dups = 0
with open(raw, encoding="utf-8", newline="") as f:
    rr = csv.reader(f)
    next(rr)
    for row in rr:
        hh = hl.sha256("\x1f".join(row).encode("utf-8", errors="replace")).hexdigest()
        if hh in seen:
            dups += 1
        else:
            seen.add(hh)
print(f"DUPS:{dups} DISTINCT:{len(seen)}")
# encoding check already utf-8 open succeeded
print("ENCODING:utf-8 OK")
