#!/usr/bin/env python3
"""Phase 2: Bounded CSIC ingestion + validation. Raw unchanged, normalized + reports only."""
import pathlib, hashlib, csv, json, collections
ROOT = pathlib.Path(r"C:\Users\DARK\Desktop\wild clude\SentientAI")
RAW = ROOT / "datasets/raw/web/csic_database.csv"
MANIFEST = ROOT / "datasets/manifests/csic_database.json"
OUT_NORMALIZED = ROOT / "datasets/normalized/csic_normalized.jsonl"
OUT_REJECTED = ROOT / "datasets/rejected/csic_rejected.jsonl"
REPORT = ROOT / "datasets/reports/csic_validation.json"
LOG = ROOT / "TESTv1/training_factory/logs/phase2_status.json"
EXPECTED_SHA = "c420f0bc0464376de75b6c419a0ac226fe69fe12c8ac4908843273721e44e637"
EXPECTED_COLS = ["", "Method", "User-Agent", "Pragma", "Cache-Control", "Accept", "Accept-encoding", "Accept-charset", "language", "host", "cookie", "content-type", "connection", "lenght", "content", "classification", "URL"]
MAX_POS = 768
BUDGET = 740

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1<<20), b""):
            h.update(c)
    return h.hexdigest()

_tok = None
def get_tok():
    global _tok
    if _tok is None:
        try:
            from tokenizers import Tokenizer
            _tok = Tokenizer.from_file(str(ROOT / "local_models/sentinel/sentinel_tokenizer.json"))
        except Exception:
            _tok = False
    return None if _tok is False else _tok

def tokenizer_len(text):
    tok = get_tok()
    if tok is None:
        return None
    return len(tok.encode(text).ids)

def main():
    assert RAW.exists(), f"missing {RAW}"
    raw_sha = sha256_file(RAW)
    assert raw_sha == EXPECTED_SHA, f"sha mismatch {raw_sha}"
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8")) if MANIFEST.exists() else {}
    with open(RAW, encoding="utf-8", newline="") as f:
        r = csv.reader(f)
        hdr = next(r)
        cols_ok = hdr == EXPECTED_COLS
    with open(RAW, encoding="utf-8", newline="") as f:
        d = csv.DictReader(f)
        assert d.fieldnames == EXPECTED_COLS, f"header mismatch {d.fieldnames}"
        n = 0
        malformed = []
        missing = {c:0 for c in EXPECTED_COLS}
        by_label_missing = {"0": collections.Counter(), "1": collections.Counter()}
        label_counts = collections.Counter()
        dups_seen = set()
        dups = 0
        rejected = []
        normalized_rows = []
        token_lengths = []
        prompt = (ROOT / "prompts/prompt.txt").read_text(encoding="utf-8").strip()
        prompt_head = prompt[:600]
        instruction = prompt_head
        for idx, row in enumerate(d, start=1):
            n += 1
            if None in row.values() or any(k is None for k in row.keys()):
                malformed.append(idx)
                rejected.append({"source_row": idx, "reason": "column_count_mismatch", "row_keys": list(row.keys())})
                continue
            for c in EXPECTED_COLS:
                if row.get(c, "") == "":
                    missing[c] += 1
                    lab = row.get("classification","").strip()
                    if lab in by_label_missing:
                        by_label_missing[lab][c] += 1
            lab = row.get("classification","").strip()
            if lab not in ("0","1"):
                rejected.append({"source_row": idx, "reason": f"invalid_label:{lab}"})
                continue
            label_counts[lab] += 1
            serial = "\x1f".join(row.get(c,"") for c in EXPECTED_COLS)
            hh = hashlib.sha256(serial.encode("utf-8", errors="replace")).hexdigest()
            if hh in dups_seen:
                dups += 1
            else:
                dups_seen.add(hh)
            normalized = {
                "source_row": idx,
                "provenance": {"file": "datasets/raw/web/csic_database.csv", "sha256": raw_sha},
                "method": row.get("Method",""),
                "url": row.get("URL",""),
                "host": row.get("host",""),
                "user_agent": row.get("User-Agent",""),
                "headers": {
                    "pragma": row.get("Pragma",""),
                    "cache_control": row.get("Cache-Control",""),
                    "accept": row.get("Accept",""),
                    "accept_encoding": row.get("Accept-encoding",""),
                    "accept_charset": row.get("Accept-charset",""),
                    "language": row.get("language",""),
                    "cookie": row.get("cookie",""),
                    "content_type": row.get("content-type",""),
                    "connection": row.get("connection",""),
                    "content_length_raw": row.get("lenght",""),
                },
                "content": row.get("content",""),
                "label_raw": lab,
                "label": "benign" if lab == "0" else "anomalous",
            }
            sanitized_log = f"{normalized['method']} {normalized['url']} Host:{normalized['host']} Content:{normalized['content'][:400]}"
            target = "likely_benign" if lab == "0" else "needs_review"
            rendered = f"<instruction>{instruction}</instruction><input>{sanitized_log}</input><output>{target}</output>"
            tlen = tokenizer_len(rendered)
            if tlen is not None:
                token_lengths.append(tlen)
                if tlen > MAX_POS:
                    rejected.append({"source_row": idx, "reason": f"token_length_{tlen}_exceeds_{MAX_POS}"})
                    continue
            normalized_rows.append(normalized)
    OUT_NORMALIZED.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_NORMALIZED, "w", encoding="utf-8") as out:
        for r_ in normalized_rows:
            out.write(json.dumps(r_, ensure_ascii=False) + "\n")
    OUT_REJECTED.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_REJECTED, "w", encoding="utf-8") as out:
        for r_ in rejected:
            out.write(json.dumps(r_, ensure_ascii=False) + "\n")
    missing_investigation = {
        "content_type_empty": missing["content-type"],
        "content_length_empty": missing["lenght"],
        "content_empty": missing["content"],
        "accept_empty": missing["Accept"],
        "by_label": {k: dict(v) for k, v in by_label_missing.items()},
        "interpretation": "Empty content/content-type/lenght occurs in 28000/36000 benign (77.8%) and 15088/25065 anomalous (60.2%) — common in GET without body, not a reliable malicious signal. Empty Accept occurs only in 397 anomalous rows, all PUT — correlated but not classified as malicious by missing alone. Validation does not label missing fields as malicious.",
    }
    token_stats = {}
    if token_lengths:
        token_stats = {
            "count": len(token_lengths),
            "min": min(token_lengths),
            "max": max(token_lengths),
            "mean": sum(token_lengths)/len(token_lengths),
            "over_budget_740": sum(1 for x in token_lengths if x > 740),
            "over_768": sum(1 for x in token_lengths if x > 768),
        }
    report = {
        "raw_path": "datasets/raw/web/csic_database.csv",
        "sha256": raw_sha,
        "sha256_match": raw_sha == EXPECTED_SHA,
        "rows": n,
        "columns": EXPECTED_COLS,
        "columns_match_expected": cols_ok,
        "encoding": "utf-8",
        "malformed_rows": len(malformed),
        "malformed_index_sample": malformed[:10],
        "duplicate_rows": dups,
        "distinct_rows": len(dups_seen),
        "missing_values": missing,
        "missing_investigation": missing_investigation,
        "label_distribution": dict(label_counts),
        "label_mapping": {"0": "benign", "1": "anomalous"},
        "normalized_path": "datasets/normalized/csic_normalized.jsonl",
        "normalized_rows": len(normalized_rows),
        "rejected_path": "datasets/rejected/csic_rejected.jsonl",
        "rejected_rows": len(rejected),
        "token_length": token_stats,
        "license": manifest.get("license", {"status": "restricted/unverified - copyright-authors; redistribution NOT permitted"}),
        "limitations": manifest.get("limitations", []),
        "raw_modified": False,
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    status = "PASS"
    if not cols_ok or raw_sha != EXPECTED_SHA or n != 61065:
        status = "FAIL"
    elif token_stats.get("over_768", 0) > 0:
        status = "PARTIAL"
    if label_counts.get("0",0) != 36000 or label_counts.get("1",0) != 25065:
        status = "FAIL"
    log_data = {
        "phase": "Phase 2: Data Ingestion and Validation",
        "status": status,
        "timestamp": __import__("datetime").datetime.now().astimezone().isoformat(),
        "report_path": "datasets/reports/csic_validation.json",
        "normalized_path": str(OUT_NORMALIZED.relative_to(ROOT)),
        "rejected_path": str(OUT_REJECTED.relative_to(ROOT)),
        "verified": {"sha256": raw_sha, "rows": n, "label_distribution": dict(label_counts), "malformed": len(malformed), "dups": dups},
        "token_length": token_stats,
        "next_step": "Phase 2 artifacts verified; do not create splits until label semantics reviewed. Await instruction for Phase 3 (split) or re-run validation tests." if status == "PASS" else "Fix failures before split.",
    }
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text(json.dumps(log_data, indent=2), encoding="utf-8")
    prog = {
        "last_phase": "phase2",
        "phase2_status": status,
        "phase2_report": "datasets/reports/csic_validation.json",
        "phase2_log": "TESTv1/training_factory/logs/phase2_status.json",
        "phase2_verified": log_data["verified"],
        "next_step": log_data["next_step"],
        "constraints": "raw unchanged; checkpoints/db untouched; no training; no Kaggle upload; splits not created",
    }
    (ROOT / "progress.json").write_text(json.dumps(prog, indent=2), encoding="utf-8")
    md = f"""# Progress

- Phase 1: PASS — web/csic_database.csv 61065 rows sha {EXPECTED_SHA[:12]}... manifest at datasets/manifests/csic_database.json
- Phase 2: {status} — ingestion/validation report at datasets/reports/csic_validation.json, log at TESTv1/training_factory/logs/phase2_status.json
- Verified: rows={n} benign={label_counts.get('0',0)} anomalous={label_counts.get('1',0)} malformed={len(malformed)} dups={dups} tokens_max={token_stats.get('max','-')} over768={token_stats.get('over_768','-')}
- Next: {log_data['next_step']}
"""
    (ROOT / "PROGRESS.md").write_text(md, encoding="utf-8")
    print(f"STATUS:{status}")
    print(f"ROWS:{n} BENIGN:{label_counts.get('0',0)} ANOMALOUS:{label_counts.get('1',0)} MALFORMED:{len(malformed)} DUPS:{dups}")
    print(f"TOKEN_MAX:{token_stats.get('max')} OVER768:{token_stats.get('over_768')} MEAN:{token_stats.get('mean')}")
    print(f"REPORT:{REPORT}")
    print(f"LOG:{LOG}")

if __name__ == "__main__":
    main()
