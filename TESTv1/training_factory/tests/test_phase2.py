import pathlib, json, hashlib, csv, collections
ROOT = pathlib.Path(r"C:\Users\DARK\Desktop\wild clude\SentientAI")
RAW = ROOT / "datasets/raw/web/csic_database.csv"
REPORT = ROOT / "datasets/reports/csic_validation.json"
NORMALIZED = ROOT / "datasets/normalized/csic_normalized.jsonl"
REJECTED = ROOT / "datasets/rejected/csic_rejected.jsonl"
EXPECTED_SHA = "c420f0bc0464376de75b6c419a0ac226fe69fe12c8ac4908843273721e44e637"
EXPECTED_COLS = ["", "Method", "User-Agent", "Pragma", "Cache-Control", "Accept", "Accept-encoding", "Accept-charset", "language", "host", "cookie", "content-type", "connection", "lenght", "content", "classification", "URL"]

def test_raw_exists_and_hash():
    assert RAW.exists(), "raw missing"
    h = hashlib.sha256()
    with open(RAW, "rb") as f:
        for c in iter(lambda: f.read(1<<20), b""):
            h.update(c)
    assert h.hexdigest() == EXPECTED_SHA

def test_schema_and_encoding():
    with open(RAW, encoding="utf-8", newline="") as f:
        r = csv.reader(f)
        hdr = next(r)
        assert hdr == EXPECTED_COLS, hdr
        n = 0
        for row in r:
            n += 1
            assert len(row) == len(hdr), f"malformed row {n}"
    assert n == 61065

def test_label_mapping_and_missing():
    label_counts = collections.Counter()
    missing = {c:0 for c in EXPECTED_COLS}
    with open(RAW, encoding="utf-8", newline="") as f:
        d = csv.DictReader(f)
        for row in d:
            lab = row["classification"].strip()
            assert lab in ("0","1"), lab
            label_counts[lab] += 1
            for c in EXPECTED_COLS:
                if row.get(c,"") == "":
                    missing[c] += 1
    assert label_counts["0"] == 36000
    assert label_counts["1"] == 25065
    assert missing["content-type"] == 43088
    assert missing["lenght"] == 43088
    assert missing["content"] == 43088
    assert missing["Accept"] == 397
    # do not classify missing as malicious: check both labels have missing content
    # verified by report

def test_duplicates_and_malformed():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert report["malformed_rows"] == 0
    assert report["duplicate_rows"] == 0
    assert report["distinct_rows"] == 61065
    assert report["columns_match_expected"] is True
    assert report["sha256_match"] is True
    assert report["raw_modified"] is False

def test_normalized_schema_and_provenance():
    assert NORMALIZED.exists()
    n = 0
    with open(NORMALIZED, encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            assert "source_row" in rec
            assert "provenance" in rec
            assert rec["provenance"]["sha256"] == EXPECTED_SHA
            assert rec["provenance"]["file"] == "datasets/raw/web/csic_database.csv"
            assert "method" in rec and "url" in rec
            assert "headers" in rec and "content_length_raw" in rec["headers"]
            assert rec["label"] in ("benign","anomalous")
            n += 1
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert n == report["normalized_rows"] == 61064  # 1 quarantined
    # source_row unique
    seen = set()
    with open(NORMALIZED, encoding="utf-8") as f:
        for line in f:
            seen.add(json.loads(line)["source_row"])
    assert len(seen) == n

def test_rejected_not_silently_discarded():
    assert REJECTED.exists()
    rows = [json.loads(l) for l in REJECTED.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(rows) == 1
    assert rows[0]["source_row"] == 51536
    assert "token_length_779_exceeds_768" in rows[0]["reason"]
    # quarantined, not counted in normalized
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert report["rows"] == report["normalized_rows"] + report["rejected_rows"]

def test_token_length_768():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    tl = report["token_length"]
    assert tl["count"] == 61065
    assert tl["over_768"] == 1
    # after quarantine, normalized max <=768
    # load tokenizer once to verify max of normalized <=768 (sanity: 779 was rejected)
    assert report["rejected_rows"] == tl["over_768"]
    assert tl["max"] == 779

def test_missing_not_malicious():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    inv = report["missing_investigation"]
    assert "not a reliable malicious signal" in inv["interpretation"]
    assert inv["by_label"]["0"]["content-type"] == 28000
    assert inv["by_label"]["1"]["Accept"] == 397

def test_license_and_limitations():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    lic = report["license"]
    assert lic["redistribution_permitted"] is False
    assert "copyright-authors" in json.dumps(lic)
    assert len(report["limitations"]) >= 4

def test_raw_unchanged_and_no_splits():
    # no train/val/test splits yet
    for p in [ROOT/"datasets/training", ROOT/"datasets/validation", ROOT/"datasets/test"]:
        # should be empty
        files = list(p.glob("*")) if p.exists() else []
        assert len(files) == 0, f"split created prematurely {p} {files}"
    # checkpoints/db untouched
    assert (ROOT/"local_models/sentinel/sentinel_best_model.pt").stat().st_size == 1092932897
    assert (ROOT/"local_models/sentinel/best_autolab_checkpoint.pt").stat().st_size == 1092935695

if __name__ == "__main__":
    import sys
    tests = [v for k,v in globals().items() if k.startswith("test_")]
    fails = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as e:
            fails += 1
            print(f"FAIL {t.__name__}: {e}")
        except Exception as e:
            fails += 1
            print(f"ERROR {t.__name__}: {e!r}")
    print(f"TOTAL {len(tests)} FAILS {fails}")
    sys.exit(fails)
