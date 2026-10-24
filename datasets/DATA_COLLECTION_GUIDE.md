# SentinelAI Data Collection Guide — Legitimate Public Sources

Provenance is not invented. Every manifest must record verified license before data enters `raw/`.

## Where to get the 12-task labels

All tasks collapse to one LM task (structured moderation JSON / structured analysis — see `DATASET_REQUIREMENTS.md`). Attack types are categories inside that JSON, not separate pipelines. So any web/network log with a trustworthy malicious/benign label can be converted if its payload is observable.

## Approved sources (license-verified, no scraping)

| Source | What it supplies | License | How to obtain | Typical size | Use for |
|---|---|---|---|---|---|
| **CSIC 2010 HTTP** (HTTP dataset CSIC 2010) | 36k normal + 25k anomalous HTTP requests with payloads (sqli/xss/traversal etc labeled) | Research use, cite Ruiz et al.; redistribution allowed for research (see UCI mirror terms) | `kaggle datasets download -d santiagomezserra/csic-2010-http` or UCI http://www.isi.csic.es/dataset/ (requires accepting terms on page) | ~30 MB zipped | Task 3,4,5 (sqli/xss/traversal) + benign web |
| **UNSW-NB15** | 257k network flows with 9 attack families + benign, CSV | CC-BY | `kaggle datasets download -d mrwellsdavid/unsw-nb15` | ~200 MB | Task 7 (port-scan/recon) + network benign |
| **CICIDS 2017** (CIC) | PCAPs + labeled flows (Brute Force, DoS, PortScan, Web Attack) | CIC research license — non-commercial, cite Sharafaldin et al. | https://www.unb.ca/cic/datasets/ids-2017.html (form + accept) — **manual** | 50 GB+ (do NOT download full PCAP on this host; flows CSV ~1-3 GB) | Task 6,7 |
| **KDD Cup 1999 / NSL-KDD** | Legacy IDS, labeled | Public domain / research | `kaggle datasets download -d galaxyh/kdd-cup-1999-data` | ~5 MB / 20 MB | Bootstrap only — biased, must not dominate |
| **SecRepo / Public S3 web logs** | Sanitized Apache/Nginx logs | Varies — check each file header | Direct HTTP if license permits | Small | Benign + ambiguous |
| **Hugging Face `huggingface.co/datasets` — `ucberkeley` / `claudette`** | Security documentation (licensed) | As listed per dataset (Apache-2.0 / MIT / CC-BY) | `huggingface-cli download` or python `datasets` | MBs | Not logs — use only for instruction diversity if needed, never as ground-truth labels |

**Not approved until re-checked:** any GitHub repo without LICENSE file, any "kaggle 1M attacks" mirror that rehosts CSIC without attribution, any private paste dump.

## How to acquire via the existing Kaggle OAuth (no token exposure)

```powershell
cd "C:\Users\DARK\Desktop\wild clude\SentientAI"
.\venv\Scripts\kaggle.exe datasets list -s "csic 2010" --csv -p 1
.\venv\Scripts\kaggle.exe datasets download -d santiagomezserra/csic-2010-http -p datasets/raw/web --unzip
# verify hash + write manifest before moving to normalized/
.\venv\Scripts\python.exe TESTv1/training_factory/tools/make_manifest.py --dataset csic2010 --source kaggle:santiagomezserra/csic-2010-http
```

Always estimate before downloading: `kaggle datasets view <slug>` reports `totalBytes`. Reject if `free MB < 2 * totalBytes + 500 MB`. All downloads go to `datasets/raw/<domain>/` verbatim; nothing is mutated in place.

## Required manifest fields (written by `make_manifest.py`, never hand-edited silently)

`source`, `download_date`, `license` (verbatim SPDX or URL + acceptance note), `file_hashes` (sha256), `record_count`, `available_labels`, `processing_history[]`, `intended_use` (tasks 1-12 map), `known_limitations`.

## What to do if a source requires manual acceptance

Stop that download, log blocker in `datasets/reports/acquisition_log.md` with exact URL + required click, continue other sources. Do not bypass terms.

## Synthetic augmentation (bounded)

Generated only after schema + validator pass. Labeled `synthetic: true` in manifest, ≤20% of any split, evidence substrings forced to appear verbatim in input, validated by same `parse_moderation` gate as real data.
