# Datasets — SentinelAI

Workspace for all training data. Raw data is never mutated; every transform is recorded and reproducible.

```
datasets/
  README.md                     — this file
  DATASET_REQUIREMENTS.md       — what Sentinel must learn, inputs/outputs, metrics
  DATA_COLLECTION_GUIDE.md      — legitimate public sources, licenses, fetch methods
  manifests/                    — one JSON per imported dataset (hashes, license, labels, processing)
  raw/{network,web,authentication,application,benign,ambiguous} — verbatim imports
  normalized/                   — field-normalized, PII-scrubbed, deduped
  processed/                    — schema-validated, token-length-checked
  training/ validation/ test/   — 80/10/10 split, test isolated from model selection
  synthetic/                    — generated examples, labeled synthetic, never mixed silently
  rejected/                     — malformed/conflicting records with reason
  reports/                      — data-quality, distribution, leakage reports
```

Rules: never silently mix unrelated datasets, never invent provenance, keep test isolated.
