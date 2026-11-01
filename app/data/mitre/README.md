# MITRE ATT&CK Enterprise dataset (local copy)

- **Source:** https://github.com/mitre-attack/attack-stix-data (STIX 2.1)
- **Installed version:** Enterprise ATT&CK **20.0** (released 2026-10-13;
  collection modified `2026-10-13T17:53:10.145Z`)
- **Bundle file:** `enterprise-attack-20.0.json` — 55,271,014 bytes,
  26,690 objects, SHA-256
  `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352`
  (see `manifest.json`, which is the loader's source of truth).
- **License:** `LICENSE.txt` is bundled verbatim per MITRE's Terms of
  Use. Attribution shown in the app: "© 2026 The MITRE Corporation.
  This work is reproduced and distributed with the permission of The
  MITRE Corporation." ATT&CK® is a registered trademark of The MITRE
  Corporation; first written reference must be "MITRE ATT&CK®", and
  nothing here implies MITRE endorsement.

## How it is used

`app/services/mitre_attack.py` loads this bundle from disk only. There
is **no live MITRE call per event** and no network access at analysis
time. Every technique ID the app emits is validated against this local
copy; anything that fails validation is reported as
`Unknown / Not mapped`, never substituted.

## Installing / updating

The bundle file itself is gitignored (55 MB); the manifest, LICENSE,
and this README are tracked. A fresh checkout gets the dataset with:

```bash
python scripts/import_mitre.py --version 20.0
```

For a newer release, run the script with that version. It downloads to
a temporary file, verifies the bundle parses and its collection
version matches, and only then installs the versioned file and moves
the manifest pointer — the previous versioned file stays on disk, so a
failed update never destroys the working dataset. A re-download of an
already-installed version with a different hash is refused.

## Staleness

The app surfaces "dataset outdated" when `index.json` at import time
reports a newer Enterprise version than the manifest. That check is
operator-triggered only (see `check_for_updates()`); it never runs
during event analysis.

## Notes from the v20.0 import

- The analytic↔detection-strategy link is NOT a relationship object:
  analytics carry no relationships at all. The parent strategy is
  encoded in the analytic's `external_references` URL
  (`.../detectionstrategies/DET0039#AN0110`). The service resolves it
  that way.
- `x-mitre-data-source` is deprecated (spec 3.3.0) — nothing is built
  on it; detection strategies and analytics are the current framework.
- v19 remapping debt is real in the data: Defense Evasion was split
  into Stealth (TA0005) and Defense Impairment (TA0112). Old mappings
  to the retired framing must be re-validated against v20.
