import sys, io
from pathlib import Path
BASE = Path(r"C:\Users\DARK\Desktop\wild clude\SentientAI")
sys.path.insert(0, str(BASE))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
import json

# 1. Check evaluation latest metrics for valid-output rate
ld = json.loads((BASE/"evaluation"/"latest.json").read_text(encoding="utf-8"))
print("=== evaluation latest (rules-only) ===")
print(json.dumps(ld["metrics"], indent=2))
print(f"n_cases {ld['meta']['n_cases']}")

# 2. Prompt size vs token budget
from tokenizers import Tokenizer
from app.services.prompt_service import get_base_prompt, build_analysis_prompt
tok = Tokenizer.from_file(str(BASE/"local_models/sentinel/sentinel_tokenizer.json"))
bp = get_base_prompt()
print(f"\n=== base prompt ===")
print(f"chars {len(bp)} tokens approx {len(tok.encode(bp).ids)}")
# show the stitched instruction length
for extra in [None, "Look at this extra context: focus on injection"]:
    pr = build_analysis_prompt("2024-01-01 10:00:00 INFO ok 200", extra_prompt=extra)
    enc = tok.encode(pr)
    print(f"  extra={repr((extra or '')[:40])} prompt tokens={len(enc.ids)} overflow={len(enc.ids)>768}")

# 3. Check that fusion rules alone behave correctly for the brute-force case vs 0-score case
from app.services.sentinel_fusion import evaluate_rules, fuse
cases = [
    ("benign single", "2024-01-01 10:00:00 INFO ok 200"),
    ("attack 6 brute", "\n".join(["2024-01-01 10:00:00 WARN 192.168.1.10 login failed 401"]*6)),
    ("attack portscan", "nmap scan " + " ".join([f"port {p} open" for p in range(8000,8015)])),
]
for label, txt in cases:
    r = evaluate_rules(txt)
    f = fuse(txt, {"model_a":{"text":"","status":"empty"},"model_b":{"text":"","status":"empty"}})
    print(f"  {label}: rules {r['verdict']} score {r['score']} fused {f['fused_verdict']} score {f['fused_score']}")

# 4. Confirm prompt truncation is dropping middle correctly but check budget math
print("\n=== truncation budget ===")
# Synthetic already 636 tokens, with max_new 64 budget = 700, synthetic fits, but attack 771 overflows
# max_new=180 budget = 768-180-4=584 -> both would truncate
for max_new in [48,64,96,180,256]:
    budget = max(64, 768 - max_new - 4)
    print(f"  max_new {max_new:3d} budget {budget}")

# 5. SentinelStatus after load
from app.services.sentinel_loader import get_status
s = get_status()
print(f"\n=== status after previous ensure_loaded still in same process? New process will re-load ===")
print(f"  This temp script new process would need load; earlier diagnostics used shared? In this script fresh process ready={s.ready} a={s.a} b={s.b} reason={s.reason}")

# 6. Check sentinel_schema validation detail on garbage
from app.services.sentinel_schema import validate_sentinel_output
garbage = "up the far far above the far above the worst , so"
print(f"\n  garbage validation: {validate_sentinel_output(garbage, 'timeout')}")
structured = "Summary: benign log\nInput status: valid\nIndicators:\n- 192.168.1.1\nReasoning: normal\nProvisional assessment: likely_benign\nRecommendation: review"
print(f"  structured valid example: {validate_sentinel_output(structured, 'ok')}")

