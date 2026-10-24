import sys, json
from pathlib import Path
BASE = Path(r"C:\Users\DARK\Desktop\wild clude\SentientAI")
sys.path.insert(0, str(BASE))
# Avoid cp1252 print issues
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from tokenizers import Tokenizer
from app.services.prompt_service import get_base_prompt, build_analysis_prompt
from app.services.sentinel_loader import ensure_loaded, get_bundle, get_models

# Already loaded, now diagnostics 3-4
import time, torch
tok_path = BASE / "local_models" / "sentinel" / "sentinel_tokenizer.json"
tok = Tokenizer.from_file(str(tok_path))

# DIAG 3: generation params inspection
print("=== DIAG 3: generation param inspection ===")
# Read sentinel_inference source-relevant defaults
prompt = build_analysis_prompt("Hello, summarize this: The cat sat on the mat.", extra_prompt=None)
prompt_susp = build_analysis_prompt("2024-01-01 10:00:00 WARN 192.168.1.10 login failed 401\n"*6, extra_prompt=None)
enc = tok.encode(prompt)
enc_susp = tok.encode(prompt_susp)
print(f"synthetic prompt tokens={len(enc.ids)} prompt_susp tokens={len(enc_susp.ids)} max_pos 768")
print(f"synthetic ids head {enc.ids[:10]} tail {enc.ids[-10:]}")
print(f"suspicious ids head {enc_susp.ids[:10]} tail {enc_susp.ids[-10:]}")
# Check BOS/EOS/PAD
print(f"pad={tok.token_to_id('<pad>')} bos={tok.token_to_id('<bos>')} eos={tok.token_to_id('<eos>')} output={tok.token_to_id('<output>')} close={tok.token_to_id('</output>')}")
# Check that input_ids construction correctly prepends BOS and preserves <output>
from app.services.sentinel_loader import get_bundle
ensure_loaded()
bundle = get_bundle()
cfg = bundle["config"]
print(f"config hidden={cfg['hidden_size']} layers={cfg['num_layers']} max_pos={cfg['max_position_embeddings']}")

print("\n=== DIAG 4: live generation (synthetic + attack) ===")
from app.services.sentinel_inference import run_dual_inference, _generate_for_model
import logging
logging.getLogger("sentientai.sentinel.inference").setLevel(logging.WARNING)
for label, pr in [("synthetic benign", prompt), ("brute-force attack", prompt_susp)]:
    print(f"\n--- {label} ---")
    inf = run_dual_inference(pr, max_new_tokens=64, timeout_s=12)
    for k in ["model_a","model_b"]:
        m = inf.get(k) or {}
        txt = (m.get("text") or "")[:400]
        print(f"  {k}: status={m.get('status')} stopped={m.get('stopped')} tokens={m.get('tokens')} latency={m.get('latency_ms')}ms")
        print(f"       text={repr(txt)}")
        if m.get("error"):
            print(f"       error={repr(m.get('error'))[:300]}")
    print(f"  agreement={inf.get('agreement')} ready={inf.get('ready')} latency={inf.get('latency_ms')}ms")
    # Also show fusion for these
    from app.services.sentinel_fusion import fuse
    from app.services.sentinel_schema import validate_sentinel_output
    fused = fuse(pr.split("</input>")[1] if "</input>" in pr else pr, inf)
    print(f"  fused verdict={fused.get('fused_verdict')} score={fused.get('fused_score')} rules={fused.get('rules',{}).get('verdict')} comps={[(c['source'], c['verdict'], c.get('structured_valid')) for c in fused.get('components',[])] }")
    for k in ["model_a","model_b"]:
        m=inf.get(k) or {}
        v=validate_sentinel_output(m.get("text"), m.get("status"))
        print(f"    {k} valid={v['valid']} verdict={v['verdict']} errors={v['errors'][:3]}")

print("\n=== DIAG 5: schema validation + pipeline stage summary ===")
from app.services.sentinel_schema import fuse_structured, validate_sentinel_output
for label, pr, log in [("synthetic", prompt, "Hello, summarize this: The cat sat on the mat."), ("attack", prompt_susp, "2024-01-01 10:00:00 WARN 192.168.1.10 login failed 401\n"*6)]:
    # Re-run inference for schema test with more tokens
    inf = run_dual_inference(pr, max_new_tokens=96, timeout_s=12)
    fs = fuse_structured(log, inf)
    print(f"  {label}: fused={fs.get('fused_verdict')} model_a_valid={(fs.get('model_a_struct') or {}).get('structured_valid')} model_b_valid={(fs.get('model_b_struct') or {}).get('structured_valid')}")
    print(f"    a verdict={(fs.get('model_a_struct') or {}).get('verdict')} b verdict={(fs.get('model_b_struct') or {}).get('verdict')} agreement={fs.get('agreement')}")

print("\n=== DIAG 6: checkpoint sanity ===")
import torch as _t
for name, p in [("A", BASE/"local_models/sentinel/sentinel_best_model.pt"), ("B", BASE/"local_models/sentinel/best_autolab_checkpoint.pt")]:
    ckpt = _t.load(str(p), map_location="cpu", weights_only=False)
    print(f"  {name}: keys={list(ckpt.keys())} epoch={ckpt.get('epoch')} best_val_loss={ckpt.get('best_val_loss')} val_loss={ckpt.get('val_loss')}")
    sd = ckpt.get("model_state_dict") or {}
    print(f"    state_dict keys={len(sd)} sample {list(sd.keys())[:3]}")
    # Check embedding size vs vocab
    if "token_embedding.weight" in sd:
        print(f"    token_embedding shape={tuple(sd['token_embedding.weight'].shape)}")
