"""Phase 2: bounded generation diagnostics for both checkpoints."""
import json, time, sys, pathlib
root = pathlib.Path(r"C:\Users\DARK\Desktop\wild clude\SentientAI")
sys.path.insert(0, str(root))
from app.services.sentinel_loader import ensure_loaded, get_bundle, get_status, get_tokenizer
from app.services.sentinel_inference import _generate_for_model
from app.services.sentinel_schema import validate_sentinel_output
from app.services.prompt_service import build_analysis_prompt, get_base_prompt

status = ensure_loaded()
print(f"LOADER status ready={status.ready} a={status.a} b={status.b} vocab={status.tokenizer_vocab_size} rss={status.rss_mb}MB load_a={status.load_ms_a} load_b={status.load_ms_b}")
bundle = get_bundle()
tok = bundle.get("tokenizer") or get_tokenizer()
cfg = bundle.get("config") or {}
models = bundle.get("model_a"), bundle.get("model_b")
from app.services.sentinel_loader import get_models
ms = get_models()
model_a = ms.get("a") or bundle.get("model_a")
model_b = ms.get("b") or bundle.get("model_b")
print(f"model_a loaded={model_a is not None} model_b loaded={model_b is not None}")
print(f"config vocab={cfg.get('vocab_size')} max_pos={cfg.get('max_position_embeddings')} bos={cfg.get('bos_token_id')} eos={cfg.get('eos_token_id')} pad={cfg.get('pad_token_id')}")
print(f"tokenizer vocab_size={tok.get_vocab_size() if tok else 'none'}")
# sanity: prompt
base = get_base_prompt()
print(f"base prompt chars={len(base)} head={base[:120].replace(chr(10),' | ')}")

cases = [
    ("greeting", "Hello, how are you today?"),
    ("factual", "What is the capital of France?"),
    ("summarize", "Summarize: The user alice viewed SELECTION committee report and then logged out. What happened?"),
    ("benign_log", "2024-01-01 10:00:05 INFO 10.0.0.5 GET /api/posts 200 duration 12ms"),
    ("suspicious_log", "2024-01-01 10:00:00 WARN 192.168.1.10 login failed for user admin 401 | " * 6),
    ("sentinel_structured", "2024-01-01 10:00:22 INFO GET /download?file=../../etc/passwd 200"),
]

for ckpt_name, model in [("A:sentinel_best_model.pt", model_a), ("B:best_autolab_checkpoint.pt", model_b)]:
    print("\n" + "="*80)
    print(f"CHECKPOINT {ckpt_name}")
    if model is None:
        print("  MODEL NOT LOADED")
        continue
    for label, log_text in cases:
        # Use training-faithful prompt for sentinel cases, raw for first 3
        if label in ("greeting","factual","summarize"):
            # test raw prompt ability: instruction/input/output still applied but with generic log
            prompt = build_analysis_prompt(log_text)
        else:
            prompt = build_analysis_prompt(log_text)
        enc = tok.encode(prompt)
        ids = enc.ids
        budget = max(64, cfg.get("max_position_embeddings",768) - 96 - 4)
        print(f"\n  [{label}] log_len={len(log_text)} prompt_ids={len(ids)} budget={budget} truncated={len(ids)>budget}")
        # bounded generation max 96
        res = _generate_for_model(model, tok, prompt, cfg, max_new_tokens=96, timeout_s=12)
        raw = res.get("raw_text","") if "raw_text" in res else res.get("text","")
        text = res.get("text","")
        v = validate_sentinel_output(text, res.get("status"))
        # Also test raw decode without strip
        print(f"    gen status={res.get('status')} stopped={res.get('stopped')} tokens={res.get('tokens')} latency={res.get('latency_ms')}ms")
        print(f"    raw_text len={len(raw)} preview={raw[:300]!r}")
        print(f"    text len={len(text)} preview={text[:400]!r}")
        print(f"    valid={v['valid']} verdict={v['verdict']} errors={v['errors'][:3]}")
        # Also check logits sanity: one-step greedy distribution
        # Run single forward to inspect top logits
        try:
            import torch
            bos = cfg.get("bos_token_id",2)
            eout = tok.token_to_id("<output>")
            # build input_ids like inference does
            ids2 = enc.ids[:]
            if len(ids2) > budget:
                tail_keep=8
                if ids2[-1]==eout and len(ids2)>tail_keep:
                    head=budget-tail_keep
                    ids2=ids2[:head]+ids2[-tail_keep:]
                else:
                    ids2=ids2[-budget:]
            input_ids=[bos]+ids2
            max_pos=cfg.get("max_position_embeddings",768)
            if len(input_ids)>max_pos:
                input_ids=input_ids[-max_pos:]
            with torch.inference_mode():
                cur=torch.tensor([input_ids[-max_pos:]], dtype=torch.long)
                out=model(cur)
                logits=out["logits"][0,-1]
                topk=torch.topk(logits,5)
                vals=topk.values.tolist()
                idxs=topk.indices.tolist()
                toks=[tok.decode([i]) if i<tok.get_vocab_size() else f"<{i}>" for i in idxs]
                # softmax
                probs=torch.softmax(logits, dim=-1)
                ent=-(probs*torch.log(probs+1e-12)).sum().item()
                print(f"    TOP5 next-token: {list(zip(idxs, toks, [round(v,3) for v in vals]))} entropy={ent:.3f} max_prob={probs.max().item():.4f}")
                # check if EOS is top
                eos=cfg.get("eos_token_id",3)
                pad=cfg.get("pad_token_id",0)
                print(f"    eos logit={logits[eos].item():.3f} prob={probs[eos].item():.4f} pad_logit={logits[pad].item():.3f} eout_logit={logits[eout].item():.3f} if eout else n/a")
        except Exception as e:
            print(f"    logit inspect error: {e}")

# Also test raw decode path without control-token stripping: compare
print("\n=== POSTPROCESSING CHECK ===")
# handcraft a valid output to ensure validator works
valid_example = """Summary: The log shows 6 failed logins from 192.168.1.10 followed by no success.
Input status: valid
Indicators:
- 192.168.1.10
- 6x login failed 401
- no success
Reasoning: Repeated failures indicate brute-force attempt; no success observed.
Provisional assessment: likely_threat
Recommendation: Block IP and review."""
print(validate_sentinel_output(valid_example, "ok"))

# Compare training vs inference format mismatch note
print("\n=== DONE ===")
