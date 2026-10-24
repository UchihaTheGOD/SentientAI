import pathlib, json, sys, io, time
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
root = pathlib.Path(r"C:\Users\DARK\Desktop\wild clude\SentientAI")
sys.path.insert(0, str(root))
from app.services.sentinel_loader import ensure_loaded, get_bundle, get_tokenizer, get_models
from app.services.sentinel_inference import _generate_for_model
from app.services.sentinel_schema import validate_sentinel_output
from app.services.prompt_service import build_analysis_prompt

status = ensure_loaded()
bundle = get_bundle()
tok = bundle.get("tokenizer") or get_tokenizer()
cfg = bundle.get("config") or {}
ms = get_models()
model_a = ms.get("a") or bundle.get("model_a")
model_b = ms.get("b") or bundle.get("model_b")
print(f"ready={status.ready} a={status.a} b={status.b} vocab={status.tokenizer_vocab_size} cfg_max_pos={cfg.get('max_position_embeddings')}")
cases = [
    ("greeting", "Hello!"),
    ("factual", "What is 2+2?"),
    ("benign_log", "2024-01-01 10:00:05 INFO 10.0.0.5 GET /api/posts 200 duration 12ms"),
    ("sqli", "2024-01-01 10:00:21 INFO GET /search?q=' UNION SELECT * FROM users-- 500"),
    ("traversal", "2024-01-01 10:00:22 INFO GET /download?file=../../etc/passwd 200"),
    ("brute_6", " | ".join(["2024-01-01 10:00:00 WARN 192.168.1.10 login failed 401"]*6)),
]
results=[]
for ckpt_name, model in [("A:sentinel_best_model.pt", model_a), ("B:best_autolab_checkpoint.pt", model_b)]:
    print(f"\n=== {ckpt_name} loaded={model is not None} ===")
    if model is None:
        continue
    for label, log_text in cases:
        prompt = build_analysis_prompt(log_text)
        enc = tok.encode(prompt)
        budget = max(64, cfg.get("max_position_embeddings",768) - 32 - 4)
        truncated = len(enc.ids) > budget
        t0=time.time()
        # use 32 tokens, timeout 20s to stay bounded
        res = _generate_for_model(model, tok, prompt, cfg, max_new_tokens=32, timeout_s=20)
        dt = int((time.time()-t0)*1000)
        text = res.get("text","") or ""
        raw = res.get("raw_text","") or ""
        v = validate_sentinel_output(text, res.get("status"))
        row = {
            "ckpt": ckpt_name, "label": label, "log_len": len(log_text),
            "prompt_ids": len(enc.ids), "truncated": truncated,
            "status": res.get("status"), "stopped": res.get("stopped"),
            "tokens": res.get("tokens"), "latency_ms": res.get("latency_ms"),
            "wall_ms": dt, "raw_len": len(raw), "text_len": len(text),
            "raw_preview": raw[:500], "text_preview": text[:800],
            "valid": v["valid"], "verdict": v["verdict"], "errors": v["errors"][:4],
        }
        results.append(row)
        # ascii-safe print
        print(f"[{label}] status={row['status']} stopped={row['stopped']} tokens={row['tokens']} valid={row['valid']} verdict={row['verdict']} text_len={row['text_len']}")
        if row["text_preview"]:
            print(f"  text: {row['text_preview'][:300]!r}")
        if row["raw_preview"] and row["raw_preview"]!=row["text_preview"]:
            print(f"  raw: {row['raw_preview'][:300]!r}")

path = root/"_phase2_quick_results.json"
path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"\nwrote {path} n={len(results)}")
# summary
for ckpt in ["A:sentinel_best_model.pt","B:best_autolab_checkpoint.pt"]:
    subset=[r for r in results if r["ckpt"]==ckpt]
    valid=sum(1 for r in subset if r["valid"])
    empty=sum(1 for r in subset if r["status"]=="empty")
    timeout=sum(1 for r in subset if r["status"]=="timeout")
    ok=sum(1 for r in subset if r["status"]=="ok")
    print(f"{ckpt}: valid {valid}/{len(subset)} empty {empty} timeout {timeout} ok {ok}")
