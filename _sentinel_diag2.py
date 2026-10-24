import json, time, sys, pathlib, io
# force utf-8 stdout
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
root = pathlib.Path(r"C:\Users\DARK\Desktop\wild clude\SentientAI")
sys.path.insert(0, str(root))
from app.services.sentinel_loader import ensure_loaded, get_bundle, get_status, get_tokenizer, get_models
from app.services.sentinel_inference import _generate_for_model
from app.services.sentinel_schema import validate_sentinel_output
from app.services.prompt_service import build_analysis_prompt, get_base_prompt

status = ensure_loaded()
bundle = get_bundle()
tok = bundle.get("tokenizer") or get_tokenizer()
cfg = bundle.get("config") or {}
ms = get_models()
model_a = ms.get("a") or bundle.get("model_a")
model_b = ms.get("b") or bundle.get("model_b")
print(f"LOADER ready={status.ready} a={status.a} b={status.b} vocab={status.tokenizer_vocab_size} rss={status.rss_mb}MB")
print(f"cfg vocab={cfg.get('vocab_size')} max_pos={cfg.get('max_position_embeddings')} bos={cfg.get('bos_token_id')} eos={cfg.get('eos_token_id')} pad={cfg.get('pad_token_id')}")
print(f"tokenizer vocab_size={tok.get_vocab_size() if tok else 'none'}")
base = get_base_prompt()
print(f"base chars={len(base)}")
cases = [
    ("greeting", "Hello, how are you today?"),
    ("factual", "What is the capital of France?"),
    ("summarize", "Summarize: The user alice viewed SELECTION committee report and then logged out. What happened?"),
    ("benign_log", "2024-01-01 10:00:05 INFO 10.0.0.5 GET /api/posts 200 duration 12ms"),
    ("suspicious_log", " | ".join(["2024-01-01 10:00:00 WARN 192.168.1.10 login failed for user admin 401"]*6)),
    ("sentinel_structured", "2024-01-01 10:00:22 INFO GET /download?file=../../etc/passwd 200"),
]
out=[]
for ckpt_name, model in [("A:sentinel_best_model.pt", model_a), ("B:best_autolab_checkpoint.pt", model_b)]:
    print("\n"+"="*80)
    print(f"CHECKPOINT {ckpt_name} loaded={model is not None}")
    if model is None:
        continue
    for label, log_text in cases:
        prompt = build_analysis_prompt(log_text)
        enc = tok.encode(prompt)
        ids = enc.ids
        budget = max(64, cfg.get("max_position_embeddings",768) - 96 - 4)
        truncated = len(ids)>budget
        res = _generate_for_model(model, tok, prompt, cfg, max_new_tokens=96, timeout_s=14)
        raw = res.get("raw_text","")
        text = res.get("text","")
        v = validate_sentinel_output(text, res.get("status"))
        # sanitize for display
        def safe(s, n=400):
            s=s or ""
            s=s.replace("\n","\\n").replace("\r","")
            return s[:n]
        print(f"\n  [{label}] log_len={len(log_text)} prompt_ids={len(ids)} truncated={truncated}")
        print(f"    status={res.get('status')} stopped={res.get('stopped')} tokens={res.get('tokens')} latency={res.get('latency_ms')}ms")
        print(f"    raw_len={len(raw)} preview={safe(raw,300)!r}")
        print(f"    text_len={len(text)} preview={safe(text,400)!r}")
        print(f"    valid={v['valid']} verdict={v['verdict']} errors={v['errors'][:2]}")
        # logits inspect
        try:
            import torch
            bos=cfg.get("bos_token_id",2)
            eout=tok.token_to_id("<output>")
            ids2=enc.ids[:]
            if len(ids2)>budget:
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
                out2=model(cur)
                logits=out2["logits"][0,-1]
                topk=torch.topk(logits,5)
                vals=topk.values.tolist()
                idxs=topk.indices.tolist()
                toks=[tok.decode([i]) if 0<=i<tok.get_vocab_size() else f"<{i}>" for i in idxs]
                probs=torch.softmax(logits, dim=-1)
                ent=-(probs*torch.log(probs.clamp(min=1e-12))).sum().item()
                eos=cfg.get("eos_token_id",3); pad=cfg.get("pad_token_id",0)
                print(f"    TOP5: {list(zip(idxs, [safe(t,20) for t in toks], [round(float(v),2) for v in vals]))} entropy={ent:.3f} max_p={float(probs.max().item()):.4f} eos_p={float(probs[eos].item()):.4f} pad_p={float(probs[pad].item()):.4f}")
        except Exception as e:
            print(f"    logit err: {e}")
        out.append({"ckpt":ckpt_name,"label":label,"log_len":len(log_text),"prompt_ids":len(ids),"truncated":truncated,"status":res.get("status"),"stopped":res.get("stopped"),"tokens":res.get("tokens"),"latency_ms":res.get("latency_ms"),"raw_len":len(raw),"text_len":len(text),"valid":v["valid"],"verdict":v["verdict"],"errors":v["errors"]})
# write json
with open(root/"_sentinel_diag2_results.json","w",encoding="utf-8") as f:
    json.dump(out,f,indent=2,ensure_ascii=False)
print("\n=== wrote _sentinel_diag2_results.json ===")
# handcraft validator sanity
valid_example = "Summary: The log shows 6 failed logins from 192.168.1.10.\nInput status: valid\nIndicators:\n- 192.168.1.10\n- 6x login failed 401\nReasoning: Repeated failures indicate brute-force.\nProvisional assessment: likely_threat\nRecommendation: Block IP and review."
print("handcraft valid:", validate_sentinel_output(valid_example,"ok")["valid"])
