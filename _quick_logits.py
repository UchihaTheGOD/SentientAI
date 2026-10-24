import pathlib, json, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
root = pathlib.Path(r"C:\Users\DARK\Desktop\wild clude\SentientAI")
sys.path.insert(0, str(root))
from app.services.sentinel_loader import ensure_loaded, get_bundle, get_tokenizer, get_models
from app.services.prompt_service import build_analysis_prompt
import torch
status = ensure_loaded()
bundle = get_bundle()
tok = bundle.get("tokenizer") or get_tokenizer()
cfg = bundle.get("config") or {}
ms = get_models()
model_a = ms.get("a")
model_b = ms.get("b")
print(f"ready={status.ready} a={status.a} b={status.b} max_pos={cfg.get('max_position_embeddings')} vocab={cfg.get('vocab_size')}")
for name, model in [("A", model_a), ("B", model_b)]:
    if model is None: continue
    for label, log in [("benign","2024-01-01 10:00:05 INFO 10.0.0.5 GET /api/posts 200"),("sqli","2024-01-01 10:00:21 INFO GET /search?q=' UNION SELECT * FROM users-- 500"),("brute"," | ".join(["2024-01-01 10:00:00 WARN 192.168.1.10 login failed 401"]*6))]:
        prompt = build_analysis_prompt(log)
        enc = tok.encode(prompt)
        ids = enc.ids
        bos=cfg.get("bos_token_id",2); eos=cfg.get("eos_token_id",3); pad=cfg.get("pad_token_id",0)
        eout=tok.token_to_id("<output>")
        budget=max(64,768-32-4)
        if len(ids)>budget:
            if ids[-1]==eout: ids=ids[:budget-8]+ids[-8:]
            else: ids=ids[-budget:]
        input_ids=[bos]+ids
        if len(input_ids)>768: input_ids=input_ids[-768:]
        print(f"\n[{name} {label}] prompt_ids={len(enc.ids)} used={len(input_ids)} log_len={len(log)}")
        with torch.inference_mode():
            cur=torch.tensor([input_ids[-768:]], dtype=torch.long)
            out=model(cur)
            logits=out["logits"][0,-1]
            probs=torch.softmax(logits, dim=-1)
            topk=torch.topk(logits,5)
            vals=topk.values.tolist(); idxs=topk.indices.tolist()
            toks=[tok.decode([i]) if 0<=i<tok.get_vocab_size() else f"<{i}>" for i in idxs]
            ent=-(probs*torch.log(probs.clamp(min=1e-12))).sum().item()
            print(f"  top5 ids={idxs} toks={[t[:20].replace(chr(10),'\\n') for t in toks]} vals={[round(float(v),2) for v in vals]} ent={ent:.2f} max_p={float(probs.max().item()):.4f}")
            print(f"  eos_logit={float(logits[eos]):.2f} eos_p={float(probs[eos]):.4f} pad_p={float(probs[pad]):.4f} eout_p={float(probs[eout]):.4f}")
        # tiny greedy 4 steps
        generated=input_ids[:]
        for step in range(4):
            with torch.inference_mode():
                cur=torch.tensor([generated[-768:]], dtype=torch.long)
                nxt=int(model(cur)["logits"][0,-1].argmax().item())
            generated.append(nxt)
            print(f"  step{step+1} nxt={nxt} tok={tok.decode([nxt])[:30]!r}")
            if nxt in (eos,pad,eout): break
        tail=generated[len(input_ids):]
        print(f"  tail_ids={tail} decode={tok.decode(tail)[:200]!r}")
print("done")
