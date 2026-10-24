#!/usr/bin/env python3
"""Smallest genuine weight-update smoke test.
- Loads SentinelModel + tokenizer (CPU)
- Builds 4 synthetic examples in the real <instruction>/<input>/<output> format
- Runs forward -> loss -> backward -> optimizer step on CPU
- Verifies params changed, grads non-zero, checkpoint saved and reloadable
- No dataset download, no Kaggle push, no overwrite of local_models/sentinel/*
"""
import pathlib, json, hashlib, time, sys
ROOT = pathlib.Path(r"C:\Users\DARK\Desktop\wild clude\SentientAI")
sys.path.insert(0, str(ROOT))
from tokenizers import Tokenizer
import torch
from config import SentinelConfig
from sentinel_model import SentinelModel

tok_path = ROOT / "local_models/sentinel/sentinel_tokenizer.json"
ckpt_path = ROOT / "local_models/sentinel/sentinel_best_model.pt"
prompt = (ROOT / "prompts/prompt.txt").read_text(encoding="utf-8")
tok = Tokenizer.from_file(str(tok_path))
cfg = SentinelConfig()

# 4 tiny examples covering the moderation contract shape
examples = [
    ("2024-01-01 10:00:00 INFO user alice GET /index.html 200", "likely_benign"),
    ("2024-01-01 10:00:01 WARN 192.168.1.5 GET /login 401 repeated 12 times then 200", "likely_threat"),
    ("2024-01-01 10:00:02 INFO GET /search?q=<script>alert(1)</script> 200", "needs_review"),
    ("2024-01-01 10:00:03 INFO GET /../../../etc/passwd 400", "needs_review"),
]

def render(instruction, log, label):
    # Real app render: instruction block + input block + output block
    return f"<instruction>{instruction}</instruction><input>{log}</input><output>{label}</output>"

instruction = prompt.strip()[:600]  # keep under max_pos budget
texts = [render(instruction, log, lab) for log, lab in examples]
# Encode with BOS/EOS handling like sentinel_inference does
pad_id = cfg.pad_token_id
bos_id = cfg.bos_token_id
eos_id = cfg.eos_token_id

def encode(s):
    ids = tok.encode(s).ids
    # Truncate to max_pos budget preserving tail <output> is not needed for this tiny set, but respect max_pos
    max_pos = cfg.max_position_embeddings
    if len(ids) + 1 > max_pos:  # +1 for BOS
        ids = ids[-(max_pos-1):]
    ids = [bos_id] + ids  # inference prepends BOS; training code in checkpoints used same
    # pad to max length in batch
    return ids

encoded = [encode(t) for t in texts]
max_len = max(len(x) for x in encoded)
input_ids = torch.tensor([x + [pad_id]*(max_len-len(x)) for x in encoded], dtype=torch.long)
labels = input_ids.clone()  # causal LM: predict next token; pad masked via ignore_index

print(f"tok vocab {tok.get_vocab_size()} pad {pad_id} bos {bos_id} eos {eos_id}")
print(f"batch {input_ids.shape} max_len {max_len} max_pos {cfg.max_position_embeddings}")
print(f"sample ids[:12] {encoded[0][:12]}")

# Load model from original checkpoint (never overwrite it)
model = SentinelModel(cfg)
sd = torch.load(str(ckpt_path), map_location="cpu", weights_only=False)["model_state_dict"]
model.load_state_dict(sd, strict=True)
model.train()

# Snapshot one param before step
with torch.no_grad():
    before = {k: v.clone() for k, v in model.named_parameters()}
    # pick a single weight for diff reporting
    sample_key = "transformer.layers.0.self_attn.in_proj_weight" if "transformer.layers.0.self_attn.in_proj_weight" in dict(model.named_parameters()) else list(dict(model.named_parameters()).keys())[0]
    before_sample = dict(model.named_parameters())[sample_key].clone()
print(f"sample param {sample_key} mean {before_sample.mean().item():.6f} std {before_sample.std().item():.6f}")

opt = torch.optim.AdamW(model.parameters(), lr=1e-4, weight_decay=0.01)

# Forward
out = model(input_ids, labels=labels)
loss0 = out["loss"]
print(f"loss before step: {loss0.item():.6f}")
assert torch.isfinite(loss0).item(), "non-finite loss"

# Backward
opt.zero_grad()
loss0.backward()
grad_norm = sum(p.grad.norm().item()**2 for p in model.parameters() if p.grad is not None)**0.5
print(f"grad_norm {grad_norm:.6f}")
assert grad_norm > 0, "zero grad"

opt.step()

# Verify params changed
after_sample = dict(model.named_parameters())[sample_key]
delta = (after_sample - before_sample).abs().max().item()
mean_delta = (after_sample - before_sample).abs().mean().item()
print(f"param delta max {delta:.8f} mean {mean_delta:.8f} after mean {after_sample.mean().item():.6f}")
assert delta > 1e-8, "params did not update"

# Second forward should change loss (not necessarily down on 1 step, but finite and different)
out2 = model(input_ids, labels=labels)
loss1 = out2["loss"]
print(f"loss after 1 step: {loss1.item():.6f} delta {loss1.item()-loss0.item():+.6f}")

# Save reloadable checkpoint under training_factory (never touches local_models/sentinel/)
ts = time.strftime("%Y%m%d_%H%M%S")
ckpt_out = ROOT / f"TESTv1/training_factory/checkpoints/smoke_{ts}.pt"
ckpt_out.parent.mkdir(parents=True, exist_ok=True)
torch.save({
    "model_state_dict": model.state_dict(),
    "optimizer_state_dict": opt.state_dict(),
    "epoch": 1,
    "global_step": 1,
    "best_val_loss": float(loss1.item()),
    "config": cfg.__dict__,
    "training_config": {"lr": 1e-4, "batch": len(examples), "max_length": max_len, "smoke": True},
    "provenance": {"base": str(ckpt_path), "examples": len(examples)},
}, str(ckpt_out))
print(f"saved {ckpt_out} {ckpt_out.stat().st_size} bytes")

# Reload check
sd2 = torch.load(str(ckpt_out), map_location="cpu", weights_only=False)["model_state_dict"]
model2 = SentinelModel(cfg)
model2.load_state_dict(sd2, strict=True)
model2.eval()
# verify one param matches saved
reloaded_sample = dict(model2.named_parameters())[sample_key]
assert torch.allclose(reloaded_sample, after_sample, atol=1e-6), "reload mismatch"
print(f"reload OK {sample_key} matches")

# Quick generation sanity: does model produce non-empty after this 1-step update?
# Use inference helper's truncation logic minimally — just check decode works
with torch.inference_mode():
    test_ids = torch.tensor([encode(render(instruction, "2024-01-01 12:00:00 INFO GET /admin 200", ""))], dtype=torch.long)
    # generate 8 tokens greedily
    cur = test_ids
    gens = []
    for _ in range(8):
        logits = model2(cur)["logits"][0, -1]
        nxt = int(logits.argmax().item())
        if nxt in (eos_id, pad_id):
            break
        gens.append(nxt)
        cur = torch.cat([cur, torch.tensor([[nxt]], dtype=torch.long)], dim=1)[:, -cfg.max_position_embeddings:]
    decoded = tok.decode(gens) if gens else ""
    safe = decoded[:120].encode('ascii','backslashreplace').decode('ascii')
    print(f"generation probe: {len(gens)} tokens decoded='{safe}' raw ids {gens[:8]}")

# Write log under training_factory/logs
log_path = ROOT / f"TESTv1/training_factory/logs/smoke_{ts}.json"
log_path.parent.mkdir(parents=True, exist_ok=True)
log_path.write_text(json.dumps({
    "ts": ts,
    "loss_before": float(loss0.item()),
    "loss_after": float(loss1.item()),
    "grad_norm": float(grad_norm),
    "param_delta_max": float(delta),
    "param_delta_mean": float(mean_delta),
    "checkpoint": str(ckpt_out),
    "reload_ok": True,
    "generation_tokens": len(gens),
    "generation_text": decoded[:500],
}, indent=2), encoding="utf-8")
print(f"logged {log_path}")
print("SMOKE PASS")
