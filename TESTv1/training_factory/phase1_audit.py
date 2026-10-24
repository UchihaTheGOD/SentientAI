import pathlib, json, hashlib, sqlite3, sys
ROOT = pathlib.Path(r"C:\Users\DARK\Desktop\wild clude\SentientAI")
print("=== PHASE 1 AUDIT ===")
print("config.json:", (ROOT/"local_models/sentinel/config.json").read_text()[:800])
import torch
print("torch", torch.__version__, "cuda", torch.cuda.is_available())
ckpt = torch.load(str(ROOT/"local_models/sentinel/sentinel_best_model.pt"), map_location="cpu", weights_only=False)
print("ckpt keys", list(ckpt.keys()))
print("epoch", ckpt.get("epoch"), "step", ckpt.get("global_step"), "val_loss", ckpt.get("best_val_loss"))
print("training_config", ckpt.get("training_config"))
sd = ckpt["model_state_dict"]
print("params", sum(p.numel() for p in sd.values()))
# also check B
import pathlib as pl
b = ROOT/"local_models/sentinel/best_autolab_checkpoint.pt"
if b.exists():
    ck2 = torch.load(str(b), map_location="cpu", weights_only=False)
    print("B epoch", ck2.get("epoch"), "val_loss", ck2.get("best_val_loss"))
    print("B params", sum(p.numel() for p in ck2["model_state_dict"].values()))
# tokenizer
tokj = json.loads((ROOT/"local_models/sentinel/sentinel_tokenizer.json").read_text())
print("added_tokens", tokj.get("added_tokens")[:12])
# prompt
print("prompt head", (ROOT/"prompts/prompt.txt").read_text()[:500].replace("\n"," | "))
# db
try:
    con = sqlite3.connect(str(ROOT/"data/sentientai.db"))
    cur = con.cursor()
    cur.execute("select status, count(*) from training_examples group by status")
    print("db status counts", cur.fetchall())
    cur.execute("select count(*) from training_examples")
    print("total rows", cur.fetchone()[0])
    con.close()
except Exception as e:
    print("db err", e)
# disk
import shutil
free = shutil.disk_usage(str(ROOT)).free // 1024 // 1024
print("disk free MB", free)
# evaluation latest
import json as j
latest = ROOT/"evaluation/latest.json"
if latest.exists():
    d=j.loads(latest.read_text())
    print("eval n_cases", d["meta"]["n_cases"], "metrics keys", list(d.get("metrics",{}).keys())[:6])
    print("rules sample", d["cases"][0]["rules"])
else:
    print("no evaluation/latest.json")
