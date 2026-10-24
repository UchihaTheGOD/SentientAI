import json, sys, traceback, time
from pathlib import Path
BASE = Path(r"C:\Users\DARK\Desktop\wild clude\SentientAI")
sys.path.insert(0, str(BASE))
print("DIAG 1: tokenizer + config inspection")
try:
    from tokenizers import Tokenizer
    tok_path = BASE / "local_models" / "sentinel" / "sentinel_tokenizer.json"
    tok = Tokenizer.from_file(str(tok_path))
    vocab_size = tok.get_vocab_size()
    print(f"  vocab_size={vocab_size}")
    for s in ["<pad>","<unk>","<bos>","<eos>","<instruction>","<input>","<output>","</output>","</instruction>","</input>"]:
        print(f"    token {repr(s)} -> id={tok.token_to_id(s)}")
    enc = tok.encode("Hello, summarize this: The cat sat on the mat.")
    print(f"  encode synthetic: ids={enc.ids[:20]} len={len(enc.ids)} tokens={enc.tokens[:10]}")
    enc2 = tok.encode("<instruction>Test</instruction><input>Hello</input><output>")
    print(f"  encode training template: ids={enc2.ids} tokens={enc2.tokens}")
    from app.services.prompt_service import PROMPT_PATH, get_base_prompt, build_analysis_prompt
    bp = get_base_prompt()
    print(f"  base prompt chars={len(bp)} preview={repr(bp[:120])}")
    prompt = build_analysis_prompt("Hello, summarize this: The cat sat on the mat.", extra_prompt=None)
    print(f"  built prompt len={len(prompt)} chars, ends with <output>: {prompt.endswith('<output>')}")
    print(f"  prompt tail: {repr(prompt[-200:])}")
    enc3 = tok.encode(prompt)
    print(f"  prompt token len={len(enc3.ids)} within 768={len(enc3.ids) <= 768}")
except Exception as e:
    traceback.print_exc()

print("\nDIAG 2: sentinel_loader status + load attempt")
try:
    from app.services.sentinel_loader import get_status, ensure_loaded, get_bundle, get_models
    s = get_status()
    print(f"  pre-load status: ready={s.ready} a={s.a} b={s.b} reason={s.reason} vocab={s.tokenizer_vocab_size} rss={s.rss_mb}")
    cfg = s.config
    print(f"  config: {json.dumps(cfg, indent=2) if cfg else None}")
    print("  calling ensure_loaded() ...")
    t0=time.time()
    s2 = ensure_loaded()
    dt=int((time.time()-t0)*1000)
    print(f"  post-load status: ready={s2.ready} a={s2.a} b={s2.b} reason={s2.reason} load_ms_a={s2.load_ms_a} load_ms_b={s2.load_ms_b} rss={s2.rss_mb} dt={dt}ms")
    bundle=get_bundle()
    print(f"  bundle keys: {list(bundle.keys())} has_tokenizer={bundle.get('tokenizer') is not None} has_model_a={bundle.get('model_a') is not None} has_model_b={bundle.get('model_b') is not None}")
    ms=get_models()
    print(f"  models dict keys: {list(ms.keys())}")
except Exception as e:
    traceback.print_exc()
