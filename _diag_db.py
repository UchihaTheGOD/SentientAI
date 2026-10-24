import pathlib, sqlite3, json
root = pathlib.Path(r"C:\Users\DARK\Desktop\wild clude\SentientAI")
db = root/"data"/"sentientai.db"
print("db", db.exists(), round(db.stat().st_size/1024/1024,2), "MB")
con = sqlite3.connect(str(db))
cur = con.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = [r[0] for r in cur.fetchall()]
print("tables", tables)
for t in tables:
    try:
        cur.execute(f'SELECT count(*) FROM "{t}"')
        print(f"  {t}: {cur.fetchone()[0]}")
    except Exception as e:
        print(t, e)
for t in tables:
    if "train" in t.lower() or "example" in t.lower() or "learn" in t.lower() or "candidate" in t.lower():
        print("---", t, "schema ---")
        cur.execute(f'PRAGMA table_info("{t}")')
        for row in cur.fetchall(): print(row)
        cur.execute(f'SELECT * FROM "{t}" LIMIT 2')
        cols=[d[0] for d in cur.description] if cur.description else []
        print("cols", cols)
        for r in cur.fetchall(): print({k:v for k,v in zip(cols,r)})
        if "train" in t.lower():
            try:
                cur.execute(f'SELECT status, safe_to_train, split, count(*) FROM "{t}" GROUP BY status, safe_to_train, split')
                print(cur.fetchall())
            except: pass
for t in ["sentinel_incidents","security_events","attact_assessments","attact_findings"]:
    if t in tables:
        cur.execute(f'SELECT count(*) FROM "{t}"')
        print(t, cur.fetchone()[0])
con.close()
