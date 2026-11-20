#!/usr/bin/env bash
# SentientAI task runner (Linux/macOS counterpart of run.bat).
# Usage: ./run.sh <start|test|status|export|export-eval|backfill|help> [args]
# Paths are quoted via variables so project paths containing spaces work.
set -e
cd "$(dirname "$0")"

if [ -x ".venv/bin/python" ]; then
  PY=".venv/bin/python"
elif [ -x "venv/bin/python" ]; then
  PY="venv/bin/python"
else
  echo "[run] Python venv not found (.venv or venv)"
  echo "[run] Create it and install deps first:"
  echo "  python3 -m venv .venv"
  echo "  .venv/bin/python -m pip install -r requirements.txt -r requirements-dev.txt"
  exit 1
fi

CMD="${1:-help}"
case "$CMD" in
  start)
    echo "[run] Starting SentientAI at http://127.0.0.1:8000 (Ctrl+C to stop)"
    exec "$PY" run.py
    ;;
  test)
    shift
    exec "$PY" -m pytest "$@"
    ;;
  status)
    exec "$PY" -m app.cli training-status
    ;;
  export)
    mkdir -p data
    exec "$PY" -m app.cli export-training --out data/training_data.jsonl
    ;;
  export-eval)
    mkdir -p data
    exec "$PY" -m app.cli export-eval --out data/eval_data.jsonl
    ;;
  backfill)
    shift
    exec "$PY" -m app.cli score-backfill "$@"
    ;;
  *)
    echo "SentientAI tasks:"
    echo "  ./run.sh start         Start the app (http://127.0.0.1:8000)"
    echo "  ./run.sh test [args]   Run the pytest suite"
    echo "  ./run.sh status        Show training-pipeline counts"
    echo "  ./run.sh export        Export approved train split to data/training_data.jsonl"
    echo "  ./run.sh export-eval   Export approved eval split to data/eval_data.jsonl"
    echo "  ./run.sh backfill [--apply]  Band scored-but-unbanded candidates (dry run without --apply)"
    ;;
esac
