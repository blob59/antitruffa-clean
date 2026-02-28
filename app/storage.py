from __future__ import annotations
import os, json, time
from typing import Any, Dict

DATA_DIR = os.getenv("DATA_DIR", "/tmp")
REPORTS_PATH = os.path.join(DATA_DIR, "reports.jsonl")

def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)

def append_report(report: Dict[str, Any]) -> None:
    ensure_data_dir()
    report = dict(report)
    report["ts"] = int(time.time())
    with open(REPORTS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(report, ensure_ascii=False) + "\n")

def load_reports(max_lines: int = 5000):
    ensure_data_dir()
    if not os.path.exists(REPORTS_PATH):
        return []
    rows = []
    with open(REPORTS_PATH, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                break
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows
