import json
import os
from datetime import datetime
from typing import Any, Dict, List

# Su Railway è più sicuro scrivere in /tmp (sempre scrivibile)
DATA_PATH = os.getenv("ANTITRUFFA_DATA_PATH", "/tmp/antitruffa_reports.json")

def load_reports() -> List[Dict[str, Any]]:
    try:
        if not os.path.exists(DATA_PATH):
            return []
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        # Se qualcosa va storto, non deve mai far crashare l'app
        return []

def append_report(report: Dict[str, Any]) -> None:
    try:
        reports = load_reports()
        report = dict(report)
        report["ts"] = report.get("ts") or datetime.utcnow().isoformat() + "Z"
        reports.append(report)
        with open(DATA_PATH, "w", encoding="utf-8") as f:
            json.dump(reports, f, ensure_ascii=False, indent=2)
    except Exception:
        # Non bloccare mai la verifica per colpa dello storage
        pass
