from __future__ import annotations

import os
import re
import hashlib
from urllib.parse import urlparse
from datetime import datetime, timedelta
from typing import Any, Dict, List

from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.analyze_text import analyze_text
from app.analyze_image import analyze_image_bytes
from app.storage import append_report, load_reports

MAX_IMAGE_MB = int(os.getenv("MAX_IMAGE_MB", "10"))

app = FastAPI(title="AntiTruffa — Franco Ficara", version="1.1.0")
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# ---------------- Blacklist domini ----------------
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "live", "site", "icu", "monster", "tk", "gq", "cf", "ml", "ga"
}

DOMAIN_BLACKLIST = {
    "secure-banca-login.xyz",
    "secure-banca-verifica-login.xyz",
    "banca-verifica-login.xyz",
}

DOMAIN_KEYWORDS = {
    "login", "verify", "verifica", "secure", "security", "update", "aggiorna",
    "account", "auth", "bank", "banca"
}

def extract_domains_from_text(text: str) -> list[str]:
    text = text or ""
    urls = re.findall(r"https?://[^\s)>\]]+", text, flags=re.IGNORECASE)
    domains: list[str] = []
    for u in urls:
        try:
            p = urlparse(u)
            host = (p.netloc or "").lower()
            host = host.split("@")[-1]
            host = host.split(":")[0]
            host = host.lstrip("www.")
            if host:
                domains.append(host)
        except Exception:
            continue
    out: list[str] = []
    for d in domains:
        if d not in out:
            out.append(d)
    return out

def domain_is_suspicious(domain: str) -> tuple[bool, str]:
    d = (domain or "").lower().strip()
    if not d:
        return False, ""
    if d in DOMAIN_BLACKLIST:
        return True, "dominio in blacklist"
    parts = d.split(".")
    tld = parts[-1] if len(parts) >= 2 else ""
    if tld in SUSPICIOUS_TLDS:
        return True, f"TLD sospetto .{tld}"
    for kw in DOMAIN_KEYWORDS:
        if kw in d:
            return True, f"keyword sospetta: {kw}"
    return False, ""

# ---------------- Pagine ----------------
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/stats", response_class=HTMLResponse)
def stats_page(request: Request):
    data = stats_summary()
    return templates.TemplateResponse("stats.html", {"request": request, **data})

# ---------------- API ----------------
class TextRequest(BaseModel):
    text: str
    source: str | None = "other"

@app.post("/api/analyze/text")
def api_analyze_text(req: TextRequest):
    score, level, signals, category, advice = analyze_text(req.text)

    domains = extract_domains_from_text(req.text)
    phones: list[str] = []
    fp = hashlib.sha256((req.text or "").encode("utf-8")).hexdigest()[:16]

    suspicious_hits: list[str] = []
    for d in domains:
        ok, why = domain_is_suspicious(d)
        if ok:
            suspicious_hits.append(f"{d} ({why})")

    if suspicious_hits:
        score = min(100, score + 25)
        signals.append({
            "code": "DOMAIN_BLACKLIST_OR_SUSPICIOUS",
            "weight": 25,
            "evidence": " | ".join(suspicious_hits)[:240]
        })
        if score >= 70:
            level = "alto"
        elif score >= 30:
            level = "medio"
        category = "phishing_link"
        if advice and advice[0] != "Non cliccare il link.":
            advice = ["Non cliccare il link."] + advice

    return {
        "risk_score": score,
        "risk_level": level,
        "signals": signals,
        "advice": advice,
        "domains": domains,
        "phones": phones,
        "category": category,
        "fingerprint": fp,
    }

@app.post("/api/analyze/image")
async def api_analyze_image(file: UploadFile = File(...)):
    data = await file.read()
    if len(data) > MAX_IMAGE_MB * 1024 * 1024:
        return JSONResponse(
            status_code=413,
            content={"detail": f"File troppo grande (max {MAX_IMAGE_MB}MB)."}
        )
    score, level, signals, notes, exif_present, fp, category = analyze_image_bytes(data)
    return {
        "risk_score": score,
        "risk_level": level,
        "signals": signals,
        "notes": notes,
        "exif_present": exif_present,
        "fingerprint": fp,
        "category": category,
    }

class ReportRequest(BaseModel):
    type: str
    source: str | None = None
    category: str | None = None
    risk_score: int
    risk_level: str
    fingerprint: str
    signals: list = []
    domains: list[str] = []
    phones: list[str] = []

@app.post("/api/report")
def api_report(req: ReportRequest):
    rows = load_reports(max_lines=5000)
    cutoff = int((datetime.utcnow() - timedelta(days=7)).timestamp())

    for r in reversed(rows[-500:]):
        if r.get("ts", 0) < cutoff:
            break
        if r.get("fingerprint") == req.fingerprint:
            return {"ok": True, "dedup": True}

    append_report(req.model_dump())
    return {"ok": True, "dedup": False}

@app.get("/api/stats/summary")
def api_stats_summary():
    return stats_summary()

# ---------------- Statistiche ----------------
def stats_summary() -> Dict[str, Any]:
    since_days = 30
    since_ts = int((datetime.utcnow() - timedelta(days=since_days)).timestamp())
    rows = [r for r in load_reports(max_lines=5000) if r.get("ts", 0) >= since_ts]

    total = len(rows)
    by_level = {"basso": 0, "medio": 0, "alto": 0}
    by_type = {"text": 0, "image": 0}
    by_category: Dict[str, int] = {}
    signal_counts: Dict[str, int] = {}
    day_counts: Dict[str, int] = {}

    for r in rows:
        lvl = r.get("risk_level", "basso")
        typ = r.get("type", "text")
        by_level[lvl] = by_level.get(lvl, 0) + 1
        by_type[typ] = by_type.get(typ, 0) + 1

        cat = r.get("category") or ""
        if cat:
            by_category[cat] = by_category.get(cat, 0) + 1

        ts = r.get("ts", 0)
        day = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
        day_counts[day] = day_counts.get(day, 0) + 1

        for s in (r.get("signals") or []):
            code = s.get("code")
            if code:
                signal_counts[code] = signal_counts.get(code, 0) + 1

    top_signals = sorted(signal_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    top_categories = sorted(by_category.items(), key=lambda x: x[1], reverse=True)[:10]
    trend = [{"day": k, "count": day_counts[k]} for k in sorted(day_counts.keys())]

    return {
        "window_days": since_days,
        "total_reports": total,
        "by_level": by_level,
        "by_type": by_type,
        "top_categories": [{"category": c, "count": n} for c, n in top_categories],
        "top_signals": [{"signal": s, "count": n} for s, n in top_signals],
        "trend": trend,
    }
