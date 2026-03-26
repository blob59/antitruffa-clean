from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# =========================================================
# ANTI TRUFFA BY FRANCO FICARA — MAIN.PY COMPLETO
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
REPORTS_PATH = DATA_DIR / "reports.jsonl"

DATA_DIR.mkdir(parents=True, exist_ok=True)
STATIC_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="AntiTruffa by Franco Ficara")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# =========================================================
# MODELLI INPUT
# =========================================================
class AnalyzeRequest(BaseModel):
    text: str
    category: str | None = "auto"


class ReportRequest(BaseModel):
    type: str | None = "altro"
    source: str | None = ""
    content: str


# =========================================================
# FUNZIONI UTILI
# =========================================================
def normalize_space(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def extract_domains(text: str) -> list[str]:
    pattern = re.compile(r"(?:https?://)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")
    domains = []
    for match in pattern.finditer(text):
        domain = match.group(1).lower()
        if domain not in domains:
            domains.append(domain)
    return domains


def extract_phones(text: str) -> list[str]:
    pattern = re.compile(r"(?:\+?39\s?)?(?:\d[\s.-]?){7,}")
    phones = []
    for match in pattern.finditer(text):
        phone = re.sub(r"\D", "", match.group(0))
        if 7 <= len(phone) <= 15 and phone not in phones:
            phones.append(phone)
    return phones


def guess_category(text: str) -> str:
    lower = text.lower()
    if re.search(r"https?://|www\.", lower):
        return "link"
    if "@" in lower:
        return "email"
    if extract_phones(text):
        return "numero"
    return "messaggio"


def make_fingerprint(text: str) -> str:
    clean = normalize_space(text.lower())
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()[:16]


def append_report(report: dict[str, Any]) -> None:
    ensure_data_dir()
    row = dict(report)
    row["ts"] = int(time.time())
    with REPORTS_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_reports() -> list[dict[str, Any]]:
    if not REPORTS_PATH.exists():
        return []

    rows: list[dict[str, Any]] = []
    with REPORTS_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


# =========================================================
# MOTORE ANALISI
# =========================================================
SUSPICIOUS_RULES: list[dict[str, Any]] = [
    {
        "pattern": r"\b(otp|one time password|codice otp|pin|password|cvv)\b",
        "score": 28,
        "signal": "Richiesta o riferimento a credenziali sensibili",
    },
    {
        "pattern": r"\b(urgente|subito|immediatamente|entro oggi|ultimo avviso|azione richiesta)\b",
        "score": 18,
        "signal": "Pressione psicologica o urgenza artificiale",
    },
    {
        "pattern": r"\b(verifica|aggiorna i dati|conferma i dati|clicca qui|accedi ora|riattiva)\b",
        "score": 18,
        "signal": "Invito a cliccare o confermare dati personali",
    },
    {
        "pattern": r"\b(conto|banca|bonifico|pagamento sospeso|poste|agenzia entrate|inps)\b",
        "score": 12,
        "signal": "Tema economico o istituzionale usato spesso nelle truffe",
    },
    {
        "pattern": r"\b(vinto|premio|rimborso|bonus|regalo|gift card|buono)\b",
        "score": 14,
        "signal": "Promessa di guadagno o vantaggio facile",
    },
    {
        "pattern": r"\b(documento|carta d'identità|iban|carta di credito|documenti)\b",
        "score": 20,
        "signal": "Possibile richiesta di dati personali o bancari",
    },
    {
        "pattern": r"https?://|www\.",
        "score": 10,
        "signal": "Presenza di link da controllare con attenzione",
    },
    {
        "pattern": r"\b(whatsapp|telegram|chat privata)\b",
        "score": 8,
        "signal": "Tentativo di spostare la conversazione su canali rapidi",
    },
]


SAFE_HINTS = [
    r"\b(promemoria appuntamento)\b",
    r"\b(ci vediamo domani)\b",
    r"\b(grazie|buona giornata)\b",
]


def analyze_text(text: str, forced_category: str | None = "auto") -> dict[str, Any]:
    original = text.strip()
    clean = normalize_space(original)
    lower = clean.lower()

    score = 5
    signals: list[str] = []

    for rule in SUSPICIOUS_RULES:
        if re.search(rule["pattern"], lower, flags=re.IGNORECASE):
            score += int(rule["score"])
            signal = str(rule["signal"])
            if signal not in signals:
                signals.append(signal)

    for safe_rule in SAFE_HINTS:
        if re.search(safe_rule, lower, flags=re.IGNORECASE):
            score -= 8

    domains = extract_domains(clean)
    phones = extract_phones(clean)

    suspicious_domains: list[str] = []
    for domain in domains:
        if (
            re.search(r"login|verify|secure|bonus|gift|promo|bank|support", domain, re.IGNORECASE)
            or domain.count(".") >= 2
            or re.search(r"[0-9]{3,}", domain)
        ):
            suspicious_domains.append(domain)

    if suspicious_domains:
        score += 18
        signals.append("Dominio con caratteristiche sospette o imitazione possibile")

    if phones:
        score += 4

    category = guess_category(clean) if not forced_category or forced_category == "auto" else forced_category
    score = max(0, min(100, score))

    if score >= 70:
        level = "pericolo"
        simple_explanation = (
            "Questo contenuto mostra diversi segnali tipici di una possibile truffa: urgenza, richieste anomale, "
            "link dubbi o riferimenti a dati sensibili."
        )
        advice = [
            "Non cliccare su link o allegati.",
            "Non inviare password, PIN, OTP o documenti.",
            "Contatta l’ente o l’azienda usando solo il sito o il numero ufficiale.",
        ]
    elif score >= 35:
        level = "attenzione"
        simple_explanation = (
            "Il contenuto non è automaticamente una truffa certa, ma contiene elementi sospetti che meritano verifica prima di fidarti."
        )
        advice = [
            "Verifica mittente, numero o dominio con una fonte ufficiale.",
            "Non fornire dati personali finché non hai conferme.",
            "Se il tono è troppo urgente, fermati e ricontrolla.",
        ]
    else:
        level = "sicuro"
        simple_explanation = (
            "Non emergono segnali forti di truffa, ma conviene comunque mantenere prudenza e controllare sempre il contesto."
        )
        advice = [
            "Controlla comunque mittente e contesto.",
            "Evita di condividere dati sensibili se non necessario.",
            "Se qualcosa non torna, verifica con il canale ufficiale.",
        ]

    return {
        "score": score,
        "level": level,
        "signals": signals,
        "advice": advice,
        "domains": domains,
        "phones": phones,
        "category": category,
        "simple_explanation": simple_explanation,
        "fingerprint": make_fingerprint(clean),
    }


# =========================================================
# ROUTES PAGINE
# =========================================================
@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/stats")
async def stats() -> dict[str, Any]:
    reports = load_reports()
    total_reports = len(reports)

    by_type: dict[str, int] = {}
    recent_fingerprints: list[str] = []
    now_ts = int(time.time())
    seven_days = 7 * 24 * 60 * 60

    for item in reports:
        key = str(item.get("type", "altro"))
        by_type[key] = by_type.get(key, 0) + 1

        ts = int(item.get("ts", 0))
        if now_ts - ts <= seven_days:
            fp = item.get("fingerprint")
            if fp:
                recent_fingerprints.append(str(fp))

    unique_recent_fingerprints = len(set(recent_fingerprints))

    return {
        "total_reports": total_reports,
        "by_type": by_type,
        "unique_recent_fingerprints": unique_recent_fingerprints,
    }


# =========================================================
# API ANALISI
# =========================================================
@app.post("/api/analyze")
async def api_analyze(payload: AnalyzeRequest) -> JSONResponse:
    text = payload.text.strip()
    if not text:
        return JSONResponse(
            status_code=400,
            content={"error": "Inserisci un messaggio, un link o un numero da analizzare."},
        )

    result = analyze_text(text, payload.category)
    return JSONResponse(content=result)


# =========================================================
# API REPORT
# =========================================================
@app.post("/api/report")
async def api_report(payload: ReportRequest) -> JSONResponse:
    content = payload.content.strip()
    if not content:
        return JSONResponse(
            status_code=400,
            content={"error": "Il contenuto della segnalazione è vuoto."},
        )

    analysis = analyze_text(content, payload.type)
    fingerprint = analysis["fingerprint"]

    reports = load_reports()
    now_ts = int(time.time())
    seven_days = 7 * 24 * 60 * 60

    for row in reports:
        ts = int(row.get("ts", 0))
        if row.get("fingerprint") == fingerprint and now_ts - ts <= seven_days:
            return JSONResponse(
                content={
                    "ok": True,
                    "message": "Segnalazione già presente di recente.",
                    "fingerprint": fingerprint,
                    "duplicate": True,
                }
            )

    report = {
        "type": payload.type or "altro",
        "source": (payload.source or "").strip(),
        "content": content,
        "fingerprint": fingerprint,
        "score": analysis["score"],
        "level": analysis["level"],
        "category": analysis["category"],
        "domains": analysis["domains"],
        "phones": analysis["phones"],
    }
    append_report(report)

    return JSONResponse(
        content={
            "ok": True,
            "message": "Segnalazione salvata correttamente.",
            "fingerprint": fingerprint,
            "duplicate": False,
        }
    )


# =========================================================
# AVVIO LOCALE
# =========================================================
if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
