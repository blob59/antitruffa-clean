import json
import os
import re
import sqlite3
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel


app = FastAPI(title="AntiTruffa AI")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "reports.db")

os.makedirs(DATA_DIR, exist_ok=True)

templates = Jinja2Templates(directory=TEMPLATES_DIR)


# =========================
# MODELLI RICHIESTA
# =========================

class AnalyzeRequest(BaseModel):
    text: Optional[str] = None
    message: Optional[str] = None
    content: Optional[str] = None


class ReportRequest(BaseModel):
    text: Optional[str] = None
    fingerprint: Optional[str] = None
    score: Optional[int] = 0
    level: Optional[str] = "basso"
    category: Optional[str] = "Sconosciuta"


# =========================
# DATABASE
# =========================

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            original_text TEXT,
            score INTEGER,
            level TEXT,
            category TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


@app.on_event("startup")
def startup_event():
    init_db()


# =========================
# UTILS
# =========================

def now_iso():
    return datetime.utcnow().isoformat()


def get_input_text(payload: AnalyzeRequest) -> str:
    return (payload.text or payload.message or payload.content or "").strip()


def normalize_text(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"\s+", " ", text)
    return text


def make_fingerprint(text: str) -> str:
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()[:24]


def extract_urls(text: str) -> list[str]:
    pattern = r"(https?://[^\s]+|www\.[^\s]+)"
    found = re.findall(pattern, text, flags=re.IGNORECASE)
    cleaned = []
    for url in found:
        url = url.strip(".,;:!?()[]{}<>\"'")
        cleaned.append(url)
    return list(dict.fromkeys(cleaned))


def extract_domains(text: str) -> list[str]:
    urls = extract_urls(text)
    domains = []

    for url in urls:
        u = url.lower()
        u = re.sub(r"^https?://", "", u)
        u = re.sub(r"^www\.", "", u)
        domain = u.split("/")[0].split("?")[0].strip()
        if domain:
            domains.append(domain)

    # Cerca anche domini scritti senza http
    extra = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", text.lower())
    for d in extra:
        if d not in domains:
            domains.append(d)

    return list(dict.fromkeys(domains))


def extract_phones(text: str) -> list[str]:
    phones = re.findall(r"(?:\+?\d[\d\-\s]{7,}\d)", text)
    cleaned = []
    for p in phones:
        p = re.sub(r"\s+", " ", p).strip()
        if p not in cleaned:
            cleaned.append(p)
    return cleaned


def has_ip_url(urls: list[str]) -> bool:
    ip_pattern = r"(https?://)?(?:\d{1,3}\.){3}\d{1,3}"
    for url in urls:
        if re.search(ip_pattern, url):
            return True
    return False


def count_uppercase_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    upper = [c for c in letters if c.isupper()]
    return len(upper) / len(letters)


def detect_category(text: str) -> str:
    t = text.lower()

    if any(k in t for k in ["pacco", "corriere", "dogana", "spedizione", "consegna", "poste", "bartolini", "gls", "sda"]):
        return "Finto corriere"

    if any(k in t for k in ["banca", "conto", "iban", "postepay", "otp", "password", "spid", "agenzia entrate", "inps", "intesa", "paypal"]):
        return "Phishing credenziali"

    if any(k in t for k in ["bitcoin", "crypto", "criptovalute", "investimento", "trading", "guadagni garantiti"]):
        return "Investimento sospetto"

    if any(k in t for k in ["microsoft", "supporto tecnico", "teamviewer", "anydesk", "pc bloccato", "virus nel computer"]):
        return "Finto supporto tecnico"

    if any(k in t for k in ["lavoro da casa", "guadagno facile", "offerta di lavoro", "curriculum", "selezione urgente"]):
        return "Offerta di lavoro sospetta"

    return "Tentativo sospetto generico"


def detect_level(score: int) -> str:
    if score >= 70:
        return "alto"
    if score >= 40:
        return "medio"
    return "basso"


def safe_browsing_check(urls: list[str]) -> list[str]:
    api_key = os.getenv("SAFE_BROWSING_API_KEY", "").strip()
    if not api_key or not urls:
        return []

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "antitruffa-ai",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u if u.startswith("http") else f"http://{u}"} for u in urls]
        }
    }

    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
            matches = data.get("matches", [])
            bad_urls = []

            for match in matches:
                entry = match.get("threat", {})
                url = entry.get("url")
                if url and url not in bad_urls:
                    bad_urls.append(url)

            return bad_urls

    except Exception:
        return []


# =========================
# ANALISI TESTO
# =========================

def analyze_text(text: str) -> dict:
    text = (text or "").strip()

    if not text:
        return {
            "score": 0,
            "level": "basso",
            "signals": ["Nessun testo inserito."],
            "advice": ["Incolla un messaggio, un link o un SMS da controllare."],
            "domains": [],
            "phones": [],
            "category": "Nessun contenuto",
            "fingerprint": "",
            "urls": [],
            "threats": []
        }

    lower_text = text.lower()
    urls = extract_urls(text)
    domains = extract_domains(text)
    phones = extract_phones(text)
    category = detect_category(text)
    fingerprint = make_fingerprint(text)

    score = 0
    signals = []
    advice = []

    urgency_keywords = [
        "urgente", "subito", "immediato", "scade oggi", "entro oggi",
        "ultimo avviso", "verifica ora", "agisci subito", "bloccato"
    ]
    data_keywords = [
        "password", "otp", "iban", "cvv", "carta", "codice", "pin",
        "documento", "credenziali", "spid"
    ]
    lure_keywords = [
        "rimborso", "bonus", "premio", "vinto", "regalo", "offerta",
        "pacco", "consegna", "dogana", "investimento", "guadagno"
    ]
    platform_keywords = [
        "whatsapp", "telegram", "sms", "email", "paypal", "poste",
        "banca", "inps", "agenzia entrate"
    ]
    shorteners = [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"
    ]
    suspicious_tlds = [".xyz", ".top", ".click", ".shop", ".live", ".info", ".site"]

    found_urgency = [k for k in urgency_keywords if k in lower_text]
    found_data = [k for k in data_keywords if k in lower_text]
    found_lure = [k for k in lure_keywords if k in lower_text]
    found_platform = [k for k in platform_keywords if k in lower_text]

    if found_urgency:
        score += 20
        signals.append("Tono di urgenza o pressione psicologica.")

    if found_data:
        score += 25
        signals.append("Richiesta di dati sensibili o codici personali.")

    if found_lure:
        score += 15
        signals.append("Presenza di esche tipiche: premio, rimborso, consegna o guadagno facile.")

    if urls:
        score += 10
        signals.append("Sono presenti uno o più link nel testo.")

    if phones:
        score += 8
        signals.append("Sono presenti numeri telefonici da contattare.")

    if has_ip_url(urls):
        score += 20
        signals.append("Link con indirizzo IP invece di un dominio normale.")

    for d in domains:
        if any(short in d for short in shorteners):
            score += 15
            signals.append("Uso di link abbreviati, spesso usati per nascondere la destinazione reale.")
            break

    for d in domains:
        if any(d.endswith(tld) for tld in suspicious_tlds):
            score += 10
            signals.append("Dominio con estensione poco affidabile o insolita.")
            break

    if found_platform and found_data:
        score += 10
        signals.append("Finge di essere un servizio noto per rubare accessi o dati.")

    upper_ratio = count_uppercase_ratio(text)
    if upper_ratio > 0.35 and len(text) > 25:
        score += 5
        signals.append("Uso eccessivo di maiuscole, tipico dei messaggi aggressivi.")

    bad_urls = safe_browsing_check(urls)
    if bad_urls:
        score += 35
        signals.append("Uno o più link risultano segnalati come pericolosi dal controllo Safe Browsing.")

    score = min(score, 100)
    level = detect_level(score)

    advice.append("Non cliccare su link sospetti e non richiamare numeri presenti nel messaggio.")
    advice.append("Non fornire password, OTP, IBAN, dati carta o documenti.")
    advice.append("Verifica sempre dal sito ufficiale scritto a mano nel browser.")
    advice.append("Se il messaggio riguarda banca, corriere o ente pubblico, contatta solo i canali ufficiali.")
    if bad_urls:
        advice.append("Questo contenuto merita attenzione seria: uno o più link risultano potenzialmente pericolosi.")
    if score >= 70:
        advice.append("Probabile truffa: meglio bloccare, segnalare e cancellare.")
    elif score >= 40:
        advice.append("Messaggio dubbio: fermati e verifica prima di fare qualsiasi cosa.")

    return {
        "score": score,
        "level": level,
        "signals": list(dict.fromkeys(signals)),
        "advice": list(dict.fromkeys(advice)),
        "domains": domains,
        "phones": phones,
        "category": category,
        "fingerprint": fingerprint,
        "urls": urls,
        "threats": bad_urls
    }


# =========================
# REPORT / STATISTICHE
# =========================

def save_report_if_new(fingerprint: str, original_text: str, score: int, level: str, category: str) -> dict:
    conn = get_conn()
    cur = conn.cursor()

    limit_date = (datetime.utcnow() - timedelta(days=7)).isoformat()

    cur.execute(
        """
        SELECT id, created_at
        FROM reports
        WHERE fingerprint = ?
          AND created_at >= ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (fingerprint, limit_date)
    )
    existing = cur.fetchone()

    if existing:
        conn.close()
        return {
            "saved": False,
            "duplicate": True,
            "message": "Segnalazione già presente negli ultimi 7 giorni."
        }

    cur.execute(
        """
        INSERT INTO reports (fingerprint, original_text, score, level, category, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (fingerprint, original_text, score, level, category, now_iso())
    )
    conn.commit()
    conn.close()

    return {
        "saved": True,
        "duplicate": False,
        "message": "Segnalazione salvata con successo."
    }


def get_stats_data() -> dict:
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) AS total FROM reports")
    total = cur.fetchone()["total"]

    cur.execute("SELECT level, COUNT(*) AS c FROM reports GROUP BY level")
    by_level_rows = cur.fetchall()
    by_level = {row["level"]: row["c"] for row in by_level_rows}

    cur.execute("SELECT category, COUNT(*) AS c FROM reports GROUP BY category ORDER BY c DESC")
    by_category_rows = cur.fetchall()
    by_category = {row["category"]: row["c"] for row in by_category_rows}

    cur.execute(
        """
        SELECT fingerprint, score, level, category, created_at
        FROM reports
        ORDER BY created_at DESC
        LIMIT 20
        """
    )
    recent_rows = cur.fetchall()
    recent_reports = [dict(row) for row in recent_rows]

    conn.close()

    return {
        "total_reports": total,
        "by_level": by_level,
        "by_category": by_category,
        "recent_reports": recent_reports
    }


# =========================
# ROUTES HTML
# =========================

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    index_file = os.path.join(TEMPLATES_DIR, "index.html")
    if os.path.exists(index_file):
        return templates.TemplateResponse("index.html", {"request": request})

    return HTMLResponse(
        """
        <html>
        <head><title>AntiTruffa AI</title></head>
        <body style="font-family: Arial; padding: 40px;">
            <h1>AntiTruffa AI online</h1>
            <p>Il backend funziona, ma manca il file <b>app/templates/index.html</b>.</p>
        </body>
        </html>
        """
    )


@app.get("/stats", response_class=HTMLResponse)
def stats_page(request: Request):
    stats_file = os.path.join(TEMPLATES_DIR, "stats.html")
    data = get_stats_data()

    if os.path.exists(stats_file):
        return templates.TemplateResponse(
            "stats.html",
            {
                "request": request,
                "total_reports": data["total_reports"],
                "by_level": data["by_level"],
                "by_category": data["by_category"],
                "recent_reports": data["recent_reports"]
            }
        )

    return JSONResponse(data)


# =========================
# API
# =========================

@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/analyze")
@app.post("/analyze")
def analyze_api(payload: AnalyzeRequest):
    text = get_input_text(payload)
    result = analyze_text(text)
    return result


@app.post("/api/report")
@app.post("/report")
def report_api(payload: ReportRequest):
    text = (payload.text or "").strip()
    fingerprint = (payload.fingerprint or "").strip()

    if not fingerprint:
        if not text:
            return JSONResponse(
                status_code=400,
                content={"error": "Serve almeno text oppure fingerprint."}
            )
        fingerprint = make_fingerprint(text)

    result = save_report_if_new(
        fingerprint=fingerprint,
        original_text=text,
        score=int(payload.score or 0),
        level=str(payload.level or "basso"),
        category=str(payload.category or "Sconosciuta")
    )

    return {
        "ok": True,
        "fingerprint": fingerprint,
        **result
    }
