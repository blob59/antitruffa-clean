from fastapi import FastAPI, Request, Form, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import re

app = FastAPI(title="AntiTruffa")

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# -----------------------------------
# NO CACHE
# -----------------------------------
def nocache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# -----------------------------------
# REGEX GLOBALI
# -----------------------------------
LINK_RE = re.compile(r"(https?://\S+|www\.\S+)", re.IGNORECASE)
IP_RE = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
RANDOM_DOMAIN_RE = re.compile(r"[a-z0-9]{8,}\.(us|xyz|top|click|fit|quest|tk|gq)")


# -----------------------------------
# LINK ANALYSIS
# -----------------------------------
def score_url(url: str):
    raw = (url or "").strip()
    display_url = raw

    if raw and not raw.lower().startswith(("http://", "https://")):
        raw = "https://" + raw

    try:
        p = urlparse(raw)
    except Exception:
        return 100, "Sembra phishing", ["URL non valido."], display_url

    host = (p.hostname or "").lower()
    reasons = []
    score = 0

    if not host:
        return 100, "Sembra phishing", ["Dominio non valido."], display_url

    if p.scheme != "https":
        score += 15
        reasons.append("Non usa HTTPS.")

    if IP_RE.fullmatch(host):
        score += 30
        reasons.append("Dominio è un indirizzo IP.")

    if host.count("-") >= 2:
        score += 10
        reasons.append("Molti trattini nel dominio.")

    if RANDOM_DOMAIN_RE.search(host):
        score += 35
        reasons.append("Dominio con pattern casuale sospetto.")

    if len(raw) > 90:
        score += 10
        reasons.append("URL molto lungo.")

    if score >= 50:
        verdict = "Sembra phishing"
    elif score >= 25:
        verdict = "Sospetto"
    else:
        verdict = "Probabilmente ok"

    if not reasons:
        reasons.append("Nessun segnale forte rilevato.")

    return score, verdict, reasons, display_url


# -----------------------------------
# SMS / TESTO ANALYSIS
# -----------------------------------
def score_text(message: str):
    txt = (message or "").strip()
    reasons = []
    score = 0

    if not txt:
        return 0, "Inserisci testo", ["Non hai incollato nulla."], []

    low = txt.lower()

    if LINK_RE.search(txt):
        score += 15
        reasons.append("Contiene link nel messaggio.")

    suspicious_words = [
        "urgente", "entro 24 ore", "account bloccato",
        "verifica", "password", "otp", "iban",
        "clicca subito", "ultimo avviso"
    ]

    hits = [w for w in suspicious_words if w in low]
    if hits:
        score += 5 * len(hits)
        reasons.append("Parole tipiche da truffa rilevate.")

    if score >= 50:
        verdict = "Molto sospetto"
    elif score >= 25:
        verdict = "Sospetto"
    else:
        verdict = "Probabilmente ok"

    if not reasons:
        reasons.append("Nessun segnale forte rilevato.")

    return min(score, 100), verdict, reasons, LINK_RE.findall(txt)


# -----------------------------------
# EMAIL ANALYSIS SERIA
# -----------------------------------
def score_email(email_text: str):
    txt = (email_text or "").strip()
    reasons = []
    score = 0

    if not txt:
        return 0, "Inserisci email", ["Non hai incollato nulla."], []

    low = txt.lower()

    # Estrazione email mittente
    email_pattern = re.search(r"<([^>]+)>", txt)
    sender_email = email_pattern.group(1).lower() if email_pattern else ""

    # Brand spoofing
    brands = ["conad", "amazon", "paypal", "poste", "inps"]
    for brand in brands:
        if brand in low and sender_email and brand not in sender_email:
            score += 45
            reasons.append(f"Il brand '{brand}' compare ma il dominio non è ufficiale.")

    # Dominio casuale
    if RANDOM_DOMAIN_RE.search(low):
        score += 35
        reasons.append("Dominio con pattern casuale sospetto.")

    # IP nel server
    if IP_RE.search(low):
        score += 25
        reasons.append("Server di invio con IP sospetto.")

    # Promo spam
    promo = ["gratis", "gratuito", "offerta", "ultima occasione", "riscatta", "premio"]
    if any(p in low for p in promo):
        score += 20
        reasons.append("Oggetto promozionale tipico da spam.")

    # Link
    links = LINK_RE.findall(txt)
    if links:
        score += 20
        reasons.append("Contiene link da verificare.")

    # Dati sensibili
    if any(x in low for x in ["password", "otp", "codice", "pin", "cvv", "iban"]):
        score += 25
        reasons.append("Possibile richiesta di dati sensibili.")

    if score >= 70:
        verdict = "Molto sospetta"
    elif score >= 40:
        verdict = "Sospetta"
    else:
        verdict = "Probabilmente ok"

    if not reasons:
        reasons.append("Nessun segnale forte rilevato.")

    return min(score, 100), verdict, reasons, links


# -----------------------------------
# ROUTES
# -----------------------------------
def base_context():
    return {
        "build_time": datetime.utcnow().isoformat(),
        "name": "Franco Ficara",
        "active": "link",
        "url_value": "",
        "text_value": "",
        "email_value": "",
        "result": None,
    }


@app.get("/", response_class=HTMLResponse)
async def home(request: Request, tab: str = Query("link")):
    ctx = base_context()
    ctx["request"] = request
    ctx["active"] = tab if tab in ("link", "text", "email") else "link"
    response = templates.TemplateResponse("index.html", ctx)
    return nocache(response)


@app.post("/check-link", response_class=HTMLResponse)
async def check_link(request: Request, url: str = Form(...)):
    score, verdict, reasons, display_url = score_url(url)

    ctx = base_context()
    ctx.update({
        "request": request,
        "active": "link",
        "url_value": display_url,
        "result": {"title": "Analisi Link", "verdict": verdict, "score": score, "reasons": reasons}
    })

    return nocache(templates.TemplateResponse("index.html", ctx))


@app.post("/check-text", response_class=HTMLResponse)
async def check_text(request: Request, message: str = Form(...)):
    score, verdict, reasons, links = score_text(message)

    ctx = base_context()
    ctx.update({
        "request": request,
        "active": "text",
        "text_value": message,
        "result": {"title": "Analisi SMS / Messaggio", "verdict": verdict, "score": score, "reasons": reasons, "links": links}
    })

    return nocache(templates.TemplateResponse("index.html", ctx))


@app.post("/check-email", response_class=HTMLResponse)
async def check_email(request: Request, email_text: str = Form(...)):
    score, verdict, reasons, links = score_email(email_text)

    ctx = base_context()
    ctx.update({
        "request": request,
        "active": "email",
        "email_value": email_text,
        "result": {"title": "Analisi Email", "verdict": verdict, "score": score, "reasons": reasons, "links": links}
    })

    return nocache(templates.TemplateResponse("index.html", ctx))


@app.get("/health")
async def health():
    return {"ok": True}
