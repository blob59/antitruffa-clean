from fastapi import FastAPI, Request, Form
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


# -----------------------------
# Utility: no-cache
# -----------------------------
def nocache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# -----------------------------
# URL check (euristiche)
# -----------------------------
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
    "rebrand.ly", "buff.ly", "rb.gy", "shorturl.at"
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "account", "secure", "security", "update",
    "password", "reset", "confirm", "billing", "invoice", "payment", "wallet",
    "bank", "support", "helpdesk", "session", "locked", "unlock"
]

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "fit", "quest", "country", "tk", "gq"
}

BRAND_BAIT = [
    "paypal", "poste", "postepay", "amazon", "apple", "microsoft", "google",
    "facebook", "instagram", "whatsapp", "inps", "agenziaentrate", "netflix",
    "booking", "banca", "intesa", "unicredit", "tim", "vodafone"
]

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def score_url(url: str):
    raw = (url or "").strip()
    display_url = raw

    if raw and not raw.lower().startswith(("http://", "https://")):
        raw = "https://" + raw

    try:
        p = urlparse(raw)
    except Exception:
        return 100, "Sembra phishing", ["URL non valido o non interpretabile."], display_url

    host = (p.hostname or "").lower()
    path = (p.path or "").lower()
    query = (p.query or "").lower()

    reasons = []
    score = 0

    if not host:
        return 100, "Sembra phishing", ["Manca il dominio nell’URL."], display_url

    if p.scheme != "https":
        score += 15
        reasons.append("Non usa HTTPS (http invece di https).")

    if "@" in (p.netloc or ""):
        score += 25
        reasons.append("Contiene '@' nel dominio (mascheramento tipico).")

    if IPV4_RE.match(host):
        score += 30
        reasons.append("Il dominio è un indirizzo IP (molto sospetto).")

    if host.startswith("xn--") or "xn--" in host:
        score += 20
        reasons.append("Dominio in punycode (possibile dominio “falso”).")

    parts = host.split(".")
    if len(parts) >= 4:
        score += 15
        reasons.append("Troppi sottodomini (spesso usati per imitare siti famosi).")

    if host.count("-") >= 2:
        score += 10
        reasons.append("Molti trattini nel dominio (pattern da phishing).")

    if len(raw) > 90:
        score += 10
        reasons.append("URL molto lungo (può nascondere la destinazione).")

    if host in SHORTENERS:
        score += 20
        reasons.append("È un link accorciato (non vedi dove porta davvero).")

    text = f"{host}/{path}?{query}"
    kw_hits = [k for k in SUSPICIOUS_KEYWORDS if k in text]
    if kw_hits:
        score += min(25, 5 * len(kw_hits))
        reasons.append(f"Parole tipiche da phishing nel link: {', '.join(sorted(set(kw_hits)))}.")

    tld = parts[-1] if parts else ""
    if tld in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"Estensione sospetta: .{tld}")

    bait_hits = [b for b in BRAND_BAIT if b in host]
    if bait_hits:
        score += 15
        reasons.append(
            f"Nel dominio compare un nome “esca” ({', '.join(sorted(set(bait_hits)))}): occhio ai falsi."
        )

    if score >= 45:
        verdict = "Sembra phishing"
    elif score >= 20:
        verdict = "Sospetto"
    else:
        verdict = "Probabilmente ok (ma verifica comunque)"

    if not reasons:
        reasons.append("Nessun segnale forte rilevato, ma controlla sempre dominio e mittente.")

    return score, verdict, reasons, display_url


# -----------------------------
# TESTO/SMS check (euristiche)
# -----------------------------
TEXT_RED_FLAGS = [
    "urgente", "entro 24 ore", "entro 12 ore", "subito", "immediato", "adesso",
    "account bloccato", "account sospeso", "verifica il tuo account", "conferma i tuoi dati",
    "password", "codice otp", "codice di verifica", "pin", "iban", "carta", "cvv",
    "pagamento non riuscito", "rimborso", "fattura", "sanzione", "multa", "agenzia delle entrate",
    "inps", "poste", "postepay", "paypal", "amazon", "supporto", "assistenza"
]

THREAT_PHRASES = [
    "verrà chiuso", "verrà sospeso", "ultimatum", "pena", "sanzione",
    "azione legale", "se non", "evita il blocco", "ultimo avviso"
]

LINK_RE = re.compile(r"(https?://\S+|www\.\S+)", re.IGNORECASE)


def score_text(message: str):
    msg = (message or "").strip()
    reasons = []
    score = 0

    if not msg:
        return 0, "Inserisci un testo", ["Non hai incollato nulla."], []

    low = msg.lower()

    # Link dentro il testo
    links = LINK_RE.findall(msg)
    if links:
        score += 15
        reasons.append(f"Contiene {len(links)} link nel messaggio (spesso usati per portarti fuori).")

    hits = [k for k in TEXT_RED_FLAGS if k in low]
    if hits:
        score += min(45, 5 * len(hits))
        reasons.append(f"Parole/temi tipici da truffa: {', '.join(sorted(set(hits)))}.")

    threats = [t for t in THREAT_PHRASES if t in low]
    if threats:
        score += min(25, 10 * len(threats))
        reasons.append("Tono minaccioso/ultimatum per farti agire di fretta.")

    # Se chiede dati sensibili
    if any(x in low for x in ["password", "otp", "codice", "pin", "cvv", "iban"]):
        score += 20
        reasons.append("Richiesta possibile di dati sensibili (password/codici/IBAN).")

    if score >= 60:
        verdict = "Molto sospetto"
    elif score >= 30:
        verdict = "Sospetto"
    else:
        verdict = "Probabilmente ok (ma attenzione)"

    if not reasons:
        reasons.append("Nessun segnale forte rilevato, ma controlla sempre mittente e contesto.")

    return min(score, 100), verdict, reasons, links


# -----------------------------
# EMAIL check (base)
# -----------------------------
EMAIL_HINTS = [
    "from:", "da:", "subject:", "oggetto:", "reply-to", "rispondi a", "unsubscribe", "disiscriviti"
]


def score_email(email_text: str):
    txt = (email_text or "").strip()
    reasons = []
    score = 0

    if not txt:
        return 0, "Inserisci una email", ["Non hai incollato nulla."], []

    low = txt.lower()

    # Se sembra proprio una email (header)
    if any(h in low for h in EMAIL_HINTS):
        score += 5
        reasons.append("Sembra contenere intestazioni email (ok per analisi).")

    # Link presenti
    links = LINK_RE.findall(txt)
    if links:
        score += 20
        reasons.append(f"Contiene {len(links)} link: controlla che puntino a domini ufficiali.")

    # Urgenza / minacce / dati
    hits = [k for k in TEXT_RED_FLAGS if k in low]
    if hits:
        score += min(40, 4 * len(hits))
        reasons.append("Ci sono parole/temi tipici da phishing (urgenza, account, pagamenti, codici).")

    threats = [t for t in THREAT_PHRASES if t in low]
    if threats:
        score += min(25, 10 * len(threats))
        reasons.append("Tono minaccioso/ultimatum: classico phishing.")

    if any(x in low for x in ["password", "otp", "codice", "pin", "cvv", "iban"]):
        score += 20
        reasons.append("Possibile richiesta di dati sensibili (mai darli via email).")

    if score >= 60:
        verdict = "Molto sospetta"
    elif score >= 30:
        verdict = "Sospetta"
    else:
        verdict = "Probabilmente ok (ma attenzione)"

    if not reasons:
        reasons.append("Nessun segnale forte rilevato, ma verifica sempre mittente e link.")

    return min(score, 100), verdict, reasons, links


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
async def home(request: Request):
    ctx = base_context()
    ctx["request"] = request
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

    response = templates.TemplateResponse("index.html", ctx)
    return nocache(response)


@app.post("/check-text", response_class=HTMLResponse)
async def check_text(request: Request, message: str = Form(...)):
    score, verdict, reasons, links = score_text(message)

    ctx = base_context()
    ctx.update({
        "request": request,
        "active": "text",
        "text_value": message,
        "result": {
            "title": "Analisi SMS / Messaggio",
            "verdict": verdict,
            "score": score,
            "reasons": reasons,
            "links": links
        }
    })

    response = templates.TemplateResponse("index.html", ctx)
    return nocache(response)


@app.post("/check-email", response_class=HTMLResponse)
async def check_email(request: Request, email_text: str = Form(...)):
    score, verdict, reasons, links = score_email(email_text)

    ctx = base_context()
    ctx.update({
        "request": request,
        "active": "email",
        "email_value": email_text,
        "result": {
            "title": "Analisi Email",
            "verdict": verdict,
            "score": score,
            "reasons": reasons,
            "links": links
        }
    })

    response = templates.TemplateResponse("index.html", ctx)
    return nocache(response)


@app.get("/health")
async def health():
    return {"ok": True}
