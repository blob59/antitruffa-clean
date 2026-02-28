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
# Phishing quick-check (euristiche)
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
    """Ritorna (score, verdict, reasons, parsed_display_url)."""
    raw = (url or "").strip()

    # Normalizza: se manca schema, aggiungi https:// (per poter fare parse)
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
        return 100, "Sembra phishing", ["Manca il dominio (host) nell’URL."], display_url

    # 1) HTTPS
    if p.scheme != "https":
        score += 15
        reasons.append("Non usa HTTPS (http invece di https).")

    # 2) @ nel link (trucco per ingannare)
    if "@" in (p.netloc or ""):
        score += 25
        reasons.append("Contiene '@' nel dominio (tecnica tipica di mascheramento).")

    # 3) Dominio è un IP
    if IPV4_RE.match(host):
        score += 30
        reasons.append("Il dominio è un indirizzo IP (molto sospetto).")

    # 4) Punycode / caratteri strani (xn--)
    if host.startswith("xn--") or "xn--" in host:
        score += 20
        reasons.append("Dominio in punycode (potenziale dominio “falso” con caratteri simili).")

    # 5) Troppi sottodomini
    parts = host.split(".")
    if len(parts) >= 4:
        score += 15
        reasons.append("Troppi sottodomini (spesso usati per imitare siti famosi).")

    # 6) Trattini strani nel dominio
    if host.count("-") >= 2:
        score += 10
        reasons.append("Molti trattini nel dominio (pattern frequente nei phishing).")

    # 7) URL troppo lungo
    if len(raw) > 90:
        score += 10
        reasons.append("URL molto lungo (può nascondere la vera destinazione).")

    # 8) Shortener
    if host in SHORTENERS:
        score += 20
        reasons.append("È un link accorciato (non vedi dove porta davvero).")

    # 9) Keyword “spinte” (login, verify, ecc.)
    text = f"{host}/{path}?{query}"
    kw_hits = [k for k in SUSPICIOUS_KEYWORDS if k in text]
    if kw_hits:
        score += min(25, 5 * len(kw_hits))
        reasons.append(f"Contiene parole tipiche da phishing: {', '.join(sorted(set(kw_hits)))}.")

    # 10) TLD sospetto
    tld = parts[-1] if parts else ""
    if tld in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"TLD (estensione) spesso usata in truffe: .{tld}")

    # 11) “Brand bait”: nome di marca nel dominio ma dominio strano
    bait_hits = [b for b in BRAND_BAIT if b in host]
    if bait_hits:
        # se contiene brand ma non è un dominio “pulito” (es: amazon.it), alziamo la guardia
        score += 15
        reasons.append(
            f"Nel dominio compare un nome “esca” ({', '.join(sorted(set(bait_hits)))}): attenzione ai falsi."
        )

    # Verdict
    if score >= 45:
        verdict = "Sembra phishing"
    elif score >= 20:
        verdict = "Sospetto"
    else:
        verdict = "Probabilmente ok (ma verifica comunque)"

    if not reasons:
        reasons.append("Nessun segnale forte rilevato, ma controlla sempre dominio e mittente.")

    return score, verdict, reasons, display_url


def nocache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    response = templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "build_time": datetime.utcnow().isoformat(),
            "name": "Franco Ficara",
            "result": None,
            "url": "",
        },
    )
    return nocache(response)


@app.post("/check", response_class=HTMLResponse)
async def check(request: Request, url: str = Form(...)):
    score, verdict, reasons, display_url = score_url(url)

    response = templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "build_time": datetime.utcnow().isoformat(),
            "name": "Franco Ficara",
            "result": {
                "verdict": verdict,
                "score": score,
                "reasons": reasons,
            },
            "url": display_url,
        },
    )
    return nocache(response)


@app.get("/health")
async def health():
    return {"ok": True}
