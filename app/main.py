from pathlib import Path

import json
import os
import urllib.request
import urllib.error


from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI()

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "").strip()


def extract_first_url(text: str) -> str | None:
    match = re.search(r"(https?://[^\s]+|www\.[^\s]+)", text, flags=re.IGNORECASE)
    if not match:
        return None

    url = match.group(1).strip().rstrip(".,;:)]}")
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


def check_url_with_safe_browsing(url: str):
    if not SAFE_BROWSING_API_KEY:
        return {
            "status": "skipped",
            "unsafe": False,
            "matches": [],
            "message": "Chiave Safe Browsing non configurata."
        }

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={SAFE_BROWSING_API_KEY}"
    )

    payload = {
        "client": {
            "clientId": "antitruffa-franco-ficara",
            "clientVersion": "1.0.0"
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
            "threatEntries": [{"url": url}]
        }
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
            result = json.loads(body) if body else {}

        matches = result.get("matches", [])
        return {
            "status": "ok",
            "unsafe": len(matches) > 0,
            "matches": matches,
            "message": "URL segnalato come pericoloso." if matches else "Nessuna segnalazione trovata."
        }

    except urllib.error.HTTPError as e:
        return {
            "status": "error",
            "unsafe": False,
            "matches": [],
            "message": f"Errore HTTP Safe Browsing: {e.code}"
        }
    except Exception as e:
        return {
            "status": "error",
            "unsafe": False,
            "matches": [],
            "message": f"Errore Safe Browsing: {str(e)}"
        }

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
