from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
from datetime import datetime

app = FastAPI(title="AntiTruffa")

# Percorso assoluto sicuro (così non sbaglia mai in Railway)
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Static su /static (non montare mai static su "/")
static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    # Timestamp per vedere subito se la pagina è nuova
    response = templates.TemplateResponse(
        "index.html",
        {"request": request, "build_time": datetime.utcnow().isoformat()}
    )

    # Anti-cache duro e puro (così l’HTML non resta vecchio)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.get("/health")
async def health():
    return {"ok": True}
