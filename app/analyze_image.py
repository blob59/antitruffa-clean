from __future__ import annotations
import io
import hashlib
from typing import Dict, List, Tuple
from PIL import Image, ImageStat

def fingerprint_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def analyze_image_bytes(data: bytes) -> Tuple[int, str, List[Dict], List[str], bool, str, str]:
    img = Image.open(io.BytesIO(data)).convert("RGB")
    w, h = img.size

    exif_present = False
    try:
        exif = img.getexif()
        exif_present = bool(exif) and len(exif) > 0
    except Exception:
        exif_present = False

    signals: List[Dict] = []
    if not exif_present:
        signals.append({"code":"NO_EXIF", "weight":10, "evidence":"Nessun EXIF"})
    if w < 500 or h < 500:
        signals.append({"code":"LOW_RES", "weight":8, "evidence":f"{w}x{h}"})

    stat = ImageStat.Stat(img.convert("L"))
    var = stat.var[0] if stat.var else 0.0
    if var < 150:
        signals.append({"code":"LOW_DETAIL", "weight":10, "evidence":f"var={var:.1f}"})

    score = min(100, sum(s["weight"] for s in signals))
    level = "basso" if score < 20 else "medio" if score < 50 else "alto"
    category = "deepfake_suspected" if level in ("medio","alto") else "image_check"

    notes = [
        "Questa analisi non è un verdetto: sono indizi tecnici.",
        "Consiglio: cerca la fonte originale (reverse image search) e verifica il contesto.",
        "Compressioni (WhatsApp/social) possono alterare i metadati e la qualità."
    ]

    fp = fingerprint_bytes(data)
    return score, level, signals, notes, exif_present, fp, category
