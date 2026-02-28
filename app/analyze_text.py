import re
from typing import Tuple, List, Dict

def analyze_text(text: str) -> Tuple[int, str, List[Dict], str, List[str]]:
    score = 0
    signals: List[Dict] = []
    text_lower = (text or "").lower()

    if re.search(r"http[s]?://", text_lower):
        score += 10
        signals.append({"code": "LINK_PRESENT", "weight": 10, "evidence": "link presente"})

    if re.search(r"(bit\.ly|tinyurl|t\.co)", text_lower):
        score += 20
        signals.append({"code": "SHORTENER", "weight": 20, "evidence": "shortener rilevato"})

    if re.search(r"(password|credenziali|otp|codice|carta|iban|dati)", text_lower):
        score += 20
        signals.append({"code": "CREDENTIALS_REQUEST", "weight": 20, "evidence": "richiesta dati sensibili"})

    if re.search(r"(bloccato|sospeso|urgente|verifica|aggiorna|conferma)", text_lower):
        score += 20
        signals.append({"code": "ACCOUNT_THREAT", "weight": 20, "evidence": "minaccia o urgenza"})

    codes = {s["code"] for s in signals}

    if "SHORTENER" in codes and "CREDENTIALS_REQUEST" in codes:
        score += 25
        signals.append({"code": "DANGEROUS_COMBO", "weight": 25, "evidence": "shortener + richiesta dati"})

    if "LINK_PRESENT" in codes and "ACCOUNT_THREAT" in codes:
        score += 20
        signals.append({"code": "PHISHING_PATTERN", "weight": 20, "evidence": "link + minaccia account"})

    score = min(score, 100)

    if score < 30:
        level = "basso"
    elif score < 70:
        level = "medio"
    else:
        level = "alto"

    if "CREDENTIALS_REQUEST" in codes:
        category = "phishing_link"
    elif "ACCOUNT_THREAT" in codes:
        category = "account_threat"
    else:
        category = "sospetto_generico"

    if level == "alto":
        advice = [
            "Non cliccare il link.",
            "Non inserire password, OTP o dati carta.",
            "Controlla solo dall'app ufficiale.",
            "Segnala come spam."
        ]
    elif level == "medio":
        advice = [
            "Verifica sempre dal sito ufficiale.",
            "Non fidarti di richieste urgenti."
        ]
    else:
        advice = [
            "Resta prudente.",
            "Non condividere dati personali."
        ]

    return score, level, signals, category, advice
