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

    if any(url.lower().startswith("http://") for url in urls):
        score += 10
        signals.append("Il link non è protetto: usa HTTP invece di HTTPS.")

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

    has_link = len(urls) > 0
    has_sanzione_words = sum(1 for word in sanzione_keywords if word in lower_text) >= 2
    has_real_details = sum(1 for word in dettagli_reali_keywords if word in lower_text) >= 2

    if has_link and has_sanzione_words and not has_real_details:
        score += 35
        signals.append("Messaggio con richiesta di pagamento o sanzione, link incluso e pochi dettagli verificabili.")

    if any(firma in lower_text for firma in firme_generiche):
        score += 10
        signals.append("Firma generica senza ente chiaramente identificabile.")

    if any(frase in lower_text for frase in tono_pressante):
        score += 15
        signals.append("Tono pressante o minaccioso tipico dei messaggi truffaldini.")

    domain_score, domain_reasons = score_suspicious_domains(domains)
    score += domain_score
    signals.extend(domain_reasons)

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
