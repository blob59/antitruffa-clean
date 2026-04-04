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

    has_link = len(urls) > 0
    has_phone = len(phones) > 0
    has_http_link = any(url.lower().startswith("http://") for url in urls)
    has_ip_link = has_ip_url(urls)

    has_shortener_domain = any(
        any(short in d for short in shorteners)
        for d in domains
    )

    has_weird_tld = any(
        any(d.endswith(tld) for tld in suspicious_tlds)
        for d in domains
    )

    has_sanzione_words = sum(1 for word in sanzione_keywords if word in lower_text) >= 2
    has_real_details = sum(1 for word in dettagli_reali_keywords if word in lower_text) >= 2
    has_generic_signature = any(firma in lower_text for firma in firme_generiche)
    has_pressing_tone = any(frase in lower_text for frase in tono_pressante)

    has_fake_security_story = any(
        frase in lower_text for frase in [
            "accesso anomalo",
            "nuovo dispositivo",
            "conto temporaneamente limitato",
            "profilo temporaneamente limitato",
            "account sospeso",
            "conto bloccato",
            "profilo limitato",
            "servizio sospeso",
        ]
    )

    has_short_deadline = any(
        frase in lower_text for frase in [
            "entro 24 ore",
            "entro 12 ore",
            "entro oggi",
            "subito",
            "immediatamente",
            "ultima possibilità",
            "ultimatum",
        ]
    )

    asks_to_click = any(
        frase in lower_text for frase in [
            "clicca qui",
            "verifica qui",
            "accedi qui",
            "conferma qui",
            "premi qui",
            "usa il seguente link",
            "al seguente link",
        ]
    )

    has_example_domain = any("example." in d for d in domains)

    if found_urgency:
        score += 20
        signals.append("Tono di urgenza o pressione psicologica.")

    if found_data:
        score += 25
        signals.append("Richiesta di dati sensibili o codici personali.")

    if found_lure:
        score += 15
        signals.append("Presenza di esche tipiche: premio, rimborso, consegna o guadagno facile.")

    if has_link:
        score += 10
        signals.append("Sono presenti uno o più link nel testo.")

    if has_phone:
        score += 8
        signals.append("Sono presenti numeri telefonici da contattare.")

    if has_http_link:
        score += 10
        signals.append("Il link non è protetto: usa HTTP invece di HTTPS.")

    if has_ip_link:
        score += 20
        signals.append("Link con indirizzo IP invece di un dominio normale.")

    if has_shortener_domain:
        score += 15
        signals.append("Uso di link abbreviati, spesso usati per nascondere la destinazione reale.")

    if has_weird_tld:
        score += 10
        signals.append("Dominio con estensione poco affidabile o insolita.")

    if has_link and has_sanzione_words and not has_real_details:
        score += 35
        signals.append("Messaggio con richiesta di pagamento o sanzione, link incluso e pochi dettagli verificabili.")

    if has_generic_signature:
        score += 10
        signals.append("Firma generica senza ente chiaramente identificabile.")

    if has_pressing_tone:
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

    # BONUS COMBINATI: qui il motore diventa più severo e più intelligente
    if has_link and found_urgency:
        score += 10
        signals.append("Link inserito insieme a urgenza: combinazione tipica delle truffe.")

    if has_link and found_data:
        score += 15
        signals.append("Il messaggio spinge a cliccare e a fornire dati: combinazione ad alto rischio.")

    if found_urgency and found_data:
        score += 12
        signals.append("Urgenza e richiesta dati nello stesso messaggio: schema fortemente sospetto.")

    if has_short_deadline:
        score += 10
        signals.append("Presenza di una scadenza ravvicinata per spingere ad agire in fretta.")

    if has_fake_security_story and has_link:
        score += 15
        signals.append("Finto avviso di sicurezza con invito a cliccare un link.")

    if has_http_link and (found_urgency or found_data):
        score += 8
        signals.append("Link non protetto unito a richiesta urgente o sensibile.")

    if has_generic_signature and not found_platform:
        score += 8
        signals.append("Mittente vago o poco identificabile.")

    if has_fake_security_story and found_data:
        score += 12
        signals.append("Pretesto di sicurezza usato per ottenere dati o accessi.")

    if asks_to_click and has_link:
        score += 12
        signals.append("Invito esplicito al clic: comportamento molto tipico delle campagne fraudolente.")

    if has_example_domain:
        score += 15
        signals.append("Dominio palesemente anomalo o non riconoscibile.")

    # Piccolo correttivo: se c'è solo un link ma niente altro, non gonfiare troppo
    if (
        has_link
        and not found_urgency
        and not found_data
        and not found_lure
        and not has_phone
        and not has_pressing_tone
        and not has_shortener_domain
        and not has_weird_tld
        and not has_ip_link
        and not has_generic_signature
    ):
        score = max(score - 5, 0)

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
