"""Verifiche di pre-lancio AntiTruffa. Eseguire con pytest in ambiente isolato."""
import sqlite3
import pytest
from fastapi.testclient import TestClient
from app import main as m


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "DB_PATH", str(tmp_path / "reports-test.db"))
    m.init_db()
    with TestClient(m.app) as api:
        yield api


def test_segnalazione_html_content_funzionante(client):
    response = client.post("/api/report", json={
        "type": "messaggio",
        "source": "SMS",
        "content": "Ti chiediamo un OTP per accedere"
    })
    assert response.status_code == 200
    assert response.json()["ok"] is True
    with sqlite3.connect(m.DB_PATH) as db:
        saved = db.execute("SELECT original_text, category, level FROM reports").fetchone()
    assert saved == ("", "messaggio", "da_verificare")


def test_testo_non_archiviato_nel_database(client):
    private = "Il mio dato privato di prova 123"
    assert client.post("/api/report", json={"content": private}).status_code == 200
    with sqlite3.connect(m.DB_PATH) as db:
        originals = db.execute("SELECT original_text FROM reports").fetchall()
    assert originals == [("",)]


def test_non_salva_duplicati_entro_7_giorni(client):
    payload = {"content": "Messaggio di test unico"}
    first = client.post("/api/report", json=payload)
    second = client.post("/api/report", json=payload)
    assert first.status_code == 200 and first.json()["saved"] is True
    assert second.status_code == 200 and second.json()["saved"] is False


def test_registro_rifiuta_fingerprint_inesistente(client):
    response = client.post("/api/report", json={"fingerprint": "../qualcosa"})
    assert response.status_code == 400


def test_lunghezza_massima_segnalazioni(client):
    response = client.post("/api/report", json={"content": "a" * 10001})
    assert response.status_code == 413


def test_lunghezza_massima_analisi(client):
    response = client.post("/api/analyze", json={"text": "a" * 10001})
    assert response.status_code == 413
