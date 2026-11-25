"""Testes básicos: rode com `python -m pytest -q`."""

import importlib
import os
import sys
from datetime import date

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope="module")
def app_module(tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("data")
    os.environ["DATA_DIR"] = str(data_dir)
    os.environ["BIRTHDAY"] = "03-27"
    os.environ["SERVER_KEY_PASSPHRASE"] = "teste-passphrase"
    os.environ["RATE_LIMIT_PER_MINUTE"] = "100"
    import app as module

    module = importlib.reload(module)
    module.app.config["TESTING"] = True
    return module


@pytest.fixture()
def client(app_module):
    return app_module.app.test_client()


def sign(client, **overrides):
    body = {"name": "Fulana de Tal", "email": "Fulana@Exemplo.com", "agree": True}
    body.update(overrides)
    return client.post("/api/sign", json=body)


def test_index_renders_document_with_birthday(client):
    res = client.get("/")
    html = res.get_data(as_text=True)
    assert res.status_code == 200
    assert "27 de março" in html
    assert "{{DATA_ANIVERSARIO}}" not in html
    assert "CLÁUSULA 1" in html
    assert "Content-Security-Policy" in res.headers


def test_sign_and_verify_roundtrip(client):
    res = sign(client)
    assert res.status_code == 201
    data = res.get_json()
    assert len(data["id"]) >= 8 and not data["id"].isdigit()

    got = client.get(f"/api/signatures/{data['id']}").get_json()
    assert got["verified"] is True
    assert "email" not in got  # email completo nunca sai pela API
    assert got["email_masked"].startswith("f•••a@e•••")

    ok = client.post("/api/verify", json={"signed_block": data["signed_block"]}).get_json()
    assert ok["verified"] is True

    tampered = data["signed_block"].replace("Fulana de Tal", "Outra Pessoa")
    bad = client.post("/api/verify", json={"signed_block": tampered}).get_json()
    assert bad["verified"] is False


def test_accented_names_verify(client):
    # Regressão: o cleartext do PGPy quebrava com caracteres não-ASCII.
    data = sign(client, name="Júlia Conceição - teste").get_json()
    assert client.get(f"/api/signatures/{data['id']}").get_json()["verified"] is True
    ok = client.post("/api/verify", json={"signed_block": data["signed_block"]}).get_json()
    assert ok["verified"] is True
    assert "Júlia Conceição" in ok["message"]


def test_sequential_ids_do_not_leak(client):
    assert client.get("/api/signatures/1").status_code == 404


def test_download_and_verify_page(client):
    sid = sign(client).get_json()["id"]
    dl = client.get(f"/api/signatures/{sid}/download")
    assert dl.status_code == 200
    assert "BEGIN PGP SIGNED MESSAGE" in dl.get_data(as_text=True)
    page = client.get(f"/verificar/{sid}").get_data(as_text=True)
    assert "Assinatura válida" in page
    assert client.get("/verificar?code=" + sid).status_code == 302
    assert client.get("/verificar/naoexiste123").status_code == 200


@pytest.mark.parametrize(
    "overrides,status",
    [
        ({"name": "A"}, 400),
        ({"name": "x" * 101}, 400),
        ({"email": "invalido"}, 400),
        ({"agree": False}, 400),
        ({"agree": "true"}, 400),
    ],
)
def test_validation(client, overrides, status):
    assert sign(client, **overrides).status_code == status


def test_key_is_protected_on_disk(app_module):
    with open(app_module.KEY_PATH, encoding="utf-8") as f:
        content = f.read()
    import pgpy

    key, _ = pgpy.PGPKey.from_blob(content)
    assert key.is_protected


def test_countdown(app_module):
    assert app_module.birthday_countdown(date(2030, 3, 27)) == 0
    assert app_module.birthday_countdown(date(2030, 3, 26)) == 1
    assert app_module.birthday_countdown(date(2030, 3, 28)) == 364


def test_rate_limit(app_module):
    key = ("teste", "1.2.3.4")
    hits = [app_module.rate_limited(key, limit=3) for _ in range(4)]
    assert hits == [False, False, False, True]
