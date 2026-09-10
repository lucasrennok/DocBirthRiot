"""
Assinador de Documento com PGP — protótipo monólito
=====================================================

Uma única aplicação Flask que:
  1. Serve uma página com um documento FIXO e um formulário (nome + email).
  2. Ao "assinar", monta um texto canônico (hash do documento + nome + email
     + timestamp) e o assina digitalmente com uma chave PGP própria do
     servidor, usando a biblioteca PGPy (OpenPGP em Python puro — sem
     depender do binário `gpg` nem de gpg-agent instalados no sistema).
  3. Guarda o registro (recibo) em um banco SQLite local.
  4. Expõe endpoints para consultar/baixar o recibo e a chave pública do
     servidor, para que qualquer pessoa possa verificar a assinatura
     offline (com `gpg --verify`, se quiser, já que o formato gerado é
     PGP padrão — ou com a própria PGPy).

IMPORTANTE (modelo de confiança):
  Isso NÃO é o usuário assinando com a própria chave PGP privada dele
  (um navegador não tem acesso a isso). O que este protótipo faz é gerar
  um RECIBO CRIPTOGRÁFICO: o SERVIDOR atesta, com sua própria chave PGP,
  que "a pessoa com nome X e email Y concordou com o documento de hash Z
  na data T". É o mesmo modelo usado por muitos sistemas de "click-wrap"
  com prova de integridade. Para assinatura com a chave do PRÓPRIO usuário,
  veja a seção "próximos passos" no README.
"""

import hashlib
import os
import re
import sqlite3
from datetime import datetime, timezone

import pgpy
from pgpy.constants import (
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)
from flask import Flask, g, jsonify, render_template, request

# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# No Vercel, o diretório do projeto é somente-leitura — só /tmp aceita
# escrita (e é apagado a cada nova instância). Localmente, continua
# salvando ao lado do app.py, como antes.
WRITABLE_DIR = "/tmp" if os.environ.get("VERCEL") else BASE_DIR

KEY_PATH = os.path.join(WRITABLE_DIR, "server_key.asc")  # guarda a chave privada+pública, armored
DB_PATH = os.path.join(WRITABLE_DIR, "signatures.db")
DOCUMENT_PATH = os.path.join(BASE_DIR, "documento.txt")  # só leitura, fica no projeto mesmo

SERVER_KEY_NAME = "Assinador de Documentos (Servidor)"
SERVER_KEY_EMAIL = "assinador@localhost"

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

app = Flask(__name__)

# Chave do servidor, carregada uma vez no bootstrap (ver seção final do arquivo)
_SERVER_KEY = None


# --------------------------------------------------------------------------
# PGP: setup e helpers (PGPy — sem processo externo, sem agente)
# --------------------------------------------------------------------------

def load_or_create_key():
    """Carrega a chave do servidor de disco, ou gera uma nova na primeira
    execução e salva em KEY_PATH (formato ASCII-armored, contém a chave
    privada — trate esse arquivo como segredo)."""
    global _SERVER_KEY

    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "r", encoding="utf-8") as f:
            key_data = f.read()
        key, _ = pgpy.PGPKey.from_blob(key_data)
        _SERVER_KEY = key
        return key

    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 3072)
    uid = pgpy.PGPUID.new(SERVER_KEY_NAME, email=SERVER_KEY_EMAIL)
    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
    )

    with open(KEY_PATH, "w", encoding="utf-8") as f:
        f.write(str(key))
    try:
        os.chmod(KEY_PATH, 0o600)  # sem efeito no Windows, e sem problema
    except (OSError, NotImplementedError):
        pass

    _SERVER_KEY = key
    return key


def get_fingerprint():
    return str(_SERVER_KEY.fingerprint).replace(" ", "")


def sign_text(canonical_text):
    """Assina o texto (equivalente a --clearsign) e devolve o bloco PGP assinado."""
    msg = pgpy.PGPMessage.new(canonical_text, cleartext=True)
    msg |= _SERVER_KEY.sign(msg)
    return str(msg)


def verify_text(signed_block):
    """Verifica um bloco assinado e retorna (True/False, mensagem de erro)."""
    try:
        msg = pgpy.PGPMessage.from_blob(signed_block)
        verified = _SERVER_KEY.pubkey.verify(msg)
        return bool(verified), ""
    except Exception as e:  # noqa: BLE001 — qualquer falha de parsing/verify vira "não verificado"
        return False, str(e)


def export_public_key():
    return str(_SERVER_KEY.pubkey)


# --------------------------------------------------------------------------
# Banco de dados
# --------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            document_hash TEXT NOT NULL,
            canonical_text TEXT NOT NULL,
            signed_block TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            signed_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Documento
# --------------------------------------------------------------------------

def load_document():
    with open(DOCUMENT_PATH, "r", encoding="utf-8") as f:
        return f.read()


def document_hash():
    return hashlib.sha256(load_document().encode("utf-8")).hexdigest()


def parse_document():
    """Divide o documento em título + blocos (parágrafo ou lista numerada)
    para o template poder exibir tipografia de verdade em vez de um bloco
    <pre> cru. A primeira linha não vazia é tratada como título; blocos
    separados por linha em branco viram parágrafos, e um bloco cuja
    primeira linha começa com "1." vira lista — juntando linhas de
    continuação (quebradas fisicamente no arquivo) ao item anterior."""
    text = load_document().strip("\n")
    raw_blocks = re.split(r"\n\s*\n", text)
    title = raw_blocks[0].strip() if raw_blocks else ""
    item_start_re = re.compile(r"^\d+\.\s*(.*)")

    blocks = []
    for raw in raw_blocks[1:]:
        lines = [line.strip() for line in raw.split("\n") if line.strip()]
        if not lines:
            continue

        if item_start_re.match(lines[0]):
            entries = []
            current = None
            for line in lines:
                m = item_start_re.match(line)
                if m:
                    if current is not None:
                        entries.append(current)
                    current = m.group(1)
                elif current is not None:
                    current += " " + line
            if current is not None:
                entries.append(current)
            blocks.append({"type": "list", "entries": entries})
        else:
            blocks.append({"type": "paragraph", "text": " ".join(lines)})

    return title, blocks


# --------------------------------------------------------------------------
# Rotas — interface
# --------------------------------------------------------------------------

@app.route("/")
def index():
    title, blocks = parse_document()
    return render_template(
        "index.html",
        document_title=title,
        document_blocks=blocks,
        doc_hash=document_hash(),
        doc_hash_short=document_hash()[:10],
    )


# --------------------------------------------------------------------------
# Rotas — API
# --------------------------------------------------------------------------

@app.route("/api/document", methods=["GET"])
def api_document():
    return jsonify({"text": load_document(), "sha256": document_hash()})


@app.route("/api/public-key", methods=["GET"])
def api_public_key():
    return jsonify({
        "fingerprint": get_fingerprint(),
        "public_key_armored": export_public_key(),
    })


@app.route("/api/sign", methods=["POST"])
def api_sign():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    agree = bool(data.get("agree"))

    if not name or len(name) < 2:
        return jsonify({"error": "Nome inválido."}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"error": "Email inválido."}), 400
    if not agree:
        return jsonify({"error": "É necessário confirmar que leu e concorda com o documento."}), 400

    doc_hash = document_hash()
    signed_at = datetime.now(timezone.utc).isoformat()

    canonical_text = (
        f"Documento (SHA-256): {doc_hash}\n"
        f"Nome do signatário: {name}\n"
        f"Email do signatário: {email}\n"
        f"Assinado em (UTC): {signed_at}\n"
    )

    try:
        signed_block = sign_text(canonical_text)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": f"Falha ao assinar: {e}"}), 500

    fingerprint = get_fingerprint()

    db = get_db()
    cur = db.execute(
        """
        INSERT INTO signatures (name, email, document_hash, canonical_text, signed_block, fingerprint, signed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (name, email, doc_hash, canonical_text, signed_block, fingerprint, signed_at),
    )
    db.commit()
    new_id = cur.lastrowid

    return jsonify({
        "id": new_id,
        "signed_at": signed_at,
        "document_hash": doc_hash,
        "canonical_text": canonical_text,
        "signed_block": signed_block,
        "fingerprint": fingerprint,
    }), 201


@app.route("/api/signatures/<int:sig_id>", methods=["GET"])
def api_get_signature(sig_id):
    db = get_db()
    row = db.execute("SELECT * FROM signatures WHERE id = ?", (sig_id,)).fetchone()
    if row is None:
        return jsonify({"error": "Assinatura não encontrada."}), 404

    ok, verify_msg = verify_text(row["signed_block"])

    return jsonify({
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "document_hash": row["document_hash"],
        "signed_at": row["signed_at"],
        "fingerprint": row["fingerprint"],
        "signed_block": row["signed_block"],
        "verified": ok,
    })


# --------------------------------------------------------------------------
# Bootstrap
# --------------------------------------------------------------------------

def bootstrap():
    load_or_create_key()
    init_db()


bootstrap()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
