"""
Assinador de Documento com PGP — protótipo monólito
=====================================================

Uma única aplicação Flask que:
  1. Serve uma página com um documento (documento.txt, em Markdown simples)
     e um formulário (nome + email).
  2. Ao "assinar", monta um texto canônico (hash do documento + nome + email
     + timestamp) e o assina com uma chave PGP própria do servidor, usando a
     biblioteca PGPy (OpenPGP em Python puro, sem depender do binário `gpg`).
  3. Guarda o recibo em um banco SQLite local.
  4. Expõe endpoints para consultar, baixar e verificar recibos, além da chave
     pública do servidor, para que qualquer pessoa verifique offline.

Modelo de confiança: isto NÃO é o usuário assinando com a própria chave
privada. O SERVIDOR atesta, com a chave dele, que "a pessoa com nome X e
email Y concordou com o documento de hash Z na data T" (recibo criptográfico).

Toda configuração sensível ou pessoal vem de variáveis de ambiente
(veja .env.example). Nada pessoal fica versionado no repositório.
"""

import hashlib
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import date, datetime, timezone

import pgpy
from flask import (
    Flask,
    Response,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from markupsafe import Markup, escape
from pgpy.constants import (
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SignatureType,
    SymmetricKeyAlgorithm,
)

# --------------------------------------------------------------------------
# .env opcional (python-dotenv); sem ele, usa só o ambiente do sistema
# --------------------------------------------------------------------------
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

# --------------------------------------------------------------------------
# Configuração
# --------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Em ambientes serverless (Vercel) só /tmp aceita escrita, e é volátil.
DEFAULT_DATA_DIR = "/tmp" if os.environ.get("VERCEL") else BASE_DIR
DATA_DIR = os.environ.get("DATA_DIR", DEFAULT_DATA_DIR)
os.makedirs(DATA_DIR, exist_ok=True)

KEY_PATH = os.path.join(DATA_DIR, "server_key.asc")
DB_PATH = os.path.join(DATA_DIR, "signatures.db")
DOCUMENT_PATH = os.path.join(BASE_DIR, "documento.txt")

SERVER_KEY_NAME = os.environ.get("SERVER_KEY_NAME", "Assinador de Documentos (Servidor)")
SERVER_KEY_EMAIL = os.environ.get("SERVER_KEY_EMAIL", "assinador@localhost")
SERVER_KEY_PASSPHRASE = os.environ.get("SERVER_KEY_PASSPHRASE") or None

# Data do aniversário no formato MM-DD (ex.: 03-27). Fica só no .env.
BIRTHDAY = os.environ.get("BIRTHDAY", "")

RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "5"))

MONTHS_PT = [
    "janeiro", "fevereiro", "março", "abril", "maio", "junho",
    "julho", "agosto", "setembro", "outubro", "novembro", "dezembro",
]

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PUBLIC_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,32}$")
NAME_MAX = 100
EMAIL_MAX = 254

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # bodies grandes não fazem sentido aqui

_SERVER_KEY = None


# --------------------------------------------------------------------------
# Aniversário (configurável por env)
# --------------------------------------------------------------------------

def parse_birthday():
    """Retorna (mes, dia) a partir de BIRTHDAY=MM-DD, ou None."""
    m = re.match(r"^(\d{2})-(\d{2})$", BIRTHDAY.strip())
    if not m:
        return None
    month, day = int(m.group(1)), int(m.group(2))
    try:
        date(2000, month, day)  # 2000 é bissexto, aceita 02-29
    except ValueError:
        return None
    return month, day


def birthday_label():
    bd = parse_birthday()
    if not bd:
        return "dia do aniversário"
    month, day = bd
    return f"{day} de {MONTHS_PT[month - 1]}"


def birthday_countdown(today=None):
    """Dias até o próximo aniversário (0 = é hoje), ou None se não configurado."""
    bd = parse_birthday()
    if not bd:
        return None
    today = today or date.today()
    month, day = bd
    for year in (today.year, today.year + 1, today.year + 2):
        try:
            target = date(year, month, day)
        except ValueError:  # 29/02 em ano não bissexto
            continue
        if target >= today:
            return (target - today).days
    return None


# --------------------------------------------------------------------------
# PGP
# --------------------------------------------------------------------------

def _save_key(key):
    with open(KEY_PATH, "w", encoding="utf-8") as f:
        f.write(str(key))
    try:
        os.chmod(KEY_PATH, 0o600)
    except (OSError, NotImplementedError):
        pass


def load_or_create_key():
    """Carrega a chave do servidor ou gera uma nova. Se SERVER_KEY_PASSPHRASE
    estiver definida, a chave privada fica protegida por ela no disco."""
    global _SERVER_KEY

    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "r", encoding="utf-8") as f:
            key, _ = pgpy.PGPKey.from_blob(f.read())
        if SERVER_KEY_PASSPHRASE and not key.is_protected:
            key.protect(SERVER_KEY_PASSPHRASE, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
            _save_key(key)
        if key.is_protected and not SERVER_KEY_PASSPHRASE:
            raise RuntimeError("A chave do servidor é protegida: defina SERVER_KEY_PASSPHRASE.")
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
    if SERVER_KEY_PASSPHRASE:
        key.protect(SERVER_KEY_PASSPHRASE, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    _save_key(key)
    _SERVER_KEY = key
    return key


def get_fingerprint():
    return str(_SERVER_KEY.fingerprint).replace(" ", "")


# O parser de cleartext do PGPy perde a assinatura quando o texto tem
# caracteres não-ASCII (ex.: "Júlia"), então montamos o bloco no formato
# cleartext do OpenPGP (RFC 4880 §7) a partir de uma assinatura destacada.
# O resultado é compatível com `gpg --verify`.
CLEARSIGN_RE = re.compile(
    r"-----BEGIN PGP SIGNED MESSAGE-----\r?\n"
    r"(?:[A-Za-z]+: [^\r\n]*\r?\n)*\r?\n"
    r"(?P<body>.*?)\r?\n"
    r"(?P<sig>-----BEGIN PGP SIGNATURE-----.*?-----END PGP SIGNATURE-----)",
    re.S,
)


def _canonical_lines(text):
    return [line.rstrip() for line in text.replace("\r\n", "\n").rstrip("\n").split("\n")]


def sign_text(canonical_text):
    lines = _canonical_lines(canonical_text)
    data = "\r\n".join(lines).encode("utf-8")
    kwargs = {"sigtype": SignatureType.CanonicalDocument, "hash": HashAlgorithm.SHA256}
    if _SERVER_KEY.is_protected:
        with _SERVER_KEY.unlock(SERVER_KEY_PASSPHRASE):
            sig = _SERVER_KEY.sign(data, **kwargs)
    else:
        sig = _SERVER_KEY.sign(data, **kwargs)
    escaped = "\n".join(("- " + l) if l.startswith("-") else l for l in lines)
    return f"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{escaped}\n{sig}"


def verify_text(signed_block):
    """Retorna (válido, mensagem_assinada_ou_None)."""
    try:
        m = CLEARSIGN_RE.search(signed_block)
        if not m:
            return False, None
        lines = [l[2:] if l.startswith("- ") else l for l in _canonical_lines(m.group("body"))]
        sig = pgpy.PGPSignature.from_blob(m.group("sig"))
        ok = bool(_SERVER_KEY.pubkey.verify("\r\n".join(lines).encode("utf-8"), sig))
        return ok, ("\n".join(lines) + "\n") if ok else None
    except Exception:  # noqa: BLE001 — qualquer falha vira "não verificado"
        return False, None


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
    # Migração: bancos antigos não tinham o ID público aleatório.
    cols = {row[1] for row in conn.execute("PRAGMA table_info(signatures)")}
    if "public_id" not in cols:
        conn.execute("ALTER TABLE signatures ADD COLUMN public_id TEXT")
        for (row_id,) in conn.execute("SELECT id FROM signatures").fetchall():
            conn.execute(
                "UPDATE signatures SET public_id = ? WHERE id = ?",
                (secrets.token_urlsafe(9), row_id),
            )
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_public_id ON signatures(public_id)")
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Documento (Markdown simples → blocos)
# --------------------------------------------------------------------------

def load_document():
    with open(DOCUMENT_PATH, "r", encoding="utf-8") as f:
        text = f.read()
    return text.replace("{{DATA_ANIVERSARIO}}", birthday_label())


def document_hash():
    return hashlib.sha256(load_document().encode("utf-8")).hexdigest()


def inline_md(text):
    """Escapa HTML e aplica **negrito**, *itálico* e `código`."""
    out = str(escape(text))
    out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<em>\1</em>", out)
    out = re.sub(r"`(.+?)`", r"<code>\1</code>", out)
    return Markup(out)


ROMAN_RE = re.compile(r"^([IVXLC]+)\.\s+(.*)$")
NUM_RE = re.compile(r"^(\d+)\.\s+(.*)$")
BULLET_RE = re.compile(r"^[*-]\s+(.*)$")


def parse_document():
    """Converte o documento em título + blocos tipados para o template.
    Suporta: # título, ## seção, ### subtítulo, ---, parágrafos, listas
    numeradas (1.), romanas (I.), com marcadores (* ou -), sublistas
    indentadas e citações (>)."""
    lines = load_document().splitlines()
    title, subtitle = "", ""
    blocks = []
    para = []
    lst = None  # {"type": "list", "style": ..., "entries": [...]}

    def flush_para():
        nonlocal para
        if para:
            blocks.append({"type": "paragraph", "html": inline_md(" ".join(para))})
            para = []

    def flush_list():
        nonlocal lst
        if lst:
            blocks.append(lst)
            lst = None

    for raw in lines:
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()

        if not line:
            flush_para()
            continue

        if line.startswith("# ") and not title:
            flush_para(); flush_list()
            title = line[2:].strip()
            continue
        if line.startswith("### "):
            flush_para(); flush_list()
            if not subtitle and not blocks:
                subtitle = line[4:].strip()
            else:
                blocks.append({"type": "h3", "html": inline_md(line[4:].strip())})
            continue
        if line.startswith("## "):
            flush_para(); flush_list()
            blocks.append({"type": "h2", "html": inline_md(line[3:].strip())})
            continue
        if re.fullmatch(r"-{3,}|\*{3,}", line):
            flush_para(); flush_list()
            blocks.append({"type": "hr"})
            continue
        if line.startswith(">"):
            flush_para(); flush_list()
            blocks.append({"type": "quote", "html": inline_md(line.lstrip("> ").strip())})
            continue

        item = None
        for style, rx in (("roman", ROMAN_RE), ("decimal", NUM_RE), ("bullet", BULLET_RE)):
            m = rx.match(line)
            if m:
                item = (style, m.groups()[-1])
                break

        if item:
            flush_para()
            style, content = item
            if lst and indent >= 2 and lst["entries"]:
                lst["entries"][-1]["children"].append(inline_md(content))
                continue
            if not lst or lst["style"] != style:
                flush_list()
                lst = {"type": "list", "style": style, "entries": []}
            lst["entries"].append({"html": inline_md(content), "children": [], "note": None})
            continue

        # linha de continuação de um item (ex.: "*(mesmo quando...)*" indentado)
        if lst and indent >= 2 and lst["entries"]:
            lst["entries"][-1]["note"] = inline_md(line)
            continue

        flush_list()
        para.append(line)

    flush_para()
    flush_list()
    return title, subtitle, blocks


# --------------------------------------------------------------------------
# Helpers de privacidade e segurança
# --------------------------------------------------------------------------

def mask_email(email):
    """ana.souza@exemplo.com → a•••a@e•••.com (nunca devolvemos o email inteiro)."""
    try:
        user, domain = email.split("@", 1)
        host, _, tld = domain.rpartition(".")
        u = user[0] + "•••" + (user[-1] if len(user) > 1 else "")
        h = (host[0] + "•••") if host else "•••"
        return f"{u}@{h}.{tld}"
    except (ValueError, IndexError):
        return "•••"


_rate_lock = threading.Lock()
_rate_hits = defaultdict(deque)


def rate_limited(key, limit=None, window=60.0):
    """Rate limit simples em memória (por processo). Suficiente para um site
    pequeno; para vários workers, troque por Flask-Limiter + Redis."""
    limit = limit or RATE_LIMIT_PER_MINUTE
    now = time.monotonic()
    with _rate_lock:
        hits = _rate_hits[key]
        while hits and now - hits[0] > window:
            hits.popleft()
        if len(hits) >= limit:
            return True
        hits.append(now)
        return False


def client_ip():
    # Atrás de proxy (Fly/Railway), confie só no primeiro X-Forwarded-For.
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() or request.remote_addr or "?"


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "script-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    )
    return resp


def get_signature_or_404(public_id):
    if not PUBLIC_ID_RE.match(public_id):
        abort(404)
    row = get_db().execute(
        "SELECT * FROM signatures WHERE public_id = ?", (public_id,)
    ).fetchone()
    if row is None:
        abort(404)
    return row


def signature_public_view(row):
    ok, _ = verify_text(row["signed_block"])
    return {
        "id": row["public_id"],
        "name": row["name"],
        "email_masked": mask_email(row["email"]),
        "document_hash": row["document_hash"],
        "document_is_current": row["document_hash"] == document_hash(),
        "signed_at": row["signed_at"],
        "fingerprint": row["fingerprint"],
        "signed_block": row["signed_block"],
        "verified": ok,
    }


def signature_count():
    return get_db().execute("SELECT COUNT(*) FROM signatures").fetchone()[0]


# --------------------------------------------------------------------------
# Rotas — páginas
# --------------------------------------------------------------------------

@app.route("/")
def index():
    title, subtitle, blocks = parse_document()
    h = document_hash()
    return render_template(
        "index.html",
        document_title=title,
        document_subtitle=subtitle,
        document_blocks=blocks,
        doc_hash=h,
        doc_hash_short=h[:10],
        countdown=birthday_countdown(),
        birthday=birthday_label(),
        total_signatures=signature_count(),
    )


@app.route("/verificar")
@app.route("/verificar/<public_id>")
def verify_page(public_id=None):
    code = (request.args.get("code") or "").strip()
    if not public_id and code:
        return redirect(url_for("verify_page", public_id=code))
    sig = None
    not_found = False
    if public_id:
        if PUBLIC_ID_RE.match(public_id):
            row = get_db().execute(
                "SELECT * FROM signatures WHERE public_id = ?", (public_id,)
            ).fetchone()
            sig = signature_public_view(row) if row else None
        not_found = sig is None
    return render_template(
        "verificar.html", sig=sig, not_found=not_found, query=public_id or ""
    )


@app.errorhandler(404)
def not_found(_e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Não encontrado."}), 404
    return render_template("verificar.html", sig=None, not_found=True, query=""), 404


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "Requisição grande demais."}), 413


# --------------------------------------------------------------------------
# Rotas — API
# --------------------------------------------------------------------------

@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok"})


@app.route("/api/document", methods=["GET"])
def api_document():
    return jsonify({"text": load_document(), "sha256": document_hash()})


@app.route("/api/public-key", methods=["GET"])
def api_public_key():
    if request.args.get("format") == "asc":
        return Response(
            export_public_key(),
            mimetype="application/pgp-keys",
            headers={"Content-Disposition": 'attachment; filename="chave-publica-servidor.asc"'},
        )
    return jsonify({"fingerprint": get_fingerprint(), "public_key_armored": export_public_key()})


@app.route("/api/stats", methods=["GET"])
def api_stats():
    return jsonify({
        "total_signatures": signature_count(),
        "days_until_birthday": birthday_countdown(),
    })


@app.route("/api/sign", methods=["POST"])
def api_sign():
    if rate_limited(("sign", client_ip())):
        return jsonify({"error": "Muitas tentativas. Espere um minutinho e tente de novo."}), 429

    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or "").strip()
    email = str(data.get("email") or "").strip().lower()
    agree = data.get("agree") is True

    if len(name) < 2 or len(name) > NAME_MAX:
        return jsonify({"error": "Nome inválido."}), 400
    if len(email) > EMAIL_MAX or not EMAIL_RE.match(email):
        return jsonify({"error": "Email inválido."}), 400
    if not agree:
        return jsonify({"error": "É necessário confirmar que leu e concorda com o documento."}), 400

    doc_hash = document_hash()
    signed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    canonical_text = (
        f"Documento (SHA-256): {doc_hash}\n"
        f"Nome do signatário: {name}\n"
        f"Email do signatário: {email}\n"
        f"Assinado em (UTC): {signed_at}\n"
    )

    try:
        signed_block = sign_text(canonical_text)
    except Exception:  # noqa: BLE001
        app.logger.exception("Falha ao assinar")
        return jsonify({"error": "Falha ao assinar o documento."}), 500

    fingerprint = get_fingerprint()
    public_id = secrets.token_urlsafe(9)

    db = get_db()
    db.execute(
        """
        INSERT INTO signatures
            (public_id, name, email, document_hash, canonical_text, signed_block, fingerprint, signed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (public_id, name, email, doc_hash, canonical_text, signed_block, fingerprint, signed_at),
    )
    db.commit()
    receipt_number = db.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]

    return jsonify({
        "id": public_id,
        "number": receipt_number,
        "signed_at": signed_at,
        "document_hash": doc_hash,
        "signed_block": signed_block,
        "fingerprint": fingerprint,
        "verify_url": f"/verificar/{public_id}",
    }), 201


@app.route("/api/signatures/<public_id>", methods=["GET"])
def api_get_signature(public_id):
    return jsonify(signature_public_view(get_signature_or_404(public_id)))


@app.route("/api/signatures/<public_id>/download", methods=["GET"])
def api_download_signature(public_id):
    row = get_signature_or_404(public_id)
    return Response(
        row["signed_block"],
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="recibo-{public_id}.asc"'},
    )


@app.route("/api/verify", methods=["POST"])
def api_verify_block():
    """Verifica um bloco PGP colado (ex.: um recibo baixado antes)."""
    if rate_limited(("verify", client_ip()), limit=30):
        return jsonify({"error": "Muitas tentativas."}), 429
    data = request.get_json(silent=True) or {}
    block = str(data.get("signed_block") or "")
    if "BEGIN PGP SIGNED MESSAGE" not in block:
        return jsonify({"verified": False, "error": "Cole um bloco PGP assinado completo."}), 400
    ok, message = verify_text(block)
    return jsonify({"verified": ok, "message": message})


# --------------------------------------------------------------------------
# Bootstrap
# --------------------------------------------------------------------------

def bootstrap():
    load_or_create_key()
    init_db()


bootstrap()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
