# DocBirthRiot 🖋️🎮

Um "termo de aceite" de brincadeira para alguém se comprometer a jogar
**League of Legends** no próprio aniversário, com assinatura digital PGP de
verdade por trás.

**Flask + SQLite + [PGPy](https://pgpy.readthedocs.io/)** (OpenPGP em Python
puro: não precisa de `gpg` instalado para rodar).

## Funcionalidades

- Documento em Markdown simples (`documento.txt`) renderizado como "papel",
  com títulos, cláusulas, listas romanas e citações
- Data do aniversário configurável por variável de ambiente, com contador
  regressivo ("faltam X dias")
- Assinatura com nome + email e recibo PGP assinado pelo servidor
- Selo, data, fingerprint e confete quando alguém assina 🎉
- Página pública de verificação (`/verificar/<código>`), com o email mascarado
- Verificação de um bloco PGP colado, download do recibo `.asc` e da chave pública
- Compatível com `gpg --verify`
- Proteções: IDs de recibo aleatórios (não sequenciais), email nunca exposto
  inteiro, rate limit por IP, limite de tamanho de requisição, cabeçalhos de
  segurança (CSP, X-Frame-Options etc.) e chave privada protegida por passphrase

## Como funciona (modelo de confiança)

O navegador não tem acesso à chave PGP de quem assina. Por isso o
**servidor** emite um recibo: ele assina com a própria chave o texto

```
Documento (SHA-256): <hash do documento>
Nome do signatário: <nome>
Email do signatário: <email>
Assinado em (UTC): <timestamp>
```

Qualquer pessoa pode verificar esse recibo offline com a chave pública do
servidor. É prova de integridade + carimbo de tempo, não "assinatura de
próprio punho".

## Rodando localmente

Requer **Python 3.9 a 3.12** (o PGPy 0.6 ainda não suporta 3.13+).

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env              # Windows: copy .env.example .env
# edite o .env: BIRTHDAY=MM-DD e SERVER_KEY_PASSPHRASE

python app.py
```

Abra <http://localhost:5000>. Na primeira execução o app gera a chave do
servidor (`server_key.asc`) e o banco (`signatures.db`). Os dois, assim como
o `.env`, ficam fora do git.

> ⚠️ `server_key.asc` contém a chave privada. Faça backup: sem ela, os
> recibos antigos não podem mais ser revalidados por este servidor.

### Testes

```bash
pip install pytest
python -m pytest -q
```

## Variáveis de ambiente

| Variável | Padrão | Descrição |
|---|---|---|
| `BIRTHDAY` | (vazio) | Data do aniversário, `MM-DD`. Vazio mostra "dia do aniversário" e esconde o contador |
| `SERVER_KEY_PASSPHRASE` | (vazio) | Protege a chave privada no disco |
| `SERVER_KEY_NAME` / `SERVER_KEY_EMAIL` | genéricos | Identidade da chave do servidor |
| `DATA_DIR` | pasta do app (`/tmp` no Vercel) | Onde ficam `signatures.db` e `server_key.asc` |
| `RATE_LIMIT_PER_MINUTE` | `5` | Assinaturas por IP por minuto |
| `HOST` / `PORT` / `FLASK_DEBUG` | `127.0.0.1` / `5000` / `0` | Servidor de desenvolvimento |

## Endpoints

| Método | Rota | Descrição |
|---|---|---|
| GET | `/` | Documento + formulário |
| GET | `/verificar/<código>` | Página pública do recibo |
| GET | `/api/document` | Texto e SHA-256 do documento |
| POST | `/api/sign` | `{"name", "email", "agree": true}` → recibo |
| GET | `/api/signatures/<código>` | Recibo revalidado (`verified`), email mascarado |
| GET | `/api/signatures/<código>/download` | Recibo `.asc` |
| POST | `/api/verify` | `{"signed_block"}` → verifica um bloco colado |
| GET | `/api/public-key` | Chave pública (`?format=asc` para baixar) |
| GET | `/api/stats` | Total de assinaturas e dias até o aniversário |
| GET | `/api/health` | Health check |

## Verificando com gpg

```bash
curl -o servidor.asc "http://localhost:5000/api/public-key?format=asc"
gpg --import servidor.asc
gpg --verify recibo-<código>.asc
```

## Trocando o documento

Edite `documento.txt`. O marcador `{{DATA_ANIVERSARIO}}` é trocado pela
data do `.env`. Se o texto mudar, o hash muda, e recibos antigos aparecem
como "versão anterior do documento".

## Deploy

Qualquer host com disco persistente serve (Fly.io, Railway, uma VM).
Configure as variáveis de ambiente lá e aponte `DATA_DIR` para o volume.
Em produção, use um servidor WSGI (`pip install gunicorn` e
`gunicorn app:app`). Serverless (Vercel/Netlify) funciona só para
demonstração: o `/tmp` é apagado e as assinaturas se perdem.

## Ideias futuras

- Assinatura com a chave do próprio usuário via [OpenPGP.js](https://openpgpjs.org/)
- Confirmação por email antes de validar a assinatura
- Exportar o recibo em PDF com QR code para a página de verificação

---

Não afiliado à Riot Games. League of Legends é marca da Riot Games, Inc.
