# Assinador de Documento com PGP (protótipo monólito)

Aplicação **Flask + SQLite + PGPy** em um único servidor: uma página com um
documento fixo, um formulário (nome + email) e uma assinatura digital PGP
gerada por trás de uma API própria.

A assinatura usa a biblioteca [PGPy](https://pgpy.readthedocs.io/), uma
implementação de OpenPGP **em Python puro** — não depende de instalar o
binário `gpg` nem de ter um `gpg-agent` rodando no sistema. Isso evita os
problemas comuns de ambiente (agente travado, PATH, IPC quebrado em pastas
sincronizadas do OneDrive etc.) e também facilita o deploy: em qualquer
host Linux gratuito, basta `pip install -r requirements.txt`.

## Como funciona (modelo de confiança)

Um navegador comum **não tem acesso à chave PGP privada do usuário**. Por
isso este protótipo usa o modelo de **recibo assinado pelo servidor**:

1. O servidor tem seu próprio par de chaves PGP (gerado automaticamente no
   primeiro start e salvo em `./server_key.asc`).
2. Quando alguém assina, o servidor monta um texto com:
   `hash SHA-256 do documento + nome + email + timestamp UTC`
3. Esse texto é assinado (equivalente a `gpg --clearsign`), usando a chave
   do servidor.
4. O resultado (o "recibo") é guardado no SQLite e devolvido para o usuário.
5. Qualquer pessoa pode pegar esse recibo + a chave pública do servidor
   (endpoint `/api/public-key`) e verificar **offline** — com `gpg --verify`
   (o formato gerado é PGP padrão) ou com a própria PGPy — sem confiar em
   mais nada além da matemática do PGP, para confirmar que aqueles dados
   não foram alterados depois de assinados.

Isso não é "o usuário assinando com a própria chave PGP" (não é
não-repúdio no sentido forte) — é uma prova de integridade e um carimbo de
tempo criptográfico de que o consentimento foi dado com aqueles dados
exatos. Veja "Próximos passos" para evoluir para assinatura com a chave do
próprio usuário.

## Requisitos

- Python 3.9+
- Nenhuma dependência de sistema — tudo é resolvido pelo `pip install`
  (não precisa de GnuPG/Gpg4win instalado).

## Como rodar

```bash
cd pgp-signer
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

python3 app.py
```

Abra **http://localhost:5000**. Na primeira execução o app vai:
- gerar automaticamente um par de chaves PGP e salvar em `./server_key.asc`
  (sem passphrase, para simplificar o protótipo — veja "Próximos passos");
- criar o arquivo `signatures.db` (SQLite) com a tabela de assinaturas.

Ambos os arquivos já estão no `.gitignore` — não são versionados, ficam
locais/no volume do servidor. **`server_key.asc` contém a chave privada:
trate-o como segredo e faça backup dele** (se perder, não dá para
revalidar as assinaturas antigas nem gerar novas com a mesma identidade).

## Endpoints da API

| Método | Rota                        | Descrição                                              |
|--------|------------------------------|----------------------------------------------------------|
| GET    | `/api/document`               | Retorna o texto do documento e seu hash SHA-256          |
| POST   | `/api/sign`                   | Body: `{"name": "...", "email": "..."}` → gera e guarda a assinatura |
| GET    | `/api/signatures/<id>`        | Retorna o recibo salvo e revalida a assinatura (`verified: true/false`) |
| GET    | `/api/public-key`             | Retorna a chave pública (ASCII-armored) do servidor       |

## Trocando o documento

Edite `documento.txt` — o conteúdo é lido em tempo real a cada requisição
(o hash mostrado na tela e usado na assinatura é recalculado automaticamente).

## Onde hospedar de graça

Como pediu algo simples e gratuito, sem precisar escalar:

- **Fly.io** ou **Railway** (free tier) rodando este mesmo Flask + um
  volume persistente pequeno para `signatures.db` e `server_key.asc`.
  Como agora não há dependência de `gpg`/`gpg-agent`, qualquer imagem
  Python padrão (ex.: `python:3.12-slim`) já basta — não precisa instalar
  mais nada no Dockerfile além do `pip install -r requirements.txt`.
- Alternativa ainda mais simples para o banco: trocar o SQLite por
  **Turso** (SQLite gerenciado, tier grátis) se quiser o banco fora do
  disco do servidor.
- Evite Vercel/Netlify serverless para isso: funções serverless não têm
  disco persistente, e você perderia o SQLite e o `server_key.asc` a cada
  deploy/cold start.

## O que eu expandiria primeiro

Em ordem de prioridade:

1. **Assinatura com a chave do próprio usuário (PGP "de verdade")**
   Integrar [OpenPGP.js](https://openpgpjs.org/) no frontend: o usuário
   cola sua chave pública (ou gera um par no navegador), assina o texto
   canônico *no cliente*, e o servidor só recebe e **verifica** a
   assinatura (em vez de criá-la). Isso muda o modelo de "recibo do
   servidor" para "assinatura de próprio punho" de verdade.

2. **Passphrase na chave do servidor + segredo fora do código**
   Hoje a chave é gerada sem passphrase para simplificar. Em produção,
   proteja `server_key.asc` com uma passphrase guardada em variável de
   ambiente/secret manager, e faça backup seguro dele.

3. **Confirmação por email**
   Enviar um link de confirmação para o email informado antes de gravar a
   assinatura como válida, evitando que alguém assine em nome de outra
   pessoa só digitando o email dela.

4. **Página de verificação pública**
   Uma rota `/verificar/<id>` amigável (HTML, não só JSON) onde qualquer
   um cola o ID do recibo e vê "✅ assinatura válida, não foi alterada"
   sem precisar rodar `gpg` na mão.

5. **Rate limiting e proteção anti-spam** no `/api/sign` (ex.: Flask-Limiter),
   já que hoje qualquer request pode gerar uma assinatura.

6. **Exportar o recibo em PDF** com o texto assinado + QR code apontando
   para `/api/signatures/<id>`, para dar a sensação de "documento assinado"
   que a pessoa pode guardar.
