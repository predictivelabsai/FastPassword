# FastPassword

A private, server-rendered **password & credentials manager** for teams — like a
self-hosted 1Password for the FastSME suite. Store logins and API keys as
encrypted items grouped into **vaults** you keep private or share with teammates.
Part of the open-source [FastSME](https://fastsme.com) suite.

## Stack

- [FastHTML](https://fastht.ml) (Starlette/Uvicorn), server-rendered Python UI
- **PostgreSQL** (default, schema `fast_password`) or **SQLite** via a `DB_TYPE` toggle
- Envelope encryption (`cryptography`): per-vault AES-256-GCM keys, X25519 sealed boxes
- Google SSO (Authlib OIDC) as the primary sign-in — no separate master password
- FastAPI Bearer-token REST API at `/api/v1`, modeled on the 1Password Connect API,
  with Swagger / ReDoc / OpenAPI docs

## API

A REST API modeled on the [1Password Connect API](https://developer.1password.com/docs/connect/connect-api-reference/)
lives under `/api/v1`, authenticated with a **Bearer token** minted in-app at
**Settings → API tokens** (shown once, prefixed `fpw_`). Token scopes: `read`
(list/read items, **including secret field values** — reading an item reveals its
concealed fields, as in 1Password Connect) and `write` (create/delete items). A
token only reaches the vaults its owner belongs to.

| Docs | URL |
|---|---|
| Swagger UI | `/api/docs` |
| ReDoc | `/api/redoc` |
| OpenAPI JSON | `/api/openapi.json` |

```bash
curl -H "Authorization: Bearer fpw_…" https://password.fastsme.com/api/v1/vaults
curl -H "Authorization: Bearer fpw_…" https://password.fastsme.com/api/v1/vaults/1/items/2
```

Endpoints: `GET /v1/vaults`, `GET /v1/vaults/{id}`, `GET /v1/vaults/{id}/items`,
`GET /v1/vaults/{id}/items/{id}` (returns fields), `POST /v1/vaults/{id}/items`,
`DELETE /v1/vaults/{id}/items/{id}`, `GET /v1/health-report`, `GET /v1/me`.

## Security model

Every **vault** has a random 256-bit key. Item **secret** fields (password, API
key, notes) are stored as AES-256-GCM ciphertext under that key; only non-secret
metadata (title, URL, username) stays in plaintext columns so search and password
health work without decrypting everything.

Each vault key is **sealed** to the deployment **recovery key**
(`FASTPASSWORD_RECOVERY_KEY`, an X25519 private key held only in the environment).
This is the **SSO auto-unlock** model: after a user authenticates with Google, the
running server unseals the keys for the vaults they belong to — there is no
separate master passphrase to remember, and a forgotten sign-in never loses data.

> ⚠️ **Trade-off:** whoever holds `FASTPASSWORD_RECOVERY_KEY` (or the running
> server) can decrypt every vault. Guard it like a root secret. **Losing it makes
> every vault permanently undecryptable — back it up out of band.**

Password health (weak / reused / old) is computed from a strength score and a
keyed HMAC fingerprint stored per item — never from stored plaintext.

## Features

- **Vaults & sharing** — a private Personal vault per user, plus shared vaults you
  invite teammates into by email. Roles: Owner, Admin (manage sharing), Member
  (add/edit), Viewer (read-only). Pending invites are claimed on first sign-in.
- **Item types** — logins and API keys / credentials.
- **Password generator** — client-side (Web Crypto), configurable length + classes.
- **Password health** — weak, reused, and stale-password audit with an overall score.
- **Import / export** — import CSV from 1Password / Bitwarden / Chrome / LastPass;
  export a passphrase-encrypted backup (or a plaintext CSV, gated by a confirm).
- **Version history & activity log** per item / vault.

## Run locally

```bash
uv pip install -r requirements.txt

# A recovery key is required (generate one, then export it):
export FASTPASSWORD_RECOVERY_KEY=$(python -m fastpassword.crypto genkey | cut -d= -f2)

# Option A — SQLite (no external DB)
DB_TYPE=sqlite FASTPASSWORD_DB=data/fastpassword.sqlite python app.py

# Option B — PostgreSQL (reads .env)
python app.py            # DB_TYPE=postgresql is the default
```

Open http://localhost:5031. In development, `/auth/dev` signs you in without SSO.

Run the tests (SQLite, self-contained):

```bash
DB_TYPE=sqlite FASTPASSWORD_DB=data/test.sqlite \
  FASTPASSWORD_RECOVERY_KEY=$(python -m fastpassword.crypto genkey | cut -d= -f2) \
  pytest -q
```

## Configuration (`.env`)

| Variable | Purpose |
|---|---|
| `DB_TYPE` | `postgresql` (default) or `sqlite` |
| `DATABASE_URL` / `DATABASE_URL_PROD` | Postgres DSN (`postgres://` accepted); the second is a fallback |
| `DB_SCHEMA` | Postgres schema, default `fast_password` (auto-created) |
| `FASTPASSWORD_DB` | SQLite path (when `DB_TYPE=sqlite`) |
| `FASTPASSWORD_SECRET` | Session signing secret + health-fingerprint pepper |
| `FASTPASSWORD_RECOVERY_KEY` | **Required.** X25519 vault recovery key (`python -m fastpassword.crypto genkey`) |
| `FASTPASSWORD_PORT` | Port, default `5031` |
| `FASTPASSWORD_OLD_DAYS` | Password-health "old" threshold in days (default 365) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Enable Google SSO |
| `GOOGLE_ALLOWED_DOMAINS` | Optional comma-separated email-domain allow-list |
| `POSTMARK_API_TOKEN` / `FROM_EMAIL` | Enable local-account verify/reset emails (fallback auth) |

See `.env.coolify.sample`. Never commit real secrets — `.env` and `data/` are gitignored.

## Google SSO

FastPassword reuses the shared FastSME OAuth client. Register this app's redirect
URIs in Google Cloud Console → **APIs & Services → Credentials** → the OAuth 2.0
client:

- `https://password.fastsme.com/auth/callback`
- `http://localhost:5031/auth/callback` (for local dev)

Scopes: `openid email profile`. The Google button appears once
`GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are set.

## Deploy (Coolify)

Single-service Docker with a persistent `fastpassword-data` volume; deploys from
`main` to `password.fastsme.com`. Set the env vars above in Coolify — **especially
a persistent `FASTPASSWORD_RECOVERY_KEY`** — and keep the `/health` check.
