"""CSV import and encrypted backup export.

Import understands the common export shapes (1Password, Bitwarden, Chrome/Edge,
LastPass): it maps by header name, case-insensitively. Export produces a
passphrase-protected JSON blob (scrypt + AES-256-GCM) so plaintext never lands on
disk unless the user explicitly asks for a plaintext CSV.
"""
from __future__ import annotations

import csv
import io
import json
import os

from . import crypto, db

# header alias → canonical field
_TITLE = {"title", "name", "account", "item", "display name"}
_URL = {"url", "website", "login_uri", "uri", "web site", "urls"}
_USER = {"username", "user", "login_username", "login", "email", "user name"}
_PASS = {"password", "login_password", "pass"}
_NOTE = {"notes", "note", "comments", "extra"}
_TYPE = {"type"}


def _pick(rowmap: dict, names: set) -> str:
    for k, v in rowmap.items():
        if k in names and v:
            return v.strip()
    return ""


def parse_csv(text: str) -> list[dict]:
    """Return a list of normalized import rows from CSV text."""
    reader = csv.DictReader(io.StringIO(text))
    out = []
    for raw in reader:
        rowmap = {(k or "").strip().lower(): (v or "") for k, v in raw.items()}
        title = _pick(rowmap, _TITLE)
        url = _pick(rowmap, _URL)
        username = _pick(rowmap, _USER)
        password = _pick(rowmap, _PASS)
        notes = _pick(rowmap, _NOTE)
        if not any((title, url, username, password)):
            continue
        kind = _pick(rowmap, _TYPE).lower()
        item_type = "credential" if kind in ("credential", "api", "api credential", "secret") else "login"
        out.append({
            "type": item_type,
            "title": title or url or username or "Imported item",
            "url": url, "username": username,
            "fields": {"password": password, "notes": notes} if password or notes else {},
        })
    return out


def import_rows(who, vault_id, rows: list[dict]) -> int:
    n = 0
    for r in rows:
        if db.create_item(who, vault_id, type=r["type"], title=r["title"],
                          url=r["url"], username=r["username"], fields=r["fields"]) is not None:
            n += 1
    if n:
        db.audit(who, "import", vault_id=vault_id, detail=f"{n} item(s)")
    return n


# ── export ───────────────────────────────────────────────────────────────────
def _export_payload(who, vault_ids=None) -> dict:
    vaults = db.vaults_for(who)
    if vault_ids:
        vaults = [v for v in vaults if v["id"] in vault_ids]
    out = {"format": "fastpassword-backup", "version": 1, "vaults": []}
    for v in vaults:
        vitems = []
        for it in db.items_in_vault(v["id"]):
            fields = db.reveal(who, it["id"]) or {}
            vitems.append({"type": it["type"], "title": it["title"], "url": it["url"],
                           "username": it["username"], "fields": fields})
        out["vaults"].append({"name": v["name"], "items": vitems})
    return out


def export_encrypted(who, passphrase: str, vault_ids=None) -> bytes:
    """Passphrase-protected backup: scrypt-derived key + AES-256-GCM over JSON."""
    payload = json.dumps(_export_payload(who, vault_ids)).encode()
    salt = os.urandom(16)
    key = crypto.derive_kek(passphrase, salt)
    blob = crypto.aes_encrypt(key, payload)
    envelope = {"format": "fastpassword-encrypted-backup", "kdf": "scrypt", "n": 16384,
                "salt": crypto.b64e(salt), "data": blob}
    return json.dumps(envelope, indent=2).encode()


def export_plaintext_csv(who, vault_ids=None) -> str:
    """Plaintext CSV (1Password-compatible headers). Caller must gate this."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Title", "URL", "Username", "Password", "Notes", "Type", "Vault"])
    for v in _export_payload(who, vault_ids)["vaults"]:
        for it in v["items"]:
            f = it["fields"]
            writer.writerow([it["title"], it["url"], it["username"],
                             f.get("password") or f.get("secret", ""), f.get("notes", ""),
                             it["type"], v["name"]])
    return buf.getvalue()
