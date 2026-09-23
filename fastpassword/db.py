"""FastPassword domain data layer (backend-agnostic via .database).

Security model (see crypto.py): every vault owns a random Vault Key sealed to the
deployment recovery key. Item *secret* fields live in an AES-GCM blob under the
Vault Key; non-secret metadata (title, url, username, tags, timestamps) stays in
plaintext columns so listing, search and password-health work without decrypting
each row. Because the server holds the recovery key, an authenticated member can
always decrypt the vaults they belong to ("SSO auto-unlock").
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta, timezone

from . import crypto
from .database import execute, init_schema, insert, row, rows, tx

API_SCOPES = ("read", "write")

ITEM_TYPES = ("login", "credential")
ROLES = ("owner", "admin", "member", "viewer")
EDIT_ROLES = ("owner", "admin", "member")
MANAGE_ROLES = ("owner", "admin")
OLD_PASSWORD_DAYS = int(__import__("os").getenv("FASTPASSWORD_OLD_DAYS", "365"))
WEAK_THRESHOLD = 50


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT NOT NULL,
  is_admin INTEGER DEFAULT 0, created_at TEXT);
CREATE TABLE IF NOT EXISTS vaults(
  id {PK},
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  owner_id TEXT NOT NULL,
  kind TEXT DEFAULT 'shared',
  enc_vault_key TEXT NOT NULL,
  created_at TEXT, updated_at TEXT, deleted_at TEXT);
CREATE TABLE IF NOT EXISTS vault_members(
  vault_id INTEGER NOT NULL, user_id TEXT NOT NULL, role TEXT DEFAULT 'member',
  invited_by TEXT, created_at TEXT, PRIMARY KEY(vault_id, user_id));
CREATE TABLE IF NOT EXISTS vault_invites(
  id {PK}, vault_id INTEGER NOT NULL, email TEXT NOT NULL, role TEXT DEFAULT 'member',
  invited_by TEXT, created_at TEXT, UNIQUE(vault_id, email));
CREATE TABLE IF NOT EXISTS items(
  id {PK},
  vault_id INTEGER NOT NULL,
  type TEXT NOT NULL DEFAULT 'login',
  title TEXT NOT NULL,
  url TEXT DEFAULT '',
  username TEXT DEFAULT '',
  favorite INTEGER DEFAULT 0,
  enc_blob TEXT DEFAULT '',
  has_password INTEGER DEFAULT 0,
  pw_strength INTEGER DEFAULT 0,
  pw_length INTEGER DEFAULT 0,
  pw_fingerprint TEXT DEFAULT '',
  pw_updated_at TEXT,
  version INTEGER DEFAULT 1,
  created_by TEXT, updated_by TEXT,
  created_at TEXT, updated_at TEXT, deleted_at TEXT);
CREATE TABLE IF NOT EXISTS item_versions(
  id {PK}, item_id INTEGER, version INTEGER,
  title TEXT, url TEXT, username TEXT, enc_blob TEXT, created_by TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS audit_log(
  id {PK}, user_id TEXT, action TEXT, vault_id INTEGER, item_id INTEGER,
  detail TEXT DEFAULT '', created_at TEXT);
CREATE TABLE IF NOT EXISTS api_tokens(
  id {PK}, user_id TEXT NOT NULL, name TEXT DEFAULT '', prefix TEXT, token_hash TEXT NOT NULL,
  scopes TEXT DEFAULT 'read', created_at TEXT, last_used_at TEXT, expires_at TEXT, revoked_at TEXT);
CREATE TABLE IF NOT EXISTS app_meta(key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX IF NOT EXISTS idx_tokens_hash ON api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_tokens_user ON api_tokens(user_id, revoked_at);
CREATE INDEX IF NOT EXISTS idx_items_vault ON items(vault_id, deleted_at);
CREATE INDEX IF NOT EXISTS idx_items_fp ON items(pw_fingerprint);
CREATE INDEX IF NOT EXISTS idx_members_user ON vault_members(user_id);
CREATE INDEX IF NOT EXISTS idx_invites_email ON vault_invites(email)
"""


def init():
    init_schema(SCHEMA)


# ── vault-key cache (perf only; source of truth is the sealed blob) ───────────
_VK_CACHE: dict[int, tuple[bytes, float]] = {}
_VK_TTL = 300


def _vault_key(vault_id: int, enc_vault_key: str) -> bytes:
    hit = _VK_CACHE.get(vault_id)
    if hit and hit[1] > time.time():
        return hit[0]
    vk = crypto.unseal(crypto.recovery_private(), enc_vault_key)
    _VK_CACHE[vault_id] = (vk, time.time() + _VK_TTL)
    return vk


def _forget_vault_key(vault_id: int):
    _VK_CACHE.pop(vault_id, None)


# ── users ────────────────────────────────────────────────────────────────────
def provision(who: dict):
    execute(
        "INSERT INTO users(id,email,name,created_at) VALUES(?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET email=excluded.email,name=excluded.name",
        (who["sub"], who["email"], who.get("name") or who["email"].split("@")[0], now()))
    claim_invites(who["sub"])


def get_user(uid):
    return row("SELECT * FROM users WHERE id=?", (uid,))


def is_admin(who):
    if not who:
        return False
    u = get_user(who["sub"])
    return bool(u and u.get("is_admin"))


def get_meta(key):
    r = row("SELECT value FROM app_meta WHERE key=?", (key,))
    return r["value"] if r else None


def set_meta(key, value):
    execute("INSERT INTO app_meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def audit(who, action, *, vault_id=None, item_id=None, detail=""):
    execute("INSERT INTO audit_log(user_id,action,vault_id,item_id,detail,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (who["sub"] if who else None, action, vault_id, item_id, detail, now()))


def recent_activity(who, limit=40):
    ids = [v["id"] for v in vaults_for(who)]
    if not ids:
        return []
    placeholders = ",".join("?" for _ in ids)
    return rows(
        f"SELECT a.*, u.name user_name FROM audit_log a LEFT JOIN users u ON u.id=a.user_id "
        f"WHERE a.vault_id IN ({placeholders}) ORDER BY a.created_at DESC LIMIT ?",
        (*ids, limit))


# ── vaults ───────────────────────────────────────────────────────────────────
def create_vault(who, name="Personal", description="", kind="shared"):
    vk = crypto.random_key()
    enc = crypto.seal(crypto.recovery_public(), vk)
    ts = now()
    with tx() as s:
        vid = s.insert(
            "INSERT INTO vaults(name,description,owner_id,kind,enc_vault_key,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (name or "Vault", description, who["sub"], kind, enc, ts, ts))
        s.execute(
            "INSERT INTO vault_members(vault_id,user_id,role,invited_by,created_at) "
            "VALUES(?,?,'owner',?,?)", (vid, who["sub"], who["sub"], ts))
    audit(who, "vault.create", vault_id=vid, detail=name)
    return vid


def ensure_personal_vault(who):
    """Guarantee the user has at least one vault to land in on first sign-in."""
    if not vaults_for(who):
        return create_vault(who, "Personal", "Your private vault.", kind="personal")
    return None


def vault(vid):
    return row("SELECT * FROM vaults WHERE id=? AND deleted_at IS NULL", (vid,))


def membership(who, vid):
    if not who:
        return None
    return row("SELECT * FROM vault_members WHERE vault_id=? AND user_id=?", (vid, who["sub"]))


def vaults_for(who):
    if not who:
        return []
    return rows(
        "SELECT v.*, m.role, "
        "(SELECT count(*) FROM items i WHERE i.vault_id=v.id AND i.deleted_at IS NULL) item_count, "
        "(SELECT count(*) FROM vault_members mm WHERE mm.vault_id=v.id) member_count "
        "FROM vaults v JOIN vault_members m ON m.vault_id=v.id "
        "WHERE m.user_id=? AND v.deleted_at IS NULL ORDER BY v.kind DESC, v.name",
        (who["sub"],))


def can_view_vault(who, vid):
    return membership(who, vid) is not None


def can_edit_vault(who, vid):
    m = membership(who, vid)
    return bool(m and m["role"] in EDIT_ROLES)


def can_manage_vault(who, vid):
    m = membership(who, vid)
    return bool(m and m["role"] in MANAGE_ROLES)


def rename_vault(who, vid, name, description):
    if not can_manage_vault(who, vid):
        return False
    execute("UPDATE vaults SET name=?,description=?,updated_at=? WHERE id=?",
            (name or "Vault", description or "", now(), vid))
    audit(who, "vault.rename", vault_id=vid, detail=name)
    return True


def delete_vault(who, vid):
    m = membership(who, vid)
    if not m or m["role"] != "owner":
        return False
    execute("UPDATE vaults SET deleted_at=? WHERE id=?", (now(), vid))
    _forget_vault_key(vid)
    audit(who, "vault.delete", vault_id=vid)
    return True


# ── sharing ──────────────────────────────────────────────────────────────────
def vault_members(vid):
    return rows(
        "SELECT m.*, u.name, u.email FROM vault_members m LEFT JOIN users u ON u.id=m.user_id "
        "WHERE m.vault_id=? ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 "
        "WHEN 'member' THEN 2 ELSE 3 END, m.created_at", (vid,))


def pending_invites(vid):
    return rows("SELECT * FROM vault_invites WHERE vault_id=? ORDER BY created_at", (vid,))


def share_vault(who, vid, email, role="member"):
    """Grant access. If the invitee has an account, add them directly; otherwise
    record a pending invite that is claimed on their first sign-in."""
    if not can_manage_vault(who, vid):
        return False, "You do not have permission to share this vault."
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return False, "Enter a valid email address."
    if role not in ROLES or role == "owner":
        role = "member"
    target = row("SELECT id FROM users WHERE id=?", (email,))
    ts = now()
    if target:
        if membership({"sub": email}, vid):
            return False, "That person already has access."
        execute("INSERT INTO vault_members(vault_id,user_id,role,invited_by,created_at) "
                "VALUES(?,?,?,?,?)", (vid, email, role, who["sub"], ts))
        audit(who, "vault.share", vault_id=vid, detail=f"{email} ({role})")
        return True, f"{email} now has access."
    execute("INSERT INTO vault_invites(vault_id,email,role,invited_by,created_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(vault_id,email) DO UPDATE SET role=excluded.role", (vid, email, role, who["sub"], ts))
    audit(who, "vault.invite", vault_id=vid, detail=f"{email} ({role})")
    return True, f"Invited {email}. They will get access when they sign in."


def claim_invites(user_id):
    """Turn any pending invites for this email into memberships (called on login)."""
    invites = rows("SELECT * FROM vault_invites WHERE email=?", (user_id,))
    for inv in invites:
        execute("INSERT INTO vault_members(vault_id,user_id,role,invited_by,created_at) "
                "VALUES(?,?,?,?,?) ON CONFLICT(vault_id,user_id) DO NOTHING",
                (inv["vault_id"], user_id, inv["role"], inv["invited_by"], now()))
        execute("DELETE FROM vault_invites WHERE id=?", (inv["id"],))


def set_member_role(who, vid, user_id, role):
    if not can_manage_vault(who, vid) or role not in ROLES:
        return False
    owner = vault(vid)
    if user_id == owner["owner_id"]:
        return False  # never demote the owner
    execute("UPDATE vault_members SET role=? WHERE vault_id=? AND user_id=?", (role, vid, user_id))
    audit(who, "vault.role", vault_id=vid, detail=f"{user_id} -> {role}")
    return True


def revoke_member(who, vid, user_id):
    if not can_manage_vault(who, vid):
        return False
    owner = vault(vid)
    if user_id == owner["owner_id"]:
        return False
    execute("DELETE FROM vault_members WHERE vault_id=? AND user_id=?", (vid, user_id))
    audit(who, "vault.revoke", vault_id=vid, detail=user_id)
    return True


def revoke_invite(who, vid, invite_id):
    if not can_manage_vault(who, vid):
        return False
    execute("DELETE FROM vault_invites WHERE id=? AND vault_id=?", (invite_id, vid))
    return True


# ── items ────────────────────────────────────────────────────────────────────
def _secret_of(fields: dict) -> str:
    """Pick the primary secret used for password-health from item fields."""
    return fields.get("password") or fields.get("secret") or ""


def _health_columns(fields: dict) -> dict:
    secret = _secret_of(fields)
    if not secret:
        return {"has_password": 0, "pw_strength": 0, "pw_length": 0,
                "pw_fingerprint": "", "pw_updated_at": None}
    return {"has_password": 1, "pw_strength": crypto.strength(secret),
            "pw_length": len(secret), "pw_fingerprint": crypto.fingerprint(secret),
            "pw_updated_at": now()}


def items_in_vault(vid, q=None, include_deleted=False):
    where = ["vault_id=?"]
    args = [vid]
    if not include_deleted:
        where.append("deleted_at IS NULL")
    if q:
        where.append("(title LIKE ? OR url LIKE ? OR username LIKE ?)")
        like = f"%{q}%"
        args += [like, like, like]
    return rows(f"SELECT * FROM items WHERE {' AND '.join(where)} "
                "ORDER BY favorite DESC, LOWER(title)", args)


def search_all(who, q):
    ids = [v["id"] for v in vaults_for(who)]
    if not ids or not q:
        return []
    placeholders = ",".join("?" for _ in ids)
    like = f"%{q}%"
    return rows(
        f"SELECT i.*, v.name vault_name FROM items i JOIN vaults v ON v.id=i.vault_id "
        f"WHERE i.vault_id IN ({placeholders}) AND i.deleted_at IS NULL "
        "AND (i.title LIKE ? OR i.url LIKE ? OR i.username LIKE ?) "
        "ORDER BY i.favorite DESC, LOWER(i.title)", (*ids, like, like, like))


def item(iid):
    return row("SELECT * FROM items WHERE id=?", (iid,))


def viewable_item(who, iid):
    it = item(iid)
    if not it or it["deleted_at"] or not can_view_vault(who, it["vault_id"]):
        return None
    return it


def _decrypt(it):
    if not it["enc_blob"]:
        return {}
    v = vault(it["vault_id"])
    return json.loads(crypto.aes_decrypt(_vault_key(v["id"], v["enc_vault_key"]), it["enc_blob"]).decode())


def peek(who, iid):
    """Decrypt an item's fields WITHOUT logging a reveal (for building the UI)."""
    it = viewable_item(who, iid)
    return _decrypt(it) if it else None


def reveal(who, iid):
    """Return an item's decrypted secret fields (membership required), audited."""
    it = viewable_item(who, iid)
    if not it:
        return None
    fields = _decrypt(it)
    audit(who, "item.reveal", vault_id=it["vault_id"], item_id=iid, detail=it["title"])
    return fields


def create_item(who, vid, *, type="login", title="Untitled", url="", username="", fields=None):
    if not can_edit_vault(who, vid):
        return None
    if type not in ITEM_TYPES:
        type = "login"
    v = vault(vid)
    fields = fields or {}
    vk = _vault_key(vid, v["enc_vault_key"])
    enc = crypto.aes_encrypt(vk, json.dumps(fields).encode()) if fields else ""
    hc = _health_columns(fields)
    ts = now()
    iid = insert(
        "INSERT INTO items(vault_id,type,title,url,username,enc_blob,has_password,pw_strength,"
        "pw_length,pw_fingerprint,pw_updated_at,created_by,updated_by,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (vid, type, title or "Untitled", url, username, enc, hc["has_password"], hc["pw_strength"],
         hc["pw_length"], hc["pw_fingerprint"], hc["pw_updated_at"], who["sub"], who["sub"], ts, ts))
    audit(who, "item.create", vault_id=vid, item_id=iid, detail=title)
    return iid


def update_item(who, iid, *, title, url, username, fields, version, type=None):
    it = item(iid)
    if not it or it["deleted_at"] or not can_edit_vault(who, it["vault_id"]):
        return None
    if it["version"] != int(version):
        return {"conflict": True, "version": it["version"]}
    v = vault(it["vault_id"])
    vk = _vault_key(v["id"], v["enc_vault_key"])
    enc = crypto.aes_encrypt(vk, json.dumps(fields).encode()) if fields else ""
    # Only refresh pw_updated_at when the primary secret actually changed.
    new_secret = _secret_of(fields)
    old_fp = it["pw_fingerprint"]
    new_fp = crypto.fingerprint(new_secret) if new_secret else ""
    if new_secret and new_fp == old_fp and it["pw_updated_at"]:
        hc = {"has_password": 1, "pw_strength": crypto.strength(new_secret),
              "pw_length": len(new_secret), "pw_fingerprint": new_fp,
              "pw_updated_at": it["pw_updated_at"]}
    else:
        hc = _health_columns(fields)
    ts = now()
    with tx() as s:
        s.execute(
            "INSERT INTO item_versions(item_id,version,title,url,username,enc_blob,created_by,created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (iid, it["version"], it["title"], it["url"], it["username"], it["enc_blob"], who["sub"], ts))
        s.execute(
            "UPDATE items SET type=?,title=?,url=?,username=?,enc_blob=?,has_password=?,pw_strength=?,"
            "pw_length=?,pw_fingerprint=?,pw_updated_at=?,version=version+1,updated_by=?,updated_at=? "
            "WHERE id=? AND version=?",
            (type or it["type"], title or "Untitled", url, username, enc, hc["has_password"],
             hc["pw_strength"], hc["pw_length"], hc["pw_fingerprint"], hc["pw_updated_at"],
             who["sub"], ts, iid, version))
    audit(who, "item.update", vault_id=it["vault_id"], item_id=iid, detail=title)
    return item(iid)


def toggle_favorite(who, iid):
    it = viewable_item(who, iid)
    if not it:
        return False
    execute("UPDATE items SET favorite=? WHERE id=?", (0 if it["favorite"] else 1, iid))
    return not it["favorite"]


def trash_item(who, iid):
    it = item(iid)
    if not it or not can_edit_vault(who, it["vault_id"]):
        return False
    execute("UPDATE items SET deleted_at=? WHERE id=?", (now(), iid))
    audit(who, "item.trash", vault_id=it["vault_id"], item_id=iid, detail=it["title"])
    return True


def move_item(who, iid, dest_vault_id):
    it = item(iid)
    if not it or it["deleted_at"] or not can_edit_vault(who, it["vault_id"]):
        return False
    if not can_edit_vault(who, dest_vault_id):
        return False
    src = vault(it["vault_id"])
    dest = vault(dest_vault_id)
    fields = {}
    if it["enc_blob"]:
        fields = json.loads(crypto.aes_decrypt(_vault_key(src["id"], src["enc_vault_key"]),
                                               it["enc_blob"]).decode())
    enc = crypto.aes_encrypt(_vault_key(dest["id"], dest["enc_vault_key"]),
                             json.dumps(fields).encode()) if fields else ""
    execute("UPDATE items SET vault_id=?,enc_blob=?,updated_by=?,updated_at=? WHERE id=?",
            (dest_vault_id, enc, who["sub"], now(), iid))
    audit(who, "item.move", vault_id=dest_vault_id, item_id=iid, detail=it["title"])
    return True


# ── item version history ─────────────────────────────────────────────────────
def item_versions(iid):
    return rows("SELECT id,version,title,created_at,created_by FROM item_versions "
                "WHERE item_id=? ORDER BY version DESC", (iid,))


def restore_item_version(who, iid, version_row_id):
    it = item(iid)
    if not it or it["deleted_at"] or not can_edit_vault(who, it["vault_id"]):
        return None
    snap = row("SELECT * FROM item_versions WHERE id=? AND item_id=?", (version_row_id, iid))
    if not snap:
        return None
    # The snapshot's enc_blob is already under this vault's key — re-decrypt to
    # refresh the plaintext metadata and health columns via the normal path.
    v = vault(it["vault_id"])
    fields = {}
    if snap["enc_blob"]:
        fields = json.loads(crypto.aes_decrypt(_vault_key(v["id"], v["enc_vault_key"]),
                                               snap["enc_blob"]).decode())
    return update_item(who, iid, title=snap["title"], url=snap["url"], username=snap["username"],
                       fields=fields, version=it["version"], type=it["type"])


# ── password health ──────────────────────────────────────────────────────────
def health_report(who):
    ids = [v["id"] for v in vaults_for(who)]
    if not ids:
        return {"weak": [], "reused": [], "old": [], "total": 0, "score": 100}
    placeholders = ",".join("?" for _ in ids)
    all_pw = rows(
        f"SELECT i.*, v.name vault_name FROM items i JOIN vaults v ON v.id=i.vault_id "
        f"WHERE i.vault_id IN ({placeholders}) AND i.deleted_at IS NULL AND i.has_password=1",
        tuple(ids))
    weak = [i for i in all_pw if i["pw_strength"] < WEAK_THRESHOLD]
    fp_counts: dict[str, int] = {}
    for i in all_pw:
        fp_counts[i["pw_fingerprint"]] = fp_counts.get(i["pw_fingerprint"], 0) + 1
    reused = [i for i in all_pw if fp_counts.get(i["pw_fingerprint"], 0) > 1]
    cutoff = (datetime.now(timezone.utc) - timedelta(days=OLD_PASSWORD_DAYS)).isoformat()
    old = [i for i in all_pw if (i["pw_updated_at"] or "") < cutoff]
    total = len(all_pw)
    flagged = len({i["id"] for i in weak} | {i["id"] for i in reused} | {i["id"] for i in old})
    score = 100 if total == 0 else round(100 * (total - flagged) / total)
    return {"weak": weak, "reused": reused, "old": old, "total": total, "score": score,
            "old_days": OLD_PASSWORD_DAYS}


# ── API tokens (Bearer auth for the /api/v1 REST API) ────────────────────────
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_api_token(who, name="", scopes="read", expires_days=None):
    """Mint a personal access token. Returns (plaintext_token, record). The
    plaintext is shown once and never stored — only its SHA-256 hash is kept."""
    wanted = [s for s in (scopes or "read").split(",") if s in API_SCOPES] or ["read"]
    if "write" in wanted and "read" not in wanted:
        wanted.insert(0, "read")
    token = "fpw_" + secrets.token_urlsafe(32)
    prefix = token[:12]
    expires_at = None
    if expires_days:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=int(expires_days))).isoformat()
    tid = insert(
        "INSERT INTO api_tokens(user_id,name,prefix,token_hash,scopes,created_at,expires_at) "
        "VALUES(?,?,?,?,?,?,?)",
        (who["sub"], name.strip() or "API token", prefix, _token_hash(token),
         ",".join(wanted), now(), expires_at))
    audit(who, "token.create", detail=f"{name} ({','.join(wanted)})")
    return token, row("SELECT * FROM api_tokens WHERE id=?", (tid,))


def list_api_tokens(who):
    return rows("SELECT * FROM api_tokens WHERE user_id=? AND revoked_at IS NULL "
                "ORDER BY created_at DESC", (who["sub"],))


def revoke_api_token(who, token_id):
    execute("UPDATE api_tokens SET revoked_at=? WHERE id=? AND user_id=?",
            (now(), token_id, who["sub"]))
    audit(who, "token.revoke", detail=str(token_id))
    return True


def resolve_api_token(token: str):
    """Validate a Bearer token → {'identity', 'scopes', 'token_id'} or None."""
    if not token or not token.startswith("fpw_"):
        return None
    rec = row("SELECT * FROM api_tokens WHERE token_hash=?", (_token_hash(token),))
    if not rec or rec["revoked_at"]:
        return None
    if rec["expires_at"] and rec["expires_at"] < now():
        return None
    u = get_user(rec["user_id"])
    if not u:
        return None
    execute("UPDATE api_tokens SET last_used_at=? WHERE id=?", (now(), rec["id"]))
    identity = {"sub": u["id"], "email": u["email"], "name": u["name"]}
    return {"identity": identity, "scopes": rec["scopes"].split(","), "token_id": rec["id"]}
