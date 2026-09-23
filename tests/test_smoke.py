"""Smoke tests — run against SQLite in a temp dir so no external DB is needed.

    DB_TYPE=sqlite FASTPASSWORD_DB=/tmp/t.sqlite \
    FASTPASSWORD_RECOVERY_KEY=$(python -m fastpassword.crypto genkey | cut -d= -f2) pytest -q
"""
import base64
import os

os.environ.setdefault("DB_TYPE", "sqlite")
os.environ.setdefault("FASTPASSWORD_DB", "data/test-fastpassword.sqlite")
os.environ.setdefault("FASTPASSWORD_SECRET", "test-secret-pepper")

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402

if not os.environ.get("FASTPASSWORD_RECOVERY_KEY"):
    raw = X25519PrivateKey.generate().private_bytes_raw()
    os.environ["FASTPASSWORD_RECOVERY_KEY"] = base64.urlsafe_b64encode(raw).decode().rstrip("=")

from fastpassword import crypto, db, imports  # noqa: E402

# fresh DB for the test run
_path = os.environ["FASTPASSWORD_DB"]
if os.path.exists(_path):
    os.remove(_path)
db.init()


def _who(email="tester@example.com"):
    who = {"sub": email, "email": email, "name": "Tester"}
    db.provision(who)
    db.ensure_personal_vault(who)
    return who


def test_crypto_roundtrip():
    key = crypto.random_key()
    blob = crypto.aes_encrypt(key, b"top secret")
    assert crypto.aes_decrypt(key, blob) == b"top secret"


def test_seal_unseal_with_recovery_key():
    priv = crypto.recovery_private()
    pub = crypto.recovery_public()
    sealed = crypto.seal(pub, b"vault-key-bytes")
    assert crypto.unseal(priv, sealed) == b"vault-key-bytes"


def test_strength_and_fingerprint():
    assert crypto.strength("password") < 20
    assert crypto.strength("Gx7!qm2Zpv93Lw#eTn1B") >= 60
    assert crypto.fingerprint("abc") == crypto.fingerprint("abc")
    assert crypto.fingerprint("abc") != crypto.fingerprint("abd")


def test_item_lifecycle_and_reveal():
    who = _who()
    db.ensure_personal_vault(who)
    vid = db.vaults_for(who)[0]["id"]
    iid = db.create_item(who, vid, type="login", title="GitHub", url="https://github.com",
                         username="octocat", fields={"password": "S3cret-Passw0rd!", "notes": "2fa on"})
    assert iid
    it = db.item(iid)
    assert it["title"] == "GitHub"
    assert it["has_password"] == 1
    assert it["enc_blob"] and "S3cret" not in it["enc_blob"]  # ciphertext, not plaintext
    fields = db.reveal(who, iid)
    assert fields["password"] == "S3cret-Passw0rd!"
    assert fields["notes"] == "2fa on"


def test_optimistic_locking_conflict():
    who = _who()
    vid = db.vaults_for(who)[0]["id"]
    iid = db.create_item(who, vid, title="X", fields={"password": "aaaaaaaaaa"})
    ok = db.update_item(who, iid, title="X2", url="", username="", fields={"password": "bbbbbbbbbb"}, version=1)
    assert ok["version"] == 2
    conflict = db.update_item(who, iid, title="X3", url="", username="", fields={}, version=1)
    assert conflict["conflict"] is True


def test_sharing_and_access_control():
    owner = _who("owner@example.com")
    vid = db.create_vault(owner, "Team", "shared")
    iid = db.create_item(owner, vid, title="DB creds", type="credential",
                         fields={"secret": "postgres://x"})
    stranger = _who("stranger@example.com")
    assert db.viewable_item(stranger, iid) is None       # no access before sharing
    ok, _ = db.share_vault(owner, vid, "stranger@example.com", "viewer")
    assert ok
    assert db.viewable_item(stranger, iid) is not None    # can view after sharing
    assert db.can_edit_vault(stranger, vid) is False       # viewer cannot edit
    assert db.reveal(stranger, iid)["secret"] == "postgres://x"


def test_pending_invite_claimed_on_login():
    owner = _who("o2@example.com")
    vid = db.create_vault(owner, "Preinvite", "shared")
    db.share_vault(owner, vid, "newcomer@example.com", "member")
    assert db.pending_invites(vid)
    newcomer = _who("newcomer@example.com")   # provision() claims the invite
    assert any(v["id"] == vid for v in db.vaults_for(newcomer))


def test_password_health():
    who = _who("health@example.com")
    vid = db.vaults_for(who)[0]["id"]
    db.create_item(who, vid, title="weak", fields={"password": "12345"})
    db.create_item(who, vid, title="reuse-a", fields={"password": "Repeated-Pw-123"})
    db.create_item(who, vid, title="reuse-b", fields={"password": "Repeated-Pw-123"})
    report = db.health_report(who)
    assert any(i["title"] == "weak" for i in report["weak"])
    assert len(report["reused"]) >= 2


def test_import_export_roundtrip():
    who = _who("io@example.com")
    vid = db.vaults_for(who)[0]["id"]
    csv_text = "title,url,username,password,notes\nMail,https://mail.com,me,Pw!,hi\n"
    n = imports.import_rows(who, vid, imports.parse_csv(csv_text))
    assert n == 1
    blob = imports.export_encrypted(who, "correct horse battery")
    assert b"fastpassword-encrypted-backup" in blob
