from __future__ import annotations
import os, secrets, threading

from dotenv import load_dotenv
from fasthtml.common import *
from starlette.responses import JSONResponse, RedirectResponse, Response

load_dotenv()
from fastpassword import account_auth, crypto, db, imports, views
from fastpassword.api import api
from fastpassword.version import RELEASE_DATE, VERSION

app, rt = fast_app(secret_key=os.getenv("FASTPASSWORD_SECRET") or secrets.token_hex(32))
app.mount("/api", api)


# Initialise the schema in the background so the server binds its port (and
# /health responds) immediately even when the remote Postgres is slow.
def _init_background():
    try:
        db.init()
        print("[init] schema ready")
    except Exception as exc:
        print(f"[init] deferred: {exc}")


threading.Thread(target=_init_background, name="init", daemon=True).start()


# ── identity ─────────────────────────────────────────────────────────────────
def who(session):
    return session.get("identity")


def guard(session):
    return who(session) or RedirectResponse("/", status_code=303)


def establish_identity(session, email, name=""):
    email = (email or "").strip().lower()
    identity = {"sub": email, "email": email, "name": name or email.split("@")[0]}
    db.provision(identity)          # also claims any pending vault invites
    try:
        db.ensure_personal_vault(identity)
    except Exception as exc:        # recovery key missing → surfaced on first use
        print(f"[vault] could not provision personal vault: {exc}")
    session["identity"] = identity


def _vaults(identity):
    return db.vaults_for(identity)


def _score(identity):
    try:
        return db.health_report(identity)["score"]
    except Exception:
        return None


# ── app: item lists ──────────────────────────────────────────────────────────
@rt("/")
def get(session):
    return views.landing_page(who(session))


@rt("/app")
def get(session):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    vaults = _vaults(identity)
    items = []
    for v in vaults:
        for it in db.items_in_vault(v["id"]):
            it["vault_name"] = v["name"]
            items.append(it)
    items.sort(key=lambda i: (-i["favorite"], i["title"].lower()))
    return views.items_view(identity, vaults, items, active="all", title="All items",
                            subtitle=f"{len(items)} item(s) across {len(vaults)} vault(s)",
                            health_score=_score(identity))


@rt("/vault/{vid:int}")
def get(session, vid: int, q: str = ""):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    v = db.vault(vid)
    if not v or not db.can_view_vault(identity, vid):
        return Response("Vault not found", status_code=404)
    m = db.membership(identity, vid)
    v = {**v, "role": m["role"], "item_count": 0, "member_count": 0}
    items = db.items_in_vault(vid, q.strip() or None)
    return views.items_view(identity, _vaults(identity), items, active=f"vault-{vid}",
                            title=v["name"], subtitle=v.get("description") or "",
                            vault=v, search=q, health_score=_score(identity))


@rt("/favorites")
def get(session):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    vaults = _vaults(identity)
    items = []
    for v in vaults:
        for it in db.items_in_vault(v["id"]):
            if it["favorite"]:
                it["vault_name"] = v["name"]
                items.append(it)
    return views.items_view(identity, vaults, items, active="favorites", title="Favorites",
                            health_score=_score(identity))


@rt("/search")
def get(session, q: str = ""):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    results = db.search_all(identity, q.strip()) if q.strip() else []
    return views.items_view(identity, _vaults(identity), results, active="search",
                            title=f"Search: “{q}”" if q else "Search",
                            subtitle=f"{len(results)} result(s)", search=q,
                            health_score=_score(identity))


# ── vaults ───────────────────────────────────────────────────────────────────
@rt("/vaults/new")
def get(session):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    return views.new_vault_page(identity, _vaults(identity))


@rt("/vaults/new")
def post(session, name: str = "", description: str = ""):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    if not name.strip():
        return views.new_vault_page(identity, _vaults(identity), msg="Please enter a vault name.")
    try:
        vid = db.create_vault(identity, name.strip(), description.strip())
    except crypto.RecoveryKeyMissing as exc:
        return views.new_vault_page(identity, _vaults(identity), msg=str(exc))
    return RedirectResponse(f"/vault/{vid}", status_code=303)


@rt("/vault/{vid:int}/share")
def get(session, vid: int):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    if not db.can_manage_vault(identity, vid):
        return Response("Not permitted", status_code=403)
    v = db.vault(vid)
    m = db.membership(identity, vid)
    return views.share_page(identity, _vaults(identity), {**v, "role": m["role"]},
                            db.vault_members(vid), db.pending_invites(vid))


@rt("/vault/{vid:int}/share")
def post(session, vid: int, email: str = "", role: str = "member"):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    ok, msg = db.share_vault(identity, vid, email, role)
    v = db.vault(vid)
    m = db.membership(identity, vid)
    return views.share_page(identity, _vaults(identity), {**v, "role": m["role"]},
                            db.vault_members(vid), db.pending_invites(vid), msg=msg)


@rt("/vault/{vid:int}/role")
def post(session, vid: int, user_id: str, role: str):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    db.set_member_role(identity, vid, user_id, role)
    return RedirectResponse(f"/vault/{vid}/share", status_code=303)


@rt("/vault/{vid:int}/revoke")
def post(session, vid: int, user_id: str):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    db.revoke_member(identity, vid, user_id)
    return RedirectResponse(f"/vault/{vid}/share", status_code=303)


@rt("/vault/{vid:int}/revoke-invite")
def post(session, vid: int, invite_id: int):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    db.revoke_invite(identity, vid, invite_id)
    return RedirectResponse(f"/vault/{vid}/share", status_code=303)


# ── items ────────────────────────────────────────────────────────────────────
def _fields_from_form(item_type, secret, notes):
    fields = {}
    key = "password" if item_type == "login" else "secret"
    if secret:
        fields[key] = secret
    if notes:
        fields["notes"] = notes
    return fields


@rt("/items/new")
def get(session, vault: int = 0, type: str = "login"):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    vaults = _vaults(identity)
    if not vaults:
        return RedirectResponse("/vaults/new", status_code=303)
    vault_id = vault or vaults[0]["id"]
    item_type = type if type in db.ITEM_TYPES else "login"
    return views.item_editor_page(identity, vaults, vault_id=vault_id, item_type=item_type,
                                  all_vaults=vaults)


@rt("/items")
def post(session, type: str = "login", vault_id: int = 0, title: str = "",
         username: str = "", url: str = "", secret: str = "", notes: str = "", version: int = 0):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    item_type = type if type in db.ITEM_TYPES else "login"
    fields = _fields_from_form(item_type, secret, notes)
    try:
        iid = db.create_item(identity, vault_id, type=item_type, title=title.strip() or "Untitled",
                             url=url.strip(), username=username.strip(), fields=fields)
    except crypto.RecoveryKeyMissing as exc:
        return views.item_editor_page(identity, _vaults(identity), vault_id=vault_id,
                                      item_type=item_type, all_vaults=_vaults(identity), msg=str(exc))
    if iid is None:
        return Response("Not permitted", status_code=403)
    return RedirectResponse(f"/items/{iid}", status_code=303)


@rt("/items/{iid:int}")
def get(session, iid: int):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    it = db.viewable_item(identity, iid)
    if not it:
        return Response("Item not found", status_code=404)
    v = db.vault(it["vault_id"])
    preview = {"has_notes": False, "custom": []}
    try:
        fields = db.peek(identity, iid) or {}
        preview = {"has_notes": bool(fields.get("notes")),
                   "custom": list((fields.get("custom") or {}).keys())}
    except crypto.RecoveryKeyMissing:
        pass
    return views.item_detail_page(identity, _vaults(identity), it, v,
                                  db.can_edit_vault(identity, it["vault_id"]), preview)


@rt("/items/{iid:int}/edit")
def get(session, iid: int):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    it = db.viewable_item(identity, iid)
    if not it or not db.can_edit_vault(identity, it["vault_id"]):
        return Response("Not found", status_code=404)
    fields = db.peek(identity, iid) or {}
    return views.item_editor_page(identity, _vaults(identity), item=it, vault_id=it["vault_id"],
                                  fields=fields, item_type=it["type"], all_vaults=_vaults(identity))


@rt("/items/{iid:int}")
def post(session, iid: int, type: str = "login", title: str = "", username: str = "",
         url: str = "", secret: str = "", notes: str = "", version: int = 0):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    it = db.viewable_item(identity, iid)
    if not it or not db.can_edit_vault(identity, it["vault_id"]):
        return Response("Not found", status_code=404)
    item_type = type if type in db.ITEM_TYPES else it["type"]
    fields = _fields_from_form(item_type, secret, notes)
    # keep any existing custom fields
    existing = db.peek(identity, iid) or {}
    if existing.get("custom"):
        fields["custom"] = existing["custom"]
    result = db.update_item(identity, iid, title=title.strip() or "Untitled", url=url.strip(),
                            username=username.strip(), fields=fields, version=version, type=item_type)
    if result and result.get("conflict"):
        return views.item_editor_page(identity, _vaults(identity), item=db.item(iid),
                                      vault_id=it["vault_id"], fields=fields, item_type=item_type,
                                      all_vaults=_vaults(identity),
                                      msg="This item changed elsewhere — reopen and try again.")
    return RedirectResponse(f"/items/{iid}", status_code=303)


@rt("/items/{iid:int}/reveal")
def post(session, iid: int):
    identity = who(session)
    if not identity:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    fields = db.reveal(identity, iid)
    if fields is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"fields": fields})


@rt("/items/{iid:int}/favorite")
def post(session, iid: int):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    db.toggle_favorite(identity, iid)
    return RedirectResponse(f"/items/{iid}", status_code=303)


@rt("/items/{iid:int}/trash")
def post(session, iid: int):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    it = db.item(iid)
    db.trash_item(identity, iid)
    return RedirectResponse(f"/vault/{it['vault_id']}" if it else "/app", status_code=303)


@rt("/items/{iid:int}/versions")
def get(session, iid: int):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    it = db.viewable_item(identity, iid)
    if not it:
        return Response("Item not found", status_code=404)
    return views.versions_page(identity, _vaults(identity), it, db.vault(it["vault_id"]),
                               db.item_versions(iid))


@rt("/items/{iid:int}/versions/{vrid:int}/restore")
def post(session, iid: int, vrid: int):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    db.restore_item_version(identity, iid, vrid)
    return RedirectResponse(f"/items/{iid}", status_code=303)


# ── health / activity ────────────────────────────────────────────────────────
@rt("/health")
def get():
    return JSONResponse({"status": "ok", "product": "FastPassword", "version": VERSION,
                         "release_date": RELEASE_DATE, "recovery_key": crypto.recovery_enabled()})


@rt("/password-health")
def get(session):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    report = db.health_report(identity)
    return views.health_page(identity, _vaults(identity), report)


@rt("/activity")
def get(session):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    return views.activity_page(identity, _vaults(identity), db.recent_activity(identity))


# ── import / export ──────────────────────────────────────────────────────────
@rt("/import")
def get(session):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    return views.import_page(identity, _vaults(identity))


@rt("/import")
async def post(request, session):
    identity = who(session)
    if not identity:
        return RedirectResponse("/", status_code=303)
    form = await request.form()
    vault_id = int(form.get("vault_id") or 0)
    upload = form.get("file")
    if not upload or not db.can_edit_vault(identity, vault_id):
        return views.import_page(identity, _vaults(identity), msg="Choose a vault and a CSV file.")
    text = (await upload.read()).decode("utf-8", "replace")
    try:
        rows = imports.parse_csv(text)
        n = imports.import_rows(identity, vault_id, rows)
    except crypto.RecoveryKeyMissing as exc:
        return views.import_page(identity, _vaults(identity), msg=str(exc))
    except Exception:
        return views.import_page(identity, _vaults(identity),
                                 msg="Could not parse that CSV. Check it has a header row.")
    return views.import_page(identity, _vaults(identity), result=n)


@rt("/export")
def get(session):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    return views.export_page(identity, _vaults(identity))


@rt("/export/encrypted")
def post(session, passphrase: str = ""):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    if len(passphrase) < 10:
        return views.export_page(identity, _vaults(identity),
                                 msg="Use a passphrase of at least 10 characters.")
    data = imports.export_encrypted(identity, passphrase)
    db.audit(identity, "export.encrypted")
    return Response(data, media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="fastpassword-backup.json"'})


@rt("/export/plaintext")
def post(session):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    csv_text = imports.export_plaintext_csv(identity)
    db.audit(identity, "export.plaintext")
    return Response(csv_text, media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="fastpassword-export.csv"'})


@rt("/settings/tokens")
def get(session):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    return views.tokens_page(identity, _vaults(identity), db.list_api_tokens(identity))


@rt("/settings/tokens")
def post(session, name: str = "", expires_days: str = "", scope_write: str = ""):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    scopes = "read,write" if scope_write else "read"
    days = int(expires_days) if expires_days.strip().isdigit() else None
    token, _ = db.create_api_token(identity, name, scopes, days)
    return views.tokens_page(identity, _vaults(identity), db.list_api_tokens(identity),
                             new_token=token, msg="Token created.")


@rt("/settings/tokens/revoke")
def post(session, token_id: int):
    identity = guard(session)
    if isinstance(identity, RedirectResponse):
        return identity
    db.revoke_api_token(identity, token_id)
    return RedirectResponse("/settings/tokens", status_code=303)


@rt("/developers")
def get():
    return RedirectResponse("/api/docs", status_code=307)


@rt("/docs")
def get(session):
    return views.docs_page(who(session))


# ── auth: Google SSO (primary) + local accounts (fallback) ───────────────────
def _on_local_login(session, account):
    establish_identity(session, account["email"], account.get("name") or "")


account_auth.register_fasthtml_routes(rt, app_name="FastPassword", success_path="/app",
                                      on_login=_on_local_login)

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_ALLOWED_DOMAINS = [d.strip().lower() for d in
                          os.environ.get("GOOGLE_ALLOWED_DOMAINS", "").split(",") if d.strip()]
OAUTH_ENABLED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)
_oauth = None
if OAUTH_ENABLED:
    from authlib.integrations.starlette_client import OAuth as _AuthlibOAuth
    _oauth = _AuthlibOAuth()
    _oauth.register(
        name="google", client_id=GOOGLE_CLIENT_ID, client_secret=GOOGLE_CLIENT_SECRET,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"})


if OAUTH_ENABLED:
    def _redirect_uri(request):
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("host", request.url.netloc)
        return f"{scheme}://{host}/auth/google/callback"

    @rt("/auth/google", methods=["GET"])
    async def google_login(request):
        return await _oauth.google.authorize_redirect(request, _redirect_uri(request))

    @rt("/auth/google/callback", methods=["GET"])
    async def google_callback(request, sess):
        try:
            token = await _oauth.google.authorize_access_token(request)
        except Exception:
            return RedirectResponse("/?auth=google-failed", status_code=303)
        info = token.get("userinfo") or {}
        email = (info.get("email") or "").strip().lower()
        if not email or not info.get("email_verified", True):
            return RedirectResponse("/?auth=unverified", status_code=303)
        if (GOOGLE_ALLOWED_DOMAINS and email.split("@")[-1] not in GOOGLE_ALLOWED_DOMAINS
                and not db.get_user(email)):
            return RedirectResponse("/?auth=not-permitted", status_code=303)
        account_auth.accounts.link_google(email, info.get("name") or email)
        establish_identity(sess, email, info.get("name") or "")
        return RedirectResponse("/app", status_code=303)
else:
    @rt("/auth/google", methods=["GET"])
    def google_disabled():
        return RedirectResponse("/?auth=google-disabled", status_code=303)


@rt("/auth/dev")
def get(session, email: str = "kaljuvee@gmail.com"):
    if os.getenv("FASTPASSWORD_ENV", "development") == "production":
        return RedirectResponse("/", status_code=303)
    establish_identity(session, email, "Julian Kaljuvee")
    return RedirectResponse("/app", status_code=303)


@rt("/logout")
def get(session):
    session.clear()
    return RedirectResponse("/", status_code=303)


@rt("/favicon.ico")
def get():
    return Response(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
        '<rect width="64" height="64" rx="16" fill="#2563eb"/>'
        '<path fill="white" d="M32 12a9 9 0 0 0-9 9v6h-3a3 3 0 0 0-3 3v16a3 3 0 0 0 3 3h24a3 3 0 0 0 '
        '3-3V30a3 3 0 0 0-3-3h-3v-6a9 9 0 0 0-9-9zm-5 15v-6a5 5 0 0 1 10 0v6H27z"/></svg>',
        media_type="image/svg+xml")


@rt("/openapi.json")
def get():
    return JSONResponse(api.openapi())


if __name__ == "__main__":
    serve(port=int(os.getenv("FASTPASSWORD_PORT", "5031")))
