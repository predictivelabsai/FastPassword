from __future__ import annotations

import html as _html
from datetime import datetime
from urllib.parse import quote

from fasthtml.common import *

from . import account_auth, crypto
from .db import ITEM_TYPES
from .version import RELEASE_DATE, VERSION

ACCENT = "#2563eb"
REPO_URL = "https://github.com/predictivelabsai/FastPassword"
LINKEDIN_URL = "https://www.linkedin.com/company/predictive-labs-ltd"
PREDICTIVELABS_URL = "https://predictivelabs.ai"

FAVICON = "data:image/svg+xml," + quote(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
    '<rect width="64" height="64" rx="16" fill="#2563eb"/>'
    '<path fill="white" d="M32 12a9 9 0 0 0-9 9v6h-3a3 3 0 0 0-3 3v16a3 3 0 0 0 3 3h24a3 3 0 0 0 '
    '3-3V30a3 3 0 0 0-3-3h-3v-6a9 9 0 0 0-9-9zm-5 15v-6a5 5 0 0 1 10 0v6H27zm5 8a3 3 0 0 1 1 5.83V44a1 '
    '1 0 0 1-2 0v-3.17A3 3 0 0 1 32 35z"/></svg>', safe="")

CAT_COLOR = {"login": "#2563eb", "credential": "#7c3aed"}
TYPE_LABEL = {"login": "Login", "credential": "API / Credential"}

BASE_CSS = r"""
:root{--accent:#2563eb;--tint:#eff4ff;--ink:#172033;--muted:#667085;--line:#e5e7eb;--panel:#f8fafc;--ok:#027a48;--warn:#b45309;--bad:#b42318}
*{box-sizing:border-box}body{margin:0;color:var(--ink);background:#fff;font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}a{color:inherit}
.nav{height:66px;display:flex;align-items:center;justify-content:space-between;max-width:1200px;margin:auto;padding:0 24px}.brand{display:flex;align-items:center;gap:10px;text-decoration:none;font-weight:800}.mark{width:34px;height:34px;background:var(--accent);color:#fff;border-radius:10px;display:grid;place-items:center;font-weight:800}.navlinks{display:flex;gap:18px;align-items:center}.navlinks a{text-decoration:none;font-weight:600;color:var(--ink)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;border:0;border-radius:10px;background:var(--accent);color:#fff;padding:11px 17px;font-weight:700;text-decoration:none;cursor:pointer;font-size:14px}.btn.ghost{background:#fff;color:var(--ink);border:1px solid var(--line)}.btn.sm{padding:8px 13px;font-size:13px}.btn.danger{background:#fff;color:var(--bad);border:1px solid #f4b4ae}
.avatar{width:26px;height:26px;border-radius:99px;background:var(--tint);color:var(--accent);display:grid;place-items:center;font-size:12px;font-weight:800}
/* landing */
.hero{max-width:960px;margin:auto;padding:72px 24px 20px;text-align:center}.eyebrow{color:var(--accent);font-weight:800;font-size:12px;letter-spacing:.17em;text-transform:uppercase}.hero h1{font-size:clamp(38px,5.4vw,60px);line-height:1.05;letter-spacing:-.04em;margin:16px 0}.hero p{font-size:19px;line-height:1.6;color:var(--muted);max-width:640px;margin:0 auto}.herocta{display:flex;gap:12px;justify-content:center;margin-top:28px;flex-wrap:wrap}
.features{background:var(--panel);padding:64px 24px;margin-top:44px}.featuregrid{max-width:1100px;margin:auto;display:grid;grid-template-columns:repeat(3,1fr);gap:18px}.feature{background:#fff;border:1px solid var(--line);border-radius:16px;padding:24px}.feature b{color:var(--accent)}.feature h3{font-size:18px;margin:10px 0 6px}.feature p{color:var(--muted);line-height:1.6;margin:0;font-size:14px}
.footer{max-width:1200px;margin:auto;padding:28px 24px;color:var(--muted);display:flex;align-items:center;justify-content:space-between;gap:14px 24px;flex-wrap:wrap;border-top:1px solid var(--line);font-size:14px}.footer a{text-decoration:none;color:var(--muted)}.footer a:hover{color:var(--accent)}.foot-right{display:flex;gap:20px;flex-wrap:wrap}.foot-right a{font-weight:600}
/* app shell */
.shell{display:grid;grid-template-columns:250px minmax(0,1fr);min-height:100vh}
.sidebar{background:#f8fafc;border-right:1px solid var(--line);padding:16px;overflow:auto}.sidehead{display:flex;align-items:center;gap:9px;margin-bottom:16px;text-decoration:none}.side-user{font-size:12px;color:var(--muted);padding:8px 6px;border-bottom:1px solid var(--line);margin-bottom:10px;display:flex;align-items:center;gap:8px}
.sideitem{display:flex;align-items:center;justify-content:space-between;gap:8px;text-decoration:none;padding:8px 10px;border-radius:8px;font-size:14px;color:var(--ink)}.sideitem:hover,.sideitem.active{background:var(--tint);color:var(--accent)}.side-count{background:#e2e8f0;color:#475569;border-radius:99px;padding:1px 8px;font-size:11px;font-weight:700}.sideitem.active .side-count{background:var(--accent);color:#fff}
.sidelabel{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:16px 0 4px;padding:0 10px;display:flex;justify-content:space-between;align-items:center}.sidelabel a{text-decoration:none;color:var(--accent);font-weight:700;font-size:15px}
.workspace{overflow:auto}.topbar{height:58px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px;padding:0 22px;position:sticky;top:0;background:#fffd;backdrop-filter:blur(10px);z-index:3}.topbar form{flex:1;max-width:480px;margin:0}.topbar input[type=search]{width:100%;border:1px solid var(--line);border-radius:10px;padding:9px 13px;font:inherit;font-size:14px}.pageactions{display:flex;gap:8px;align-items:center;margin-left:auto}
.content{max-width:1000px;margin:0 auto;padding:26px 24px 80px}
.pagehead{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:20px}.pagehead h1{font-size:26px;letter-spacing:-.02em;margin:0}.pagehead .sub{color:var(--muted);font-size:14px;margin-top:3px}
/* item list */
.itemlist{display:flex;flex-direction:column;border:1px solid var(--line);border-radius:14px;overflow:hidden}
.itemrow{display:flex;align-items:center;gap:13px;padding:13px 16px;text-decoration:none;color:inherit;border-bottom:1px solid var(--line);background:#fff}.itemrow:last-child{border-bottom:0}.itemrow:hover{background:var(--panel)}
.favi{width:34px;height:34px;border-radius:9px;background:var(--tint);color:var(--accent);display:grid;place-items:center;font-weight:800;font-size:13px;flex:none;overflow:hidden}.favi img{width:20px;height:20px}
.itemmain{min-width:0;flex:1}.itemmain .t{font-weight:650;font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.itemmain .s{color:var(--muted);font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.itemmeta{display:flex;align-items:center;gap:10px;flex:none}.star{font-size:16px;color:#d0d5dd}.star.on{color:#f59e0b}
.typepill{font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.05em;padding:3px 8px;border-radius:99px;color:#fff}
.empty{padding:66px 24px;text-align:center;color:var(--muted);border:1px dashed var(--line);border-radius:14px}
/* detail */
.card{border:1px solid var(--line);border-radius:14px;background:#fff;overflow:hidden}
.detailhead{display:flex;align-items:center;gap:14px;padding:22px}.detailhead .favi{width:46px;height:46px;font-size:17px}.detailhead h1{margin:0;font-size:22px}.detailhead .s{color:var(--muted);font-size:13px}
.field{display:flex;align-items:center;gap:10px;padding:14px 22px;border-top:1px solid var(--line)}.field .lab{width:120px;flex:none;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}.field .val{flex:1;min-width:0;font-size:15px;word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.field .val.mono-off{font-family:inherit}
.iconbtn{border:1px solid var(--line);background:#fff;border-radius:8px;padding:6px 10px;cursor:pointer;font-size:12px;font-weight:650;color:#475569}.iconbtn:hover{background:var(--tint);border-color:var(--accent);color:var(--accent)}
.detailactions{display:flex;gap:9px;padding:16px 22px;border-top:1px solid var(--line);flex-wrap:wrap}.inlineform{display:inline-flex;margin:0}
.strengthbar{height:7px;border-radius:99px;background:#e5e7eb;overflow:hidden;flex:1;max-width:180px}.strengthbar i{display:block;height:100%}
/* editor form */
.form{border:1px solid var(--line);border-radius:14px;background:#fff;padding:22px;display:flex;flex-direction:column;gap:16px}
.frow label{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:5px}
.frow input,.frow select,.frow textarea{width:100%;border:1px solid var(--line);border-radius:9px;padding:10px 12px;font:inherit;font-size:14px}.frow textarea{min-height:80px;resize:vertical}.frow input:focus,.frow textarea:focus,.frow select:focus{outline:2px solid color-mix(in srgb,var(--accent) 22%,white);border-color:var(--accent)}
.pwrow{display:flex;gap:8px}.pwrow input{flex:1;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.gen{border:1px solid var(--line);border-radius:12px;padding:14px;background:var(--panel);display:none}.gen.open{display:block}.gen .genctl{display:flex;align-items:center;gap:14px;flex-wrap:wrap;font-size:13px;color:var(--muted)}.gen label{display:inline-flex;align-items:center;gap:6px;text-transform:none;letter-spacing:0;color:var(--ink);margin:0}
.formactions{display:flex;gap:10px;align-items:center}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
/* health */
.scorewrap{display:flex;align-items:center;gap:20px;border:1px solid var(--line);border-radius:14px;padding:22px;margin-bottom:20px}
.scorering{width:96px;height:96px;border-radius:99px;display:grid;place-items:center;font-size:26px;font-weight:800;flex:none}
.healthgroup{margin-top:24px}.healthgroup h2{font-size:16px;margin:0 0 10px;display:flex;align-items:center;gap:8px}.badge{border-radius:99px;padding:2px 9px;font-size:12px;font-weight:800}
/* members */
.memrow{display:flex;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid var(--line)}.memrow:last-child{border:0}.memrow .who{flex:1;min-width:0}.memrow .who .e{color:var(--muted);font-size:13px}
.rolepill{font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.05em;color:var(--accent);background:var(--tint);border-radius:99px;padding:3px 9px}
.toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%) translateY(12px);background:var(--ink);color:#fff;padding:11px 16px;border-radius:10px;font-size:14px;box-shadow:0 12px 34px rgba(15,23,42,.28);opacity:0;pointer-events:none;transition:.2s;z-index:3000}.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.flash{border:1px solid var(--line);border-left:3px solid var(--accent);background:var(--tint);border-radius:10px;padding:11px 15px;margin-bottom:18px;font-size:14px}
.callout{border:1px solid #fde68a;background:#fffbeb;border-radius:10px;padding:11px 15px;font-size:13px;color:#92400e;margin-bottom:16px}
.breadcrumbs{display:flex;gap:7px;align-items:center;flex-wrap:wrap;color:var(--muted);font-size:13px;margin-bottom:14px}.breadcrumbs a{text-decoration:none}
table.tbl{width:100%;border-collapse:collapse}table.tbl th,table.tbl td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);font-size:14px}table.tbl th{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
@media(max-width:820px){.shell{grid-template-columns:1fr}.sidebar{display:none}.featuregrid{grid-template-columns:1fr}.grid2{grid-template-columns:1fr}}
"""


def head(title, description="A private password and credentials manager for your team."):
    return Head(
        Title(title), Meta(charset="utf-8"),
        Meta(name="viewport", content="width=device-width,initial-scale=1"),
        Meta(name="description", content=description),
        Meta(name="robots", content="noindex"),
        Link(rel="icon", type="image/svg+xml", href=FAVICON),
        Link(rel="preconnect", href="https://fonts.googleapis.com"),
        Link(rel="stylesheet", href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"),
        Style(BASE_CSS), Style(account_auth.AUTH_CSS))


def _initial(text):
    return (text or "?").strip()[:1].upper() or "?"


def _favi(item):
    dom = ""
    url = item.get("url") or ""
    if "://" in url:
        dom = url.split("://", 1)[1].split("/", 1)[0]
    if dom:
        return Span(Img(src=f"https://www.google.com/s2/favicons?domain={quote(dom)}&sz=64",
                        alt="", loading="lazy"), cls="favi")
    return Span(_initial(item["title"]), cls="favi")


def toast_js():
    return Script("function toast(m){let t=document.getElementById('toast');t.textContent=m;"
                  "t.classList.add('show');clearTimeout(window._tt);window._tt=setTimeout(()=>t.classList.remove('show'),1800)}"
                  "async function copyText(t){try{await navigator.clipboard.writeText(t);toast('Copied')}catch(e){toast('Copy failed')}}")


# ── landing ──────────────────────────────────────────────────────────────────
def _footer():
    return Footer(
        Div(f"FastPassword v{VERSION} · ", A("Predictive Labs", href=PREDICTIVELABS_URL)),
        Div(A("GitHub", href=REPO_URL), A("LinkedIn", href=LINKEDIN_URL), A("Docs", href="/docs"),
            cls="foot-right"),
        cls="footer")


def landing_page(who):
    if who:
        right = Div(A("Open vault", href="/app", cls="btn sm"),
                    A("Sign out", href="/logout"), cls="navlinks")
    else:
        right = Div(A("Docs", href="/docs"),
                    A("Sign in with Google", href="/auth/google", cls="btn sm"), cls="navlinks")
    nav = Nav(A(Span("🔒", cls="mark"), "FastPassword", href="/", cls="brand"), right, cls="nav")
    hero = Div(
        Div("FastSME suite", cls="eyebrow"),
        H1("Passwords and credentials, kept safe together."),
        P("A private vault for your logins and API keys — encrypted at rest, shared with your "
          "team by vault, unlocked with your Google account."),
        Div(A("Sign in with Google", href="/auth/google", cls="btn"),
            A("Read the docs", href="/docs", cls="btn ghost"), cls="herocta"),
        cls="hero")
    feats = Div(Div(
        Div(B("Encrypted at rest"), H3("Every secret sealed"),
            P("Logins and API keys are stored as AES-256-GCM ciphertext under per-vault keys. "
              "Only non-secret metadata stays searchable."), cls="feature"),
        Div(B("Shared vaults"), H3("Access by team"),
            P("Keep a private vault and share others with teammates by email. Roles control who "
              "can view, edit, or manage."), cls="feature"),
        Div(B("Password health"), H3("Find weak & reused"),
            P("A built-in audit flags weak, reused, and stale passwords — computed from fingerprints, "
              "never from stored plaintext."), cls="feature"),
        cls="featuregrid"), cls="features")
    return Html(head("FastPassword — team password & credentials manager"),
                Body(nav, hero, feats, _footer()))


# ── app shell ────────────────────────────────────────────────────────────────
def sidebar(who, vaults, active, health_score=None):
    def link(href, label, icon, key, count=None):
        cls = "sideitem active" if active == key else "sideitem"
        inner = [Span(f"{icon}  {label}")]
        if count is not None:
            inner.append(Span(str(count), cls="side-count"))
        return A(*inner, href=href, cls=cls)

    vault_links = [
        A(Span(f"{'🔒' if v['kind']=='personal' else '👥'}  {v['name']}"),
          Span(str(v["item_count"]), cls="side-count"),
          href=f"/vault/{v['id']}", cls="sideitem active" if active == f"vault-{v['id']}" else "sideitem")
        for v in vaults]
    return Div(
        A(Span("🔒", cls="mark"), Span("FastPassword", style="font-weight:800"),
          href="/app", cls="sidehead"),
        Div(Span(_initial(who.get("name") or who["email"]), cls="avatar"),
            Span(who.get("name") or who["email"]), cls="side-user"),
        link("/app", "All items", "🗂️", "all"),
        link("/favorites", "Favorites", "⭐", "favorites"),
        link("/password-health", "Password health", "🩺", "health",
             count=(f"{health_score}%" if health_score is not None else None)),
        Div(Span("Vaults"), A("+", href="/vaults/new", title="New vault"), cls="sidelabel"),
        *vault_links,
        Div(Span("Tools"), cls="sidelabel"),
        link("/import", "Import", "📥", "import"),
        link("/export", "Export", "📤", "export"),
        link("/activity", "Activity", "🕑", "activity"),
        link("/settings/tokens", "API tokens", "🔑", "tokens"),
        link("/docs", "Docs", "📖", "docs"),
        Div(A("Sign out", href="/logout", cls="sideitem"), style="margin-top:14px"),
        Div(f"v{VERSION} · {RELEASE_DATE}", style="color:var(--muted);font-size:10px;padding:12px 10px"),
        cls="sidebar")


def app_shell(who, vaults, active, *content, health_score=None, title="FastPassword", search=""):
    top = Div(
        Form(Input(type="search", name="q", placeholder="Search all items…", value=search),
             action="/search", method="get"),
        Div(A("＋ New item", href="/items/new", cls="btn sm"), cls="pageactions"),
        cls="topbar")
    return Html(head(title),
                Body(Div(sidebar(who, vaults, active, health_score),
                         Div(top, Div(*content, cls="content"), cls="workspace"),
                         cls="shell"),
                     Div(id="toast", cls="toast"), toast_js()))


def flash(msg):
    return Div(msg, cls="flash") if msg else None


# ── item list ────────────────────────────────────────────────────────────────
def _item_row(it, show_vault=False):
    sub = it.get("username") or it.get("url") or ""
    if show_vault and it.get("vault_name"):
        sub = f"{sub} · {it['vault_name']}" if sub else it["vault_name"]
    return A(_favi(it),
             Div(Div(it["title"], cls="t"), Div(sub, cls="s"), cls="itemmain"),
             Div(Span("★" if it["favorite"] else "", cls="star on" if it["favorite"] else "star"),
                 Span(TYPE_LABEL[it["type"]].split(" ")[0], cls="typepill",
                      style=f"background:{CAT_COLOR[it['type']]}"),
                 cls="itemmeta"),
             href=f"/items/{it['id']}", cls="itemrow")


def items_view(who, vaults, items, *, active="all", title="All items", subtitle="",
               vault=None, search="", health_score=None, msg=""):
    head_actions = []
    if vault:
        if vault.get("role") in ("owner", "admin"):
            head_actions.append(A("Share", href=f"/vault/{vault['id']}/share", cls="btn ghost sm"))
        head_actions.append(A("＋ New item", href=f"/items/new?vault={vault['id']}", cls="btn sm"))
    body = [
        flash(msg),
        Div(Div(H1(title), Div(subtitle, cls="sub") if subtitle else None),
            Div(*head_actions, cls="pageactions") if head_actions else None, cls="pagehead"),
    ]
    if items:
        body.append(Div(*[_item_row(i, show_vault=(active in ("all", "favorites", "search")))
                          for i in items], cls="itemlist"))
    else:
        body.append(Div(P("No items yet."),
                        A("Add your first item", href=f"/items/new{('?vault='+str(vault['id'])) if vault else ''}",
                          cls="btn sm"), cls="empty"))
    return app_shell(who, vaults, active, *body, health_score=health_score, title=title, search=search)


# ── item detail ──────────────────────────────────────────────────────────────
def _field_row(lab, value, *, secret=False, mono=True, item_id=None, field_key=None):
    if secret:
        val = Span("•" * 12, cls="val", id=f"secret-{field_key}", data_loaded="0")
        btns = Div(
            Button("Reveal", type="button", cls="iconbtn",
                   onclick=f"revealField({item_id},'{field_key}','secret-{field_key}',this)"),
            Button("Copy", type="button", cls="iconbtn",
                   onclick=f"copyField({item_id},'{field_key}')"),
            style="display:flex;gap:6px")
        return Div(Span(lab, cls="lab"), val, btns, cls="field")
    valcls = "val" if mono else "val mono-off"
    return Div(Span(lab, cls="lab"), Span(value, cls=valcls),
               Button("Copy", type="button", cls="iconbtn",
                      onclick=f"copyText({_js(value)})") if value else None, cls="field")


def _js(s):
    import json
    return json.dumps(s or "")


def item_detail_page(who, vaults, it, vault, can_edit, fields_preview):
    strength = it["pw_strength"]
    color = "#12b76a" if strength >= 60 else ("#f79009" if strength >= 40 else "#f04438")
    rows = []
    if it["username"]:
        rows.append(_field_row("Username", it["username"], mono=False))
    if it["url"]:
        rows.append(Div(Span("Website", cls="lab"),
                        A(it["url"], href=it["url"], target="_blank", rel="noopener",
                          cls="val mono-off", style="color:var(--accent)"),
                        Button("Copy", type="button", cls="iconbtn", onclick=f"copyText({_js(it['url'])})"),
                        cls="field"))
    # secret fields (password/secret + notes) revealed on demand
    if it["has_password"]:
        key = "password" if it["type"] == "login" else "secret"
        rows.append(_field_row("Password" if it["type"] == "login" else "Secret", None,
                               secret=True, item_id=it["id"], field_key=key))
        rows.append(Div(Span("Strength", cls="lab"),
                        Div(Span(cls="", style=f"display:block;height:100%;width:{strength}%;background:{color}"),
                            cls="strengthbar"),
                        Span(f"{crypto.strength_label(strength)}", style="font-size:13px;color:var(--muted)"),
                        cls="field"))
    if fields_preview.get("has_notes"):
        rows.append(_field_row("Notes", None, secret=True, item_id=it["id"], field_key="notes"))
    for f in fields_preview.get("custom", []):
        rows.append(_field_row(f, None, secret=True, item_id=it["id"], field_key=f"custom:{f}"))

    actions = []
    if can_edit:
        actions.append(A("Edit", href=f"/items/{it['id']}/edit", cls="btn sm"))
    actions.append(Form(Button("★ Favorite" if not it["favorite"] else "★ Unfavorite",
                               type="submit", cls="btn ghost sm"),
                        action=f"/items/{it['id']}/favorite", method="post", cls="inlineform"))
    actions.append(A("History", href=f"/items/{it['id']}/versions", cls="btn ghost sm"))
    if can_edit:
        actions.append(Form(Button("Delete", type="submit", cls="btn danger sm",
                                   onclick="return confirm('Move this item to trash?')"),
                            action=f"/items/{it['id']}/trash", method="post", cls="inlineform"))

    card = Div(
        Div(_favi(it), Div(H1(it["title"]),
                           Div(f"{TYPE_LABEL[it['type']]} · {vault['name']}", cls="s")),
            cls="detailhead"),
        *rows,
        Div(*actions, cls="detailactions"),
        cls="card")
    reveal_js = Script(
        "async function _fetchSecret(id){const r=await fetch('/items/'+id+'/reveal',{method:'POST',"
        "headers:{'Accept':'application/json'}});if(!r.ok){toast('Could not reveal');return null}"
        "return (await r.json()).fields||{}}"
        "function _fieldVal(f,key){if(key.startsWith('custom:')){return (f.custom||{})[key.slice(7)]||''}"
        "return f[key]||''}"
        "async function revealField(id,key,elId,btn){const el=document.getElementById(elId);"
        "if(el.dataset.loaded==='1'){el.textContent='••••••••••••';el.dataset.loaded='0';btn.textContent='Reveal';return}"
        "const f=await _fetchSecret(id);if(!f)return;el.textContent=_fieldVal(f,key)||'(empty)';"
        "el.dataset.loaded='1';btn.textContent='Hide'}"
        "async function copyField(id,key){const f=await _fetchSecret(id);if(!f)return;"
        "copyText(_fieldVal(f,key))}")
    return app_shell(who, vaults, f"vault-{vault['id']}",
                     Div(A("← ", href=f"/vault/{vault['id']}"), A(vault["name"], href=f"/vault/{vault['id']}"),
                         Span(" / "), Span(it["title"]), cls="breadcrumbs"),
                     card, reveal_js, title=it["title"])


# ── item editor ──────────────────────────────────────────────────────────────
def item_editor_page(who, vaults, *, item=None, vault_id=None, fields=None, item_type="login",
                     all_vaults=None, msg=""):
    fields = fields or {}
    is_new = item is None
    action = "/items" if is_new else f"/items/{item['id']}"
    secret_key = "password" if item_type == "login" else "secret"
    secret_label = "Password" if item_type == "login" else "Secret / API key"
    vault_options = [Option(f"{'🔒 ' if v['kind']=='personal' else '👥 '}{v['name']}", value=str(v["id"]),
                            selected=(str(v["id"]) == str(vault_id)))
                     for v in (all_vaults or vaults) if v["role"] in ("owner", "admin", "member")]
    type_options = [Option(TYPE_LABEL[t], value=t, selected=(t == item_type)) for t in ITEM_TYPES]
    gen = Div(
        Div(Label(Input(type="checkbox", id="g-upper", checked=True), "A-Z"),
            Label(Input(type="checkbox", id="g-lower", checked=True), "a-z"),
            Label(Input(type="checkbox", id="g-num", checked=True), "0-9"),
            Label(Input(type="checkbox", id="g-sym", checked=True), "!@#"),
            Label("Length ", Input(type="range", id="g-len", min="8", max="48", value="20",
                                   oninput="document.getElementById('g-lenv').textContent=this.value"),
                  Span("20", id="g-lenv")),
            Button("Generate", type="button", cls="iconbtn", onclick="doGenerate()"),
            cls="genctl"),
        id="gen", cls="gen")
    form = Form(
        flash(msg),
        Div(Div(Label("Type"), Select(*type_options, name="type", id="f-type",
                                      onchange="onTypeChange()")),
            Div(Label("Vault"), Select(*vault_options, name="vault_id")), cls="grid2"),
        Div(Label("Title"), Input(name="title", value=(item["title"] if item else ""),
                                  placeholder="e.g. GitHub", required=True), cls="frow"),
        Div(Label("Username / account", id="lab-user"),
            Input(name="username", value=(item["username"] if item else ""),
                  placeholder="you@example.com"), cls="frow"),
        Div(Label("Website URL"), Input(name="url", value=(item["url"] if item else ""),
                                        placeholder="https://…"), cls="frow"),
        Div(Label(secret_label, id="lab-secret"),
            Div(Input(name="secret", id="f-secret", type="text", autocomplete="off",
                      value=fields.get(secret_key, "")),
                Button("🎲", type="button", cls="iconbtn", title="Password generator",
                       onclick="document.getElementById('gen').classList.toggle('open')"),
                cls="pwrow"),
            gen, cls="frow"),
        Div(Label("Notes"), Textarea(fields.get("notes", ""), name="notes",
                                     placeholder="Recovery codes, hints, context…"), cls="frow"),
        Input(type="hidden", name="version", value=str(item["version"] if item else 0)),
        Div(Button("Save item", type="submit", cls="btn"),
            A("Cancel", href=(f"/items/{item['id']}" if item else "/app"), cls="btn ghost"),
            cls="formactions"),
        cls="form", action=action, method="post")
    gen_js = Script(
        "function onTypeChange(){const t=document.getElementById('f-type').value;"
        "document.getElementById('lab-secret').textContent=t==='login'?'Password':'Secret / API key';"
        "document.getElementById('lab-user').textContent=t==='login'?'Username':'Account / key name'}"
        "function doGenerate(){let sets='';if(document.getElementById('g-upper').checked)sets+='ABCDEFGHJKLMNPQRSTUVWXYZ';"
        "if(document.getElementById('g-lower').checked)sets+='abcdefghijkmnpqrstuvwxyz';"
        "if(document.getElementById('g-num').checked)sets+='23456789';"
        "if(document.getElementById('g-sym').checked)sets+='!@#$%^&*()-_=+[]{}';"
        "if(!sets)return;const n=+document.getElementById('g-len').value;const a=new Uint32Array(n);"
        "crypto.getRandomValues(a);let out='';for(let i=0;i<n;i++)out+=sets[a[i]%sets.length];"
        "document.getElementById('f-secret').value=out;document.getElementById('f-secret').type='text';toast('Generated')}")
    title = "New item" if is_new else f"Edit {item['title']}"
    return app_shell(who, vaults, "all", H1(title), form, gen_js, title=title)


# ── share page ───────────────────────────────────────────────────────────────
def share_page(who, vaults, vault, members, invites, msg=""):
    def member_row(m):
        is_owner = m["role"] == "owner"
        controls = Span(m["role"].title(), cls="rolepill") if is_owner else Div(
            Form(Select(*[Option(r.title(), value=r, selected=(r == m["role"]))
                          for r in ("admin", "member", "viewer")], name="role",
                        onchange="this.form.submit()"),
                 Input(type="hidden", name="user_id", value=m["user_id"]),
                 action=f"/vault/{vault['id']}/role", method="post", cls="inlineform"),
            Form(Button("Remove", type="submit", cls="iconbtn"),
                 Input(type="hidden", name="user_id", value=m["user_id"]),
                 action=f"/vault/{vault['id']}/revoke", method="post", cls="inlineform"),
            style="display:flex;gap:8px;align-items:center")
        return Div(Span(_initial(m.get("name") or m["user_id"]), cls="avatar"),
                   Div(Div(m.get("name") or m["user_id"]), Div(m["user_id"], cls="e"), cls="who"),
                   controls, cls="memrow")

    def invite_row(inv):
        return Div(Span("✉", cls="avatar"),
                   Div(Div(inv["email"]), Div("Pending — access on first sign-in", cls="e"), cls="who"),
                   Div(Span(inv["role"].title(), cls="rolepill"),
                       Form(Button("Cancel", type="submit", cls="iconbtn"),
                            Input(type="hidden", name="invite_id", value=str(inv["id"])),
                            action=f"/vault/{vault['id']}/revoke-invite", method="post", cls="inlineform"),
                       style="display:flex;gap:8px;align-items:center"), cls="memrow")

    invite_form = Form(
        Div(Input(name="email", type="email", placeholder="teammate@example.com", required=True,
                  style="flex:1"),
            Select(*[Option(r.title(), value=r) for r in ("member", "admin", "viewer")], name="role"),
            Button("Invite", type="submit", cls="btn sm"),
            style="display:flex;gap:8px"),
        action=f"/vault/{vault['id']}/share", method="post")
    body = [
        Div(A(vault["name"], href=f"/vault/{vault['id']}"), Span(" / "), Span("Share"), cls="breadcrumbs"),
        Div(Div(H1(f"Share “{vault['name']}”"),
                Div("Invite teammates by email and set what they can do.", cls="sub")), cls="pagehead"),
        flash(msg),
        Div(invite_form, style="margin-bottom:20px"),
        Div(*[member_row(m) for m in members],
            *[invite_row(i) for i in invites], cls="card", style="padding:6px 18px"),
        Div(P("Roles: Owner and Admins manage sharing; Members can add and edit items; "
              "Viewers can only read and copy.", style="color:var(--muted);font-size:13px;margin-top:16px")),
    ]
    return app_shell(who, vaults, f"vault-{vault['id']}", *body, title=f"Share {vault['name']}")


# ── password health ──────────────────────────────────────────────────────────
def health_page(who, vaults, report):
    score = report["score"]
    color = "#12b76a" if score >= 80 else ("#f79009" if score >= 50 else "#f04438")
    ring = Div(f"{score}%", cls="scorering",
               style=f"background:conic-gradient({color} {score*3.6}deg,#e5e7eb 0);color:#fff;"
                     f"box-shadow:inset 0 0 0 10px #fff")
    ring = Div(Div(f"{score}", style=f"color:{color}"), cls="scorering",
               style=f"border:8px solid {color};color:{color}")

    def group(title, items, color_hex, note):
        if not items:
            return Div(H2(f"✓ {title}", style="color:var(--ok)"),
                      P("Nothing flagged.", style="color:var(--muted);font-size:14px"),
                      cls="healthgroup")
        rows = [Tr(Td(A(i["title"], href=f"/items/{i['id']}", style="color:var(--accent)")),
                   Td(i.get("username") or "", style="color:var(--muted)"),
                   Td(i["vault_name"]),
                   Td(f"{i['pw_strength']}%")) for i in items]
        return Div(
            H2(title, Span(str(len(items)), cls="badge",
                           style=f"background:{color_hex}22;color:{color_hex}")),
            P(note, style="color:var(--muted);font-size:13px;margin:0 0 8px"),
            Table(Thead(Tr(Th("Item"), Th("Username"), Th("Vault"), Th("Strength"))),
                  Tbody(*rows), cls="tbl"),
            cls="healthgroup")

    body = [
        Div(Div(H1("Password health"),
                Div(f"{report['total']} password(s) checked across your vaults.", cls="sub")), cls="pagehead"),
        Div(ring, Div(H2("Overall score", style="margin:0 0 4px"),
                      P("Share of your passwords with no weak, reused, or stale flags.",
                        style="color:var(--muted);font-size:14px;margin:0")),
            cls="scorewrap"),
        group("Weak passwords", report["weak"], "#f04438",
              "Below our strength threshold — regenerate these with a longer, more varied password."),
        group("Reused passwords", report["reused"], "#f79009",
              "The same password is used on more than one item. Give each its own."),
        group(f"Old passwords (>{report['old_days']} days)", report["old"], "#6b7280",
              "Not rotated in a while — consider updating."),
    ]
    return app_shell(who, vaults, "health", *body,
                     health_score=score, title="Password health")


# ── import / export ──────────────────────────────────────────────────────────
def import_page(who, vaults, msg="", result=None):
    vault_options = [Option(f"{'🔒 ' if v['kind']=='personal' else '👥 '}{v['name']}", value=str(v["id"]))
                     for v in vaults if v["role"] in ("owner", "admin", "member")]
    form = Form(
        Div(Label("Import into vault"), Select(*vault_options, name="vault_id"), cls="frow"),
        Div(Label("CSV file"), Input(type="file", name="file", accept=".csv", required=True), cls="frow"),
        Button("Import", type="submit", cls="btn"),
        cls="form", action="/import", method="post", enctype="multipart/form-data")
    body = [H1("Import"),
            Div("Upload a CSV exported from 1Password, Bitwarden, Chrome/Edge, or LastPass. "
                "We match columns by name (title, url, username, password, notes).", cls="callout"),
            flash(msg)]
    if result is not None:
        body.append(Div(f"Imported {result} item(s).", cls="flash"))
    body.append(form)
    return app_shell(who, vaults, "import", *body, title="Import")


def export_page(who, vaults, msg=""):
    enc_form = Form(
        Div(Label("Backup passphrase"),
            Input(name="passphrase", type="password", minlength="10", required=True,
                  placeholder="At least 10 characters"), cls="frow"),
        P("The backup is encrypted with this passphrase (scrypt + AES-256-GCM). Keep it safe — "
          "there is no way to recover the file without it.", style="color:var(--muted);font-size:13px"),
        Button("Download encrypted backup", type="submit", cls="btn"),
        cls="form", action="/export/encrypted", method="post")
    plain_form = Form(
        P("Exports every secret in plaintext CSV. Only use this to migrate to another manager, "
          "then delete the file.", style="color:#92400e;font-size:13px;margin:0 0 10px"),
        Button("Export plaintext CSV", type="submit", cls="btn danger",
               onclick="return confirm('This downloads all your passwords in plaintext. Continue?')"),
        cls="form", action="/export/plaintext", method="post",
        style="border-color:#fde68a;background:#fffbeb")
    return app_shell(who, vaults, "export",
                     H1("Export"), flash(msg),
                     H2("Encrypted backup", style="font-size:16px;margin:18px 0 10px"), enc_form,
                     H2("Plaintext CSV", style="font-size:16px;margin:26px 0 10px"), plain_form,
                     title="Export")


# ── activity ─────────────────────────────────────────────────────────────────
_ACTION_LABEL = {"item.create": "created", "item.update": "updated", "item.reveal": "revealed",
                 "item.trash": "deleted", "item.move": "moved", "vault.create": "created vault",
                 "vault.share": "shared vault", "vault.invite": "invited to vault",
                 "vault.role": "changed role", "vault.revoke": "revoked access",
                 "vault.rename": "renamed vault", "vault.delete": "deleted vault", "import": "imported"}


def activity_page(who, vaults, events):
    rows = [Tr(Td(_fmt(e["created_at"]), style="color:var(--muted);white-space:nowrap"),
               Td(e.get("user_name") or e.get("user_id") or "—"),
               Td(_ACTION_LABEL.get(e["action"], e["action"])),
               Td(e.get("detail") or "", style="color:var(--muted)")) for e in events]
    body = [H1("Activity"),
            Table(Thead(Tr(Th("When"), Th("Who"), Th("Action"), Th("Detail"))),
                  Tbody(*rows), cls="tbl") if rows else Div(P("No activity yet."), cls="empty")]
    return app_shell(who, vaults, "activity", *body, title="Activity")


def versions_page(who, vaults, it, vault, versions):
    rows = [Tr(Td(f"v{v['version']}"), Td(v["title"]),
               Td(_fmt(v["created_at"]), style="color:var(--muted)"),
               Td(Form(Button("Restore", type="submit", cls="iconbtn"),
                       action=f"/items/{it['id']}/versions/{v['id']}/restore", method="post",
                       cls="inlineform"))) for v in versions]
    body = [Div(A(it["title"], href=f"/items/{it['id']}"), Span(" / "), Span("History"), cls="breadcrumbs"),
            H1(f"History — {it['title']}"),
            Table(Thead(Tr(Th("Version"), Th("Title"), Th("Saved"), Th(""))), Tbody(*rows), cls="tbl")
            if rows else Div(P("No earlier versions."), cls="empty")]
    return app_shell(who, vaults, f"vault-{vault['id']}", *body, title="History")


def tokens_page(who, vaults, tokens, new_token=None, msg=""):
    def token_row(t):
        scopes = t["scopes"].replace(",", ", ")
        used = _fmt(t["last_used_at"]) if t["last_used_at"] else "never used"
        exp = f" · expires {_fmt(t['expires_at'])}" if t["expires_at"] else ""
        return Div(
            Div(Div(t["name"] or "API token", style="font-weight:650"),
                Div(f"{t['prefix']}…  ·  {scopes}  ·  {used}{exp}", cls="e"), cls="who"),
            Form(Button("Revoke", type="submit", cls="iconbtn",
                        onclick="return confirm('Revoke this token? Any client using it stops working.')"),
                 Input(type="hidden", name="token_id", value=str(t["id"])),
                 action="/settings/tokens/revoke", method="post", cls="inlineform"),
            cls="memrow")

    created = None
    if new_token:
        created = Div(
            P("Copy this token now — it is shown only once.", style="font-weight:650;margin:0 0 8px"),
            Div(Span(new_token, cls="val", id="new-token", style="word-break:break-all"),
                Button("Copy", type="button", cls="iconbtn",
                       onclick=f"copyText({_js(new_token)})"),
                cls="field", style="border:0;padding:0;gap:10px"),
            cls="flash", style="border-left-color:#12b76a;background:#f0fdf4")

    create_form = Form(
        Div(Div(Label("Name"), Input(name="name", placeholder="e.g. CI pipeline"), cls="frow"),
            Div(Label("Expires (days, blank = never)"),
                Input(name="expires_days", type="number", min="1", placeholder="never"), cls="frow"),
            cls="grid2"),
        Div(Label("Scopes"),
            Div(Label(Input(type="checkbox", name="scope_read", checked=True, disabled=True),
                      " read — list & read items (returns secret values)"),
                Label(Input(type="checkbox", name="scope_write"),
                      " write — create & delete items"),
                style="display:flex;flex-direction:column;gap:6px;color:var(--ink)"), cls="frow"),
        Button("Create token", type="submit", cls="btn"),
        cls="form", action="/settings/tokens", method="post")

    body = [
        Div(Div(H1("API tokens"),
                Div("Bearer tokens for the REST API. ",
                    A("Open API docs →", href="/api/docs", style="color:var(--accent)"), cls="sub")),
            cls="pagehead"),
        Div("A ", B("read"), " token can retrieve secret values for any vault you belong to. "
            "Treat tokens like passwords; revoke any you no longer use.", cls="callout"),
        flash(msg), created, create_form,
        (Div(*[token_row(t) for t in tokens], cls="card", style="padding:6px 18px;margin-top:20px")
         if tokens else Div(P("No active tokens."), cls="empty", style="margin-top:20px")),
        Div(H2("Using the API", style="font-size:16px;margin:26px 0 10px"),
            Pre(Code("curl -H \"Authorization: Bearer fpw_…\" \\\n"
                     "  https://password.fastsme.com/api/v1/vaults\n\n"
                     "# read an item (returns its secret fields)\n"
                     "curl -H \"Authorization: Bearer fpw_…\" \\\n"
                     "  https://password.fastsme.com/api/v1/vaults/1/items/2"),
                style="background:var(--panel);border:1px solid var(--line);border-radius:10px;"
                      "padding:14px;overflow:auto;font-size:13px"),
            P(A("Swagger UI", href="/api/docs"), " · ", A("ReDoc", href="/api/redoc"),
              " · ", A("OpenAPI JSON", href="/api/openapi.json"),
              style="font-size:13px;margin-top:10px")),
    ]
    return app_shell(who, vaults, "tokens", *body, title="API tokens")


def new_vault_page(who, vaults, msg=""):
    form = Form(
        Div(Label("Vault name"), Input(name="name", placeholder="e.g. Engineering", required=True), cls="frow"),
        Div(Label("Description"), Input(name="description", placeholder="Optional"), cls="frow"),
        Button("Create vault", type="submit", cls="btn"),
        cls="form", action="/vaults/new", method="post")
    return app_shell(who, vaults, "all", H1("New vault"),
                     Div("Shared vaults let you invite teammates. Your Personal vault stays private.",
                         cls="callout"),
                     flash(msg), form, title="New vault")


def docs_page(who):
    from .db import OLD_PASSWORD_DAYS
    sections = [
        ("What it is", "FastPassword is a server-rendered password and credentials manager for the "
         "FastSME suite. It stores logins and API keys as encrypted items grouped into vaults you "
         "can keep private or share with teammates."),
        ("Signing in", "Sign in with your Google account. There is no separate master password — after "
         "you authenticate, the vaults you belong to unlock automatically."),
        ("Vaults & sharing", "Everyone gets a private Personal vault. Create shared vaults and invite "
         "teammates by email; roles are Owner, Admin (manage sharing), Member (add/edit items) and "
         "Viewer (read only)."),
        ("Encryption", "Each vault has a random key; item secrets are AES-256-GCM ciphertext under that "
         "key. Only non-secret metadata (title, URL, username) is stored in the clear so search and "
         "health checks work without decrypting everything."),
        ("Password health", f"The health page flags weak passwords, ones reused across items, and any "
         f"not changed in over {OLD_PASSWORD_DAYS} days — all from stored fingerprints, never plaintext."),
        ("Import & export", "Import a CSV from 1Password, Bitwarden, Chrome or LastPass. Export a "
         "passphrase-encrypted backup, or a plaintext CSV for migration."),
    ]
    cards = [Div(H3(t), P(b), cls="feature") for t, b in sections]
    nav_right = (Div(A("Open vault", href="/app", cls="btn sm"), cls="navlinks") if who
                 else Div(A("Sign in with Google", href="/auth/google", cls="btn sm"), cls="navlinks"))
    return Html(head("FastPassword — docs"),
                Body(Nav(A(Span("🔒", cls="mark"), "FastPassword", href="/", cls="brand"),
                         nav_right, cls="nav"),
                     Div(Div("Documentation", cls="eyebrow"), H1("How FastPassword works"),
                         cls="hero", style="padding-bottom:8px"),
                     Div(Div(*cards, cls="featuregrid"), cls="features", style="margin-top:20px"),
                     _footer()))


def _fmt(iso):
    try:
        return datetime.fromisoformat(iso).strftime("%b %d, %H:%M")
    except (ValueError, TypeError):
        return iso or ""
