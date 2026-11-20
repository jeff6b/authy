# auth.py — Discord OAuth + web sessions + server linking

import os
import secrets
import hashlib
from datetime import datetime, timedelta

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse
from sqlalchemy import Column, Integer, String, DateTime, BigInteger
from sqlalchemy.orm import Session as OrmSession

from main import Base, engine, SessionLocal, Server, sha256


# ==================== CONFIG ====================
DISCORD_CLIENT_ID     = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI  = os.getenv("DISCORD_REDIRECT_URI", "https://authy-o0pm.onrender.com/api/auth/discord/callback")

WEB_SESSION_TTL = 60 * 60 * 24 * 7
COOKIE_NAME     = "kf_session"
STATE_COOKIE    = "kf_oauth_state"

IS_PROD         = os.getenv("ENV", "prod").lower() != "dev"
COOKIE_SECURE   = IS_PROD
COOKIE_DOMAIN   = os.getenv("COOKIE_DOMAIN") or None


# ==================== MODELS ====================
class User(Base):
    __tablename__ = "users"
    id          = Column(Integer, primary_key=True)
    discord_id  = Column(BigInteger, unique=True, nullable=False)
    username    = Column(String(100), nullable=True)
    avatar      = Column(String(64), nullable=True)
    created_at  = Column(DateTime, default=datetime.utcnow)


class WebSession(Base):
    __tablename__ = "web_sessions"
    id          = Column(Integer, primary_key=True)
    user_id     = Column(Integer, nullable=False)
    token_hash  = Column(String(64), unique=True, nullable=False)
    expires_at  = Column(DateTime, nullable=False)
    created_at  = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


# ==================== MIGRATION (idempotent) ====================
def _migrate():
    from sqlalchemy import text
    stmts = [
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS user_id INTEGER",
    ]
    with engine.begin() as conn:
        for s in stmts:
            try:
                conn.execute(text(s))
            except Exception as e:
                print(f"[auth.migrate] skipped: {s} -> {e}")
    print("[auth.migrate] done")

_migrate()


# ==================== DB DEP ====================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ==================== COOKIE HELPERS ====================
def _set_cookie(resp, name: str, value: str, max_age: int):
    kwargs = dict(max_age=max_age, httponly=True, samesite="lax",
                  secure=COOKIE_SECURE, path="/")
    if COOKIE_DOMAIN:
        kwargs["domain"] = COOKIE_DOMAIN
    resp.set_cookie(name, value, **kwargs)


def _delete_cookie(resp, name: str):
    kwargs = dict(path="/")
    if COOKIE_DOMAIN:
        kwargs["domain"] = COOKIE_DOMAIN
    resp.delete_cookie(name, **kwargs)


# ==================== SESSION HELPERS ====================
def _new_session(db, user_id: int) -> str:
    raw = secrets.token_hex(32)
    db.add(WebSession(
        user_id=user_id,
        token_hash=sha256(raw),
        expires_at=datetime.utcnow() + timedelta(seconds=WEB_SESSION_TTL),
    ))
    db.commit()
    return raw


def get_current_user(request: Request, db: OrmSession = Depends(get_db)) -> User:
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        raise HTTPException(401, "Not logged in")
    ws = db.query(WebSession).filter(WebSession.token_hash == sha256(raw)).first()
    if not ws:
        raise HTTPException(401, "Unknown session")
    if ws.expires_at < datetime.utcnow():
        db.delete(ws); db.commit()
        raise HTTPException(401, "Session expired")
    user = db.query(User).filter(User.id == ws.user_id).first()
    if not user:
        raise HTTPException(401, "User missing")
    return user


# ==================== ROUTER ====================
router = APIRouter(prefix="/api")


# ==================== OAUTH ====================
@router.get("/auth/discord")
def auth_discord():
    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        raise HTTPException(500, "Discord OAuth not configured on server")
    state = secrets.token_urlsafe(24)
    url = (
        "https://discord.com/oauth2/authorize"
        f"?client_id={DISCORD_CLIENT_ID}"
        f"&redirect_uri={DISCORD_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=identify%20guilds"
        f"&state={state}"
    )
    resp = RedirectResponse(url, status_code=302)
    _set_cookie(resp, STATE_COOKIE, state, max_age=600)
    return resp


@router.get("/auth/discord/callback")
async def auth_discord_callback(
    request: Request,
    code: str = None,
    state: str = None,
    db: OrmSession = Depends(get_db),
):
    cookie_state = request.cookies.get(STATE_COOKIE)
    if not code:
        raise HTTPException(400, "Missing code")
    if not state:
        raise HTTPException(400, "Missing state")
    if not cookie_state:
        raise HTTPException(400, "Missing state cookie")
    if not secrets.compare_digest(cookie_state, state):
        raise HTTPException(400, "Invalid state")

    async with httpx.AsyncClient(timeout=15) as client:
        token_resp = await client.post(
            "https://discord.com/api/oauth2/token",
            data={
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": DISCORD_REDIRECT_URI,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if token_resp.status_code != 200:
            raise HTTPException(400, f"Token exchange failed: {token_resp.text[:200]}")
        tok = token_resp.json()

        me_resp = await client.get(
            "https://discord.com/api/users/@me",
            headers={"Authorization": f"Bearer {tok['access_token']}"},
        )
        if me_resp.status_code != 200:
            raise HTTPException(400, "Failed to fetch Discord user")
        me = me_resp.json()

    user = db.query(User).filter(User.discord_id == int(me["id"])).first()
    if not user:
        user = User(
            discord_id=int(me["id"]),
            username=me.get("username"),
            avatar=me.get("avatar"),
        )
        db.add(user); db.commit(); db.refresh(user)
    else:
        user.username = me.get("username")
        user.avatar   = me.get("avatar")
        db.commit()

    raw = _new_session(db, user.id)

    resp = RedirectResponse("/dashboard", status_code=302)
    _delete_cookie(resp, STATE_COOKIE)
    _set_cookie(resp, COOKIE_NAME, raw, max_age=WEB_SESSION_TTL)
    return resp


@router.post("/auth/logout")
def auth_logout(request: Request, db: OrmSession = Depends(get_db)):
    raw = request.cookies.get(COOKIE_NAME)
    if raw:
        ws = db.query(WebSession).filter(WebSession.token_hash == sha256(raw)).first()
        if ws:
            db.delete(ws); db.commit()
    resp = JSONResponse({"ok": True})
    _delete_cookie(resp, COOKIE_NAME)
    return resp


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {
        "id": user.id,
        "discord_id": str(user.discord_id),
        "username": user.username,
        "avatar": user.avatar,
    }


# ==================== SERVERS (linking) ====================
@router.get("/servers")
def list_servers(user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    rows = db.query(Server).filter(Server.user_id == user.id).all()
    return [
        {
            "id": s.id,
            "guild_id": str(s.guild_id) if s.guild_id else None,
            "guild_name": s.guild_name,
            "panel_name": s.panel_name,
            "linked": bool(s.guild_id),
        }
        for s in rows
    ]


@router.post("/servers/link")
def link_server(payload: dict, user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    api_key  = (payload.get("api_key") or "").strip()
    guild_id = (payload.get("guild_id") or "").strip()
    if not api_key:
        raise HTTPException(400, "Missing api_key")
    if not guild_id or not guild_id.isdigit():
        raise HTTPException(400, "guild_id must be a numeric Discord server ID")

    gid = int(guild_id)
    s = db.query(Server).filter(Server.api_key == api_key).with_for_update().first()
    if not s:
        raise HTTPException(404, "Invalid API key")
    if s.user_id is not None and s.user_id != user.id:
        raise HTTPException(403, "That server is already linked to another account")
    if s.guild_id is not None and int(s.guild_id) != gid:
        raise HTTPException(409, "That server is already linked to a different guild")

    existing = db.query(Server).filter(Server.guild_id == gid).first()
    if existing and existing.id != s.id:
        raise HTTPException(409, "That guild is already linked to another server")

    s.user_id  = user.id
    s.guild_id = gid
    s.guild_name = s.guild_name or f"Guild {gid}"
    s.linked_at = datetime.utcnow()
    db.commit()
    return {"ok": True, "id": s.id, "guild_id": str(s.guild_id)}


@router.delete("/servers/{server_id}")
def unlink_server(server_id: int, user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    s = db.query(Server).filter(Server.id == server_id).with_for_update().first()
    if not s:
        raise HTTPException(404, "Server not found")
    if s.user_id != user.id:
        raise HTTPException(403, "Not yours")
    s.guild_id = None
    s.guild_name = None
    s.admin_role = None
    s.linked_at = None
    s.panel_name = None
    s.panel_message_id = None
    s.panel_channel_id = None
    db.commit()
    return {"ok": True}
