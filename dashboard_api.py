# dashboard_api.py — Real backend for the dashboard.
# Owns: /api/overview, /api/services, /api/keys, /api/blocklists.
# Uses the same tables the Discord bot writes to. No mock data.
# Key creation is Discord-only (/generatekey, /whitelist). Dashboard is read + manage.
#
# Required env on the web service:
#   DISCORD_BOT_TOKEN  — optional; enables real Discord avatar lookup for keys.

import os
import time
import secrets
import httpx
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session as OrmSession

from main import (
    SessionLocal,
    Server,
    License,
    Device,
    Session,
    AuthLog,
    Blocklist,
)
from auth import get_current_user, User


router = APIRouter(prefix="/api")

BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")

# discord_id -> (fetched_at, username, avatar_url)
_AV_CACHE: dict[int, tuple[float, str | None, str | None]] = {}
_AV_TTL_OK = 600
_AV_TTL_MISS = 60


# ==================== DB DEP ====================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ==================== HELPERS ====================
def _user_server_ids(db, user_id):
    return [r[0] for r in db.query(Server.id).filter(Server.user_id == user_id).all()]


def _cdn_avatar(discord_id, avatar_hash):
    if not discord_id or not avatar_hash:
        return None
    ext = "gif" if avatar_hash.startswith("a_") else "png"
    return f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar_hash}.{ext}?size=128"


async def _fetch_discord_user(discord_id):
    """Best-effort pfp lookup via bot token, memoised. Returns (username, avatar_url)."""
    if not BOT_TOKEN or not discord_id:
        return (None, None)

    try:
        did = int(discord_id)
    except (TypeError, ValueError):
        return (None, None)

    hit = _AV_CACHE.get(did)
    if hit:
        age = time.time() - hit[0]
        if (hit[1] or hit[2]) and age < _AV_TTL_OK:
            return (hit[1], hit[2])
        if not (hit[1] or hit[2]) and age < _AV_TTL_MISS:
            return (None, None)

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"https://discord.com/api/v10/users/{did}",
                headers={"Authorization": f"Bot {BOT_TOKEN}"},
            )
            if r.status_code != 200:
                _AV_CACHE[did] = (time.time(), None, None)
                return (None, None)
            u = r.json()
            name = u.get("username")
            av = _cdn_avatar(u.get("id"), u.get("avatar"))
            _AV_CACHE[did] = (time.time(), name, av)
            return (name, av)
    except Exception:
        _AV_CACHE[did] = (time.time(), None, None)
        return (None, None)


# ==================== OVERVIEW ====================
@router.get("/overview")
def overview(range_days: int = 7, user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    try:
        range_days = int(range_days)
    except (TypeError, ValueError):
        range_days = 7
    range_days = max(1, min(90, range_days))

    empty = {"users": 0, "active_keys": 0, "auth_requests": 0,
             "success_rate": 0.0, "series": [], "activity": []}

    server_ids = _user_server_ids(db, user.id)
    if not server_ids:
        return empty

    lic_ids = [r[0] for r in db.query(License.id).filter(License.server_id.in_(server_ids)).all()]
    if not lic_ids:
        return empty

    base = db.query(License).filter(License.server_id.in_(server_ids))
    users = base.with_entities(func.count(func.distinct(License.redeemed_by))).scalar() or 0
    active_keys = base.filter(License.status == "active").count()

    since = (datetime.utcnow() - timedelta(days=range_days - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0)

    logs = db.query(AuthLog).filter(AuthLog.license_id.in_(lic_ids), AuthLog.created_at >= since)
    total = logs.count()
    ok = logs.filter(AuthLog.success == True).count()

    buckets = {
        r[0]: r[1] for r in db.query(func.date(AuthLog.created_at), func.count())
        .filter(AuthLog.license_id.in_(lic_ids), AuthLog.created_at >= since)
        .group_by(func.date(AuthLog.created_at)).all()
    }
    series = []
    for i in range(range_days):
        d = (since + timedelta(days=i)).date()
        series.append({"date": d.isoformat(), "count": int(buckets.get(d, 0))})

    recent = (db.query(AuthLog).filter(AuthLog.license_id.in_(lic_ids))
              .order_by(AuthLog.created_at.desc()).limit(8).all())
    names = {}
    ids = [a.license_id for a in recent if a.license_id]
    if ids:
        names = {r[0]: r[1] for r in db.query(License.id, License.redeemed_name)
                 .filter(License.id.in_(ids)).all()}

    return {
        "users": users,
        "active_keys": active_keys,
        "auth_requests": total,
        "success_rate": round(ok / total * 100, 1) if total else 0.0,
        "series": series,
        "activity": [{
            "event": a.event_type or "unknown",
            "success": bool(a.success),
            "name": names.get(a.license_id) or "Unknown user",
            "reason": a.failure_reason,
            "at": a.created_at.isoformat() if a.created_at else None,
        } for a in recent],
    }


# ==================== SERVICES ====================
# Dashboard creates Server rows with a fresh api_key (mirrors /create in the bot).
# Guild binding still happens via /api/servers/link or /link in Discord.

@router.get("/services")
def list_services(user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    rows = db.query(Server).filter(Server.user_id == user.id).order_by(Server.id.desc()).all()
    out = []
    for s in rows:
        key_count = db.query(License).filter(License.server_id == s.id).count()
        out.append({
            "id": s.id,
            "sid": str(s.id),
            "api_key": s.api_key,
            "name": s.panel_name or s.guild_name or f"Server {s.id}",
            "desc": s.description or "",
            "guild_id": str(s.guild_id) if s.guild_id else None,
            "guild_name": s.guild_name,
            "linked": bool(s.guild_id),
            "freemium": bool(s.freemium),
            "freemium_days": (s.freemium_days or "").split(",") if s.freemium_days else [],
            "keys": key_count,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "linked_at": s.linked_at.isoformat() if s.linked_at else None,
            "panel_name": s.panel_name,
            "admin_role": s.admin_role,
            "anti_tamper_enabled": bool(s.anti_tamper_enabled),
            "greeting_enabled": bool(s.greeting_enabled),
            "greeting_message": s.greeting_message,
        })
    return out


@router.post("/services")
def create_service(payload: dict, user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "Service name is required")
    api_key = secrets.token_hex(32)
    s = Server(
        api_key=api_key,
        panel_name=name[:100],
        user_id=user.id,
        description=(payload.get("desc") or "").strip()[:2000] or None,
        freemium=bool(payload.get("freemium")),
        freemium_days=",".join(payload.get("days") or []) or None,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return {"id": s.id, "api_key": s.api_key, "name": s.panel_name}


@router.patch("/services/{service_id}")
def update_service(service_id: int, payload: dict, user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    s = db.query(Server).filter(Server.id == service_id).first()
    if not s:
        raise HTTPException(404, "Service not found")
    if s.user_id != user.id:
        raise HTTPException(403, "Not yours")
    if "name" in payload:
        n = (payload["name"] or "").strip()
        if not n:
            raise HTTPException(400, "Name cannot be empty")
        s.panel_name = n[:100]
    if "desc" in payload:
        s.description = (payload["desc"] or "").strip()[:2000] or None
    if "freemium" in payload:
        s.freemium = bool(payload["freemium"])
    if "days" in payload:
        s.freemium_days = ",".join(payload["days"] or []) or None
    db.commit()
    return {"ok": True}


@router.delete("/services/{service_id}")
def delete_service(service_id: int, user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    s = db.query(Server).filter(Server.id == service_id).first()
    if not s:
        raise HTTPException(404, "Service not found")
    if s.user_id != user.id:
        raise HTTPException(403, "Not yours")
    # Detach licenses so they don't dangle; don't delete them.
    db.query(License).filter(License.server_id == s.id).update({"server_id": None})
    db.delete(s)
    db.commit()
    return {"ok": True}


@router.post("/services/{service_id}/rotate-key")
def rotate_service_key(service_id: int, user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    s = db.query(Server).filter(Server.id == service_id).first()
    if not s:
        raise HTTPException(404, "Service not found")
    if s.user_id != user.id:
        raise HTTPException(403, "Not yours")
    s.api_key = secrets.token_hex(32)
    db.commit()
    return {"api_key": s.api_key}


# ==================== KEYS (read-only; creation is Discord-only) ====================
# Keys come from /generatekey, /whitelist, or panel redeem in the bot.
# The dashboard never mints keys.

@router.get("/keys")
async def list_keys(user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    server_ids = _user_server_ids(db, user.id)
    if not server_ids:
        return []

    lics = (
        db.query(License)
        .filter(License.server_id.in_(server_ids))
        .order_by(License.created_at.desc())
        .all()
    )
    server_map = {s.id: s for s in db.query(Server).filter(Server.id.in_(server_ids)).all()}

    out = []
    for lic in lics:
        sv = server_map.get(lic.server_id)

        # HWID: prefer a non-banned device, most recently seen.
        dev = (
            db.query(Device)
            .filter(Device.license_id == lic.id)
            .order_by(Device.banned.asc(), Device.last_seen.desc())
            .first()
        )

        # Executions: successful verify events
        ex = db.query(AuthLog).filter(
            AuthLog.license_id == lic.id,
            AuthLog.event_type == "verify",
            AuthLog.success == True,
        ).count()

        # Discord identity — cached pfp via bot token, fallback to default avatar.
        username = lic.redeemed_name
        avatar_url = None
        if lic.redeemed_by:
            uname, aurl = await _fetch_discord_user(lic.redeemed_by)
            if uname:
                username = username or uname
            avatar_url = aurl
            if not avatar_url:
                idx = int(lic.redeemed_by) % 6
                avatar_url = f"https://cdn.discordapp.com/embed/avatars/{idx}.png"

        out.append({
            "id": lic.id,
            "key": lic.key_plain or "(hidden)",
            "status": lic.status,
            "state": "Active" if lic.status == "active" else lic.status.title(),
            "server_id": lic.server_id,
            "server_name": (sv.panel_name or sv.guild_name or f"Server {sv.id}") if sv else None,
            "redeemed_by": str(lic.redeemed_by) if lic.redeemed_by else None,
            "redeemed_name": username,
            "avatar_url": avatar_url,
            "hwid": dev.device_hash if dev and not dev.banned else None,
            "executions": ex,
            "blacklisted": (lic.status == "banned") or bool(dev and dev.banned),
            "created_at": lic.created_at.isoformat() if lic.created_at else None,
            "last_used": lic.last_used.isoformat() if lic.last_used else None,
        })
    return out


@router.post("/keys/{license_id}/reset-hwid")
def reset_key_hwid(license_id: int, user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    server_ids = _user_server_ids(db, user.id)
    lic = db.query(License).filter(License.id == license_id).first()
    if not lic:
        raise HTTPException(404, "Key not found")
    if lic.server_id not in server_ids:
        raise HTTPException(403, "Not yours")
    db.query(Device).filter(Device.license_id == lic.id).delete()
    db.query(Session).filter(Session.license_id == lic.id).update({"revoked": True})
    db.commit()
    return {"ok": True}


@router.post("/keys/{license_id}/blacklist")
def toggle_key_blacklist(license_id: int, payload: dict, user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    server_ids = _user_server_ids(db, user.id)
    lic = db.query(License).filter(License.id == license_id).first()
    if not lic:
        raise HTTPException(404, "Key not found")
    if lic.server_id not in server_ids:
        raise HTTPException(403, "Not yours")
    on = bool(payload.get("on"))
    lic.status = "banned" if on else "active"
    db.commit()
    return {"ok": True, "status": lic.status}


@router.delete("/keys/{license_id}")
def delete_key(license_id: int, user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    server_ids = _user_server_ids(db, user.id)
    lic = db.query(License).filter(License.id == license_id).first()
    if not lic:
        raise HTTPException(404, "Key not found")
    if lic.server_id not in server_ids:
        raise HTTPException(403, "Not yours")
    db.query(Session).filter(Session.license_id == lic.id).delete()
    db.query(Device).filter(Device.license_id == lic.id).delete()
    db.delete(lic)
    db.commit()
    return {"ok": True}


# ==================== BLOCKLISTS ====================
@router.get("/blocklists")
def list_blocks(user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    server_ids = _user_server_ids(db, user.id)
    if not server_ids:
        return []
    rows = (
        db.query(Blocklist)
        .filter(Blocklist.server_id.in_(server_ids))
        .order_by(Blocklist.created_at.desc())
        .all()
    )
    return [
        {
            "id": b.id,
            "type": b.type,
            "value": b.value,
            "reason": b.reason,
            "added": b.created_at.strftime("%Y-%m-%d") if b.created_at else "",
        }
        for b in rows
    ]


@router.post("/blocklists")
def add_block(payload: dict, user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    server_ids = _user_server_ids(db, user.id)
    if not server_ids:
        raise HTTPException(400, "Create a service first")
    t = (payload.get("type") or "").strip()
    v = (payload.get("value") or "").strip()
    if t not in ("hwid", "discord"):
        raise HTTPException(400, "type must be hwid or discord")
    if not v:
        raise HTTPException(400, "value required")
    sid = int(payload.get("server_id") or server_ids[0])
    if sid not in server_ids:
        raise HTTPException(403, "Not your server")
    exists = db.query(Blocklist).filter(
        Blocklist.server_id == sid,
        Blocklist.type == t,
        Blocklist.value == v,
    ).first()
    if exists:
        raise HTTPException(409, "Already blocked")
    b = Blocklist(server_id=sid, type=t, value=v, reason=(payload.get("reason") or "").strip() or None)
    db.add(b)
    db.commit()
    return {"ok": True, "id": b.id}


@router.delete("/blocklists/{block_id}")
def delete_block(block_id: int, user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    server_ids = _user_server_ids(db, user.id)
    b = db.query(Blocklist).filter(Blocklist.id == block_id).first()
    if not b:
        raise HTTPException(404, "Block not found")
    if b.server_id not in server_ids:
        raise HTTPException(403, "Not yours")
    db.delete(b)
    db.commit()
    return {"ok": True}


# ==================== ENFORCEMENT HELPER ====================
# Import into main.py's /v2/auth/init to actually reject blocked HWIDs/Discord IDs.

def is_blocked(db, server_id, hwid=None, discord_id=None):
    if not server_id:
        return False
    q = db.query(Blocklist).filter(Blocklist.server_id == server_id)
    if hwid and q.filter(Blocklist.type == "hwid", Blocklist.value == hwid).first():
        return True
    if discord_id and q.filter(Blocklist.type == "discord", Blocklist.value == str(discord_id)).first():
        return True
    return False
