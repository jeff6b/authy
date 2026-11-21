# dashboard_api.py — Real backend for the dashboard.
# Owns: /api/overview, /api/services, /api/keys, /api/blocklists, /api/integrations.
# Key creation is Discord-only (/generatekey, /whitelist) EXCEPT freemium claim keys from integrations.
# Dashboard is read + manage.

import asyncio
import os
import re
import secrets
from datetime import datetime, timedelta

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import Column, Integer, String, Boolean, DateTime, func
from sqlalchemy.orm import Session as OrmSession

from main import (
    Base,
    engine,
    SessionLocal,
    Server,
    License,
    Device,
    Session,
    AuthLog,
    Blocklist,
    sha256,
)
from auth import get_current_user, User
from discord_media import fetch_discord_user, fetch_guild_media


router = APIRouter(prefix="/api")


# ==================== INTEGRATIONS ====================
PROVIDERS = {
    "linkvertise": "Linkvertise",
    "lootlabs":    "Lootlabs",
    "workink":     "Work.ink",
}


class Integration(Base):
    __tablename__ = "integrations"
    id              = Column(Integer, primary_key=True)
    user_id         = Column(Integer, nullable=False, index=True)
    provider        = Column(String(32), nullable=False)
    name            = Column(String(100), nullable=False)
    enabled         = Column(Boolean, default=False)
    created_at      = Column(DateTime, default=datetime.utcnow)
    # Claim / monetization
    slug            = Column(String(64), nullable=True, index=True)
    server_id       = Column(Integer, nullable=True)
    key_hours       = Column(Integer, default=24)
    provider_link   = Column(String(512), nullable=True)
    api_token       = Column(String(256), nullable=True)
    publisher_id    = Column(String(64), nullable=True)


class ClaimSession(Base):
    __tablename__ = "claim_sessions"
    id              = Column(Integer, primary_key=True)
    token           = Column(String(64), unique=True, nullable=False, index=True)
    integration_id  = Column(Integer, nullable=False)
    completed       = Column(Boolean, default=False)
    license_id      = Column(Integer, nullable=True)
    key_plain       = Column(String(64), nullable=True)
    created_at      = Column(DateTime, default=datetime.utcnow)
    expires_at      = Column(DateTime, nullable=False)


Base.metadata.create_all(bind=engine, tables=[Integration.__table__, ClaimSession.__table__])


# Soft migrations for existing deployments
def _migrate_integrations():
    from sqlalchemy import text
    stmts = [
        "ALTER TABLE integrations ADD COLUMN IF NOT EXISTS slug VARCHAR(64)",
        "ALTER TABLE integrations ADD COLUMN IF NOT EXISTS server_id INTEGER",
        "ALTER TABLE integrations ADD COLUMN IF NOT EXISTS key_hours INTEGER DEFAULT 24",
        "ALTER TABLE integrations ADD COLUMN IF NOT EXISTS provider_link VARCHAR(512)",
        "ALTER TABLE integrations ADD COLUMN IF NOT EXISTS api_token VARCHAR(256)",
        "ALTER TABLE integrations ADD COLUMN IF NOT EXISTS publisher_id VARCHAR(64)",
    ]
    for s in stmts:
        try:
            with engine.begin() as conn:
                conn.execute(text(s))
        except Exception as e:
            print(f"[dashboard_api.migrate] skipped: {s} -> {e}")


_migrate_integrations()


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


def _slugify(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9\-]", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s[:48] or secrets.token_hex(4)


def fmt_hours(h: int) -> str:
    h = int(h or 24)
    if h < 24:
        return f"{h}h"
    d, r = divmod(h, 24)
    return f"{d}d" if not r else f"{d}d {r}h"


CLAIM_TTL_MIN = 30


async def verify_linkvertise(api_token: str, hash_val: str) -> bool:
    if not api_token or not hash_val:
        return False
    url = "https://publisher.linkvertise.com/api/v1/anti_bypassing"
    try:
        async with httpx.AsyncClient(timeout=12) as client:
            r = await client.post(url, params={"token": api_token, "hash": hash_val})
            text = (r.text or "").strip().upper()
            if text in ("TRUE", "1", "YES"):
                return True
            try:
                j = r.json()
                return bool(j is True or j.get("valid") or j.get("success"))
            except Exception:
                return False
    except Exception as e:
        print(f"[claim] linkvertise verify error: {e}")
        return False


async def verify_workink(token: str) -> bool:
    if not token:
        return False
    url = f"https://work.ink/_api/v2/token/isValid/{token}?deleteToken=1"
    try:
        async with httpx.AsyncClient(timeout=12) as client:
            r = await client.get(url)
            return bool(r.json().get("valid"))
    except Exception as e:
        print(f"[claim] workink verify error: {e}")
        return False


def issue_claim_key(db, integration: Integration) -> tuple:
    """Create a License for this integration's server. Returns (key_plain, license_id)."""
    if not integration.server_id:
        raise HTTPException(400, "Integration has no service linked")
    raw = secrets.token_hex(16).upper()
    key = "-".join(raw[i:i + 4] for i in range(0, 16, 4))
    expires = datetime.utcnow() + timedelta(hours=integration.key_hours or 24)
    lic = License(
        server_id=integration.server_id,
        key_hash=sha256(key),
        key_plain=key,
        status="active",
        expires_at=expires,
        max_devices=1,
    )
    db.add(lic)
    db.commit()
    db.refresh(lic)
    return key, lic.id


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
@router.get("/services")
async def list_services(user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    rows = db.query(Server).filter(Server.user_id == user.id).order_by(Server.id.desc()).all()
    media = await asyncio.gather(*[fetch_guild_media(s.guild_id) for s in rows])
    out = []
    for s, (gname, gicon) in zip(rows, media):
        key_count = db.query(License).filter(License.server_id == s.id).count()
        out.append({
            "id": s.id,
            "sid": str(s.id),
            "api_key": s.api_key,
            "name": s.panel_name or s.guild_name or f"Server {s.id}",
            "desc": s.description or "",
            "guild_id": str(s.guild_id) if s.guild_id else None,
            "guild_name": s.guild_name or gname,
            "icon_url": gicon,
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


# ==================== KEYS ====================
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

        dev = (
            db.query(Device)
            .filter(Device.license_id == lic.id)
            .order_by(Device.banned.asc(), Device.last_seen.desc())
            .first()
        )

        ex = db.query(AuthLog).filter(
            AuthLog.license_id == lic.id,
            AuthLog.event_type == "verify",
            AuthLog.success == True,
        ).count()

        username = lic.redeemed_name
        avatar_url = None
        if lic.redeemed_by:
            uname, aurl = await fetch_discord_user(lic.redeemed_by)
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


# ==================== INTEGRATIONS CRUD ====================
@router.get("/integrations")
def list_integrations(user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    rows = (
        db.query(Integration)
        .filter(Integration.user_id == user.id)
        .order_by(Integration.id.desc())
        .all()
    )
    return [
        {
            "id": i.id,
            "provider": i.provider,
            "provider_label": PROVIDERS.get(i.provider, i.provider),
            "name": i.name,
            "enabled": bool(i.enabled),
            "slug": i.slug or "",
            "server_id": i.server_id,
            "key_hours": i.key_hours or 24,
            "provider_link": i.provider_link or "",
            "has_token": bool(i.api_token),
            "publisher_id": i.publisher_id or "",
            "claim_url": f"/go/{i.slug}" if i.slug else None,
            "created_at": i.created_at.isoformat() if i.created_at else None,
        }
        for i in rows
    ]


@router.post("/integrations")
def create_integration(payload: dict, user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    provider = (payload.get("provider") or "").strip().lower()
    if provider not in PROVIDERS:
        raise HTTPException(400, "Pick a provider")
    name = (payload.get("name") or "").strip() or PROVIDERS[provider]
    slug = _slugify(payload.get("slug") or name)
    exists = db.query(Integration).filter(Integration.user_id == user.id, Integration.slug == slug).first()
    if exists:
        slug = f"{slug}-{secrets.token_hex(2)}"

    try:
        key_hours = int(payload.get("key_hours") or 24)
    except (TypeError, ValueError):
        key_hours = 24
    key_hours = max(1, min(720, key_hours))

    server_id = payload.get("server_id")
    if server_id is not None and server_id != "":
        server_id = int(server_id)
        if server_id not in _user_server_ids(db, user.id):
            raise HTTPException(403, "Not your service")
    else:
        server_id = None

    i = Integration(
        user_id=user.id,
        provider=provider,
        name=name[:100],
        enabled=bool(payload.get("enabled")),
        slug=slug,
        server_id=server_id,
        key_hours=key_hours,
        provider_link=(payload.get("provider_link") or "").strip()[:512] or None,
        api_token=(payload.get("api_token") or "").strip()[:256] or None,
        publisher_id=(payload.get("publisher_id") or "").strip()[:64] or None,
    )
    db.add(i)
    db.commit()
    db.refresh(i)
    return {"ok": True, "id": i.id, "slug": i.slug, "claim_url": f"/go/{i.slug}"}


@router.patch("/integrations/{integration_id}")
def update_integration(integration_id: int, payload: dict, user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    i = db.query(Integration).filter(Integration.id == integration_id).first()
    if not i:
        raise HTTPException(404, "Integration not found")
    if i.user_id != user.id:
        raise HTTPException(403, "Not yours")

    if "provider" in payload:
        p = (payload["provider"] or "").strip().lower()
        if p not in PROVIDERS:
            raise HTTPException(400, "Unknown provider")
        i.provider = p
    if "name" in payload:
        n = (payload["name"] or "").strip()
        if not n:
            raise HTTPException(400, "Name cannot be empty")
        i.name = n[:100]
    if "enabled" in payload:
        i.enabled = bool(payload["enabled"])
    if "slug" in payload:
        slug = _slugify(payload["slug"])
        clash = db.query(Integration).filter(
            Integration.user_id == user.id,
            Integration.slug == slug,
            Integration.id != i.id,
        ).first()
        if clash:
            raise HTTPException(409, "Slug already in use")
        i.slug = slug
    if "key_hours" in payload:
        try:
            i.key_hours = max(1, min(720, int(payload["key_hours"] or 24)))
        except (TypeError, ValueError):
            pass
    if "server_id" in payload:
        sid = payload["server_id"]
        if sid is None or sid == "":
            i.server_id = None
        else:
            sid = int(sid)
            if sid not in _user_server_ids(db, user.id):
                raise HTTPException(403, "Not your service")
            i.server_id = sid
    if "provider_link" in payload:
        i.provider_link = (payload["provider_link"] or "").strip()[:512] or None
    if "api_token" in payload:
        tok = (payload["api_token"] or "").strip()
        if tok:
            i.api_token = tok[:256]
    if "publisher_id" in payload:
        i.publisher_id = (payload["publisher_id"] or "").strip()[:64] or None

    db.commit()
    return {"ok": True, "slug": i.slug, "claim_url": f"/go/{i.slug}" if i.slug else None}


@router.delete("/integrations/{integration_id}")
def delete_integration(integration_id: int, user: User = Depends(get_current_user), db: OrmSession = Depends(get_db)):
    i = db.query(Integration).filter(Integration.id == integration_id).first()
    if not i:
        raise HTTPException(404, "Integration not found")
    if i.user_id != user.id:
        raise HTTPException(403, "Not yours")
    db.delete(i)
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
def is_blocked(db, server_id, hwid=None, discord_id=None):
    if not server_id:
        return False
    q = db.query(Blocklist).filter(Blocklist.server_id == server_id)
    if hwid and q.filter(Blocklist.type == "hwid", Blocklist.value == hwid).first():
        return True
    if discord_id and q.filter(Blocklist.type == "discord", Blocklist.value == str(discord_id)).first():
        return True
    return False
