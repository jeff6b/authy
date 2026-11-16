from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse, HTMLResponse, Response
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, BigInteger, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timedelta
from fastapi_limiter.depends import RateLimiter
from pyrate_limiter import Duration, Limiter, Rate
import os
import secrets
import hashlib

# ==================== CONFIG ====================
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    DATABASE_URL = "postgresql://neondb_owner:npg_S7hoDMeaw2cQ@ep-wandering-dream-ah21egpt-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require"
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

CHALLENGE_TTL = 60          # seconds
SESSION_TTL = 3600          # seconds
MAX_FAILURES = 10
FAILURE_WINDOW_MINUTES = 10

# ==================== MODELS ====================
class Server(Base):
    __tablename__ = "servers"
    id = Column(Integer, primary_key=True)
    api_key = Column(String(64), unique=True, nullable=False)
    guild_id = Column(BigInteger, unique=True, nullable=True)
    guild_name = Column(String(200), nullable=True)
    admin_role = Column(String(100), nullable=True)
    panel_name = Column(String(100), nullable=True, default="Key Panel")
    panel_message_id = Column(BigInteger, nullable=True)
    panel_channel_id = Column(BigInteger, nullable=True)
    buyer_role = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    linked_at = Column(DateTime, nullable=True)

class License(Base):
    __tablename__ = "licenses"
    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, nullable=True)
    key_hash = Column(String(64), unique=True, nullable=False)
    key_plain = Column(String(64), nullable=True)
    status = Column(String(20), default="active")
    expires_at = Column(DateTime, nullable=True)
    max_devices = Column(Integer, default=1)
    redeemed_by = Column(BigInteger, nullable=True)
    redeemed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)

class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True)
    license_id = Column(Integer, ForeignKey("licenses.id"))
    device_hash = Column(String(128), nullable=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    banned = Column(Boolean, default=False)

class Session(Base):
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True)
    license_id = Column(Integer, ForeignKey("licenses.id"))
    device_id = Column(Integer, ForeignKey("devices.id"))
    token_hash = Column(String(64), unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    last_heartbeat = Column(DateTime, default=datetime.utcnow)
    revoked = Column(Boolean, default=False)

class Challenge(Base):
    __tablename__ = "challenges"
    id = Column(Integer, primary_key=True)
    challenge_hash = Column(String(64), unique=True, nullable=False)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    expires_at = Column(DateTime, nullable=False)
    consumed_at = Column(DateTime, nullable=True)

class AuthLog(Base):
    __tablename__ = "auth_logs"
    id = Column(Integer, primary_key=True)
    license_id = Column(Integer, nullable=True)
    ip_address = Column(String(64), nullable=True)
    event_type = Column(String(40), nullable=True)
    success = Column(Boolean, default=False)
    failure_reason = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Script(Base):
    __tablename__ = "script"
    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, nullable=True)
    name = Column(String(200), nullable=True)
    content = Column(Text, nullable=False, default="")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class HostedFile(Base):
    __tablename__ = "hosted_files"
    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, nullable=True)
    token = Column(String(64), unique=True, nullable=False)
    filename = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def log_auth(db, license_id, ip, event, success, reason=None):
    db.add(AuthLog(license_id=license_id, ip_address=ip, event_type=event,
                   success=success, failure_reason=reason))
    db.commit()

def recent_failures(db, license_id, minutes):
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    return db.query(AuthLog).filter(
        AuthLog.license_id == license_id,
        AuthLog.success == False,
        AuthLog.created_at >= cutoff,
    ).count()

# ==================== APP ====================
app = FastAPI()

BLOCK_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Not permitted</title>
<style>html,body{margin:0;height:100%;background:#000;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif}span{color:#4a4a4a;font-size:2rem;font-weight:600}</style>
</head><body><span>Not permitted mijo</span></body></html>"""

# Rate limiters (in-memory, per-process)
init_limiter = Limiter(Rate(5, Duration.MINUTE))
verify_limiter = Limiter(Rate(5, Duration.MINUTE))

# ---- v2 auth flow ----
@app.post("/v2/auth/init", dependencies=[Depends(RateLimiter(limiter=init_limiter))])
def auth_init(payload: dict, request: Request, db=Depends(get_db)):
    license_key = (payload.get("license") or "").strip()
    ip = request.client.host if request.client else None
    if not license_key:
        raise HTTPException(400, "Missing license")

    key_hash = sha256(license_key)
    lic = db.query(License).filter(License.key_hash == key_hash).with_for_update().first()
    if not lic:
        log_auth(db, None, ip, "init", False, "not_found")
        raise HTTPException(401, "Invalid license")
    if lic.status != "active":
        log_auth(db, lic.id, ip, "init", False, "banned")
        raise HTTPException(403, "License banned")
    if lic.expires_at and lic.expires_at < datetime.utcnow():
        log_auth(db, lic.id, ip, "init", False, "expired")
        raise HTTPException(403, "License expired")

    if recent_failures(db, lic.id, FAILURE_WINDOW_MINUTES) >= MAX_FAILURES:
        lic.status = "banned"
        db.commit()
        log_auth(db, lic.id, ip, "init", False, "auto_banned")
        raise HTTPException(403, "License banned due to repeated failures")

    active_devices = db.query(Device).filter(
        Device.license_id == lic.id, Device.banned == False
    ).count()
    if active_devices >= (lic.max_devices or 1):
        stale_cutoff = datetime.utcnow() - timedelta(days=7)
        fresh = db.query(Device).filter(
            Device.license_id == lic.id,
            Device.banned == False,
            Device.last_seen >= stale_cutoff,
        ).count()
        if fresh >= (lic.max_devices or 1):
            log_auth(db, lic.id, ip, "init", False, "device_limit")
            raise HTTPException(403, "Device limit reached")

    raw_challenge = secrets.token_hex(32)
    ch = Challenge(
        challenge_hash=sha256(raw_challenge),
        expires_at=datetime.utcnow() + timedelta(seconds=CHALLENGE_TTL),
    )
    db.add(ch)
    db.commit()
    log_auth(db, lic.id, ip, "init", True)

    return {"challenge_id": ch.id, "challenge": raw_challenge, "expires_in": CHALLENGE_TTL}

@app.post("/v2/auth/verify", dependencies=[Depends(RateLimiter(limiter=verify_limiter))])
def auth_verify(payload: dict, request: Request, db=Depends(get_db)):
    challenge_id = payload.get("challenge_id")
    proof = (payload.get("proof") or "").strip()
    license_key = (payload.get("license") or "").strip()
    ip = request.client.host if request.client else None

    if not challenge_id or not proof or not license_key:
        raise HTTPException(400, "Missing fields")

    ch = db.query(Challenge).filter(Challenge.id == challenge_id).with_for_update().first()
    if not ch:
        raise HTTPException(401, "Unknown challenge")
    if ch.consumed_at:
        raise HTTPException(401, "Challenge already used")
    if ch.expires_at < datetime.utcnow():
        raise HTTPException(401, "Challenge expired")
    if sha256(proof) != ch.challenge_hash:
        log_auth(db, None, ip, "verify", False, "bad_proof")
        raise HTTPException(401, "Invalid proof")

    lic = db.query(License).filter(License.key_hash == sha256(license_key)).with_for_update().first()
    if not lic or lic.status != "active":
        raise HTTPException(403, "License invalid")

    if recent_failures(db, lic.id, FAILURE_WINDOW_MINUTES) >= MAX_FAILURES:
        lic.status = "banned"
        db.commit()
        raise HTTPException(403, "License banned due to repeated failures")

    device_hash = sha256(license_key + "|" + proof)[:128]
    dev = db.query(Device).filter(
        Device.license_id == lic.id, Device.device_hash == device_hash
    ).first()
    if not dev:
        dev = Device(license_id=lic.id, device_hash=device_hash)
        db.add(dev)
        db.flush()
    if dev.banned:
        raise HTTPException(403, "Device banned")
    dev.last_seen = datetime.utcnow()

    ch.consumed_at = datetime.utcnow()
    ch.device_id = dev.id

    raw_token = secrets.token_hex(32)
    sess = Session(
        license_id=lic.id,
        device_id=dev.id,
        token_hash=sha256(raw_token),
        expires_at=datetime.utcnow() + timedelta(seconds=SESSION_TTL),
    )
    db.add(sess)
    db.commit()
    log_auth(db, lic.id, ip, "verify", True)

    return {"success": True, "session_token": raw_token, "expires_in": SESSION_TTL}

@app.post("/v2/auth/heartbeat")
def auth_heartbeat(payload: dict, db=Depends(get_db)):
    raw_token = (payload.get("session_token") or "").strip()
    if not raw_token:
        return {"valid": False, "reason": "missing_token"}

    sess = db.query(Session).filter(Session.token_hash == sha256(raw_token)).first()
    if not sess:
        return {"valid": False, "reason": "unknown_session"}
    if sess.revoked:
        return {"valid": False, "reason": "revoked"}
    if sess.expires_at < datetime.utcnow():
        return {"valid": False, "reason": "expired"}

    lic = db.query(License).filter(License.id == sess.license_id).first()
    if not lic or lic.status != "active":
        return {"valid": False, "reason": "license_inactive"}

    dev = db.query(Device).filter(Device.id == sess.device_id).first()
    if dev and dev.banned:
        return {"valid": False, "reason": "device_banned"}

    sess.last_heartbeat = datetime.utcnow()
    lic.last_used = datetime.utcnow()
    if dev:
        dev.last_seen = datetime.utcnow()
    db.commit()
    return {"valid": True}

# ---- script delivery (only after valid session) ----
@app.get("/v2/script", response_class=PlainTextResponse)
def serve_script(session_token: str, db=Depends(get_db)):
    sess = db.query(Session).filter(Session.token_hash == sha256(session_token)).first()
    if not sess or sess.revoked or sess.expires_at < datetime.utcnow():
        raise HTTPException(401, "Invalid session")

    lic = db.query(License).filter(License.id == sess.license_id, License.status == "active").first()
    if not lic:
        raise HTTPException(403, "License inactive")

    if not lic.server_id:
        return ""
    s = db.query(Script).filter(Script.server_id == lic.server_id).first()
    return s.content if s else ""

@app.get("/raw/{token}")
def raw_file(token: str, request: Request, db=Depends(get_db)):
    f = db.query(HostedFile).filter(HostedFile.token == token).first()
    if not f:
        raise HTTPException(404, "Not found")
    ua = (request.headers.get("user-agent") or "").lower()
    if "mozilla" in ua and "text/html" in (request.headers.get("accept") or "").lower():
        return HTMLResponse(BLOCK_PAGE, status_code=200)
    return Response(content=f.content, media_type="text/plain")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))