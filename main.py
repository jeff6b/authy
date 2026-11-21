from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse, HTMLResponse, Response, JSONResponse
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, BigInteger, ForeignKey, text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timedelta
from collections import defaultdict, deque
import os
import secrets
import hashlib
import hmac
import time
import asyncio
import traceback

# ==================== CONFIG ====================
# Set DATABASE_URL as an environment variable on Render. Never hardcode it.
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set")
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

# Set DEBUG_ERRORS=0 on Render once everything works, so 500s stop leaking details.
DEBUG_ERRORS = os.getenv("DEBUG_ERRORS", "1") == "1"

engine = create_engine(DATABASE_URL, pool_pre_ping=True, pool_recycle=300)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

CHALLENGE_TTL = 60
SESSION_TTL = 3600
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
    anti_tamper_enabled = Column(Boolean, default=False)
    greeting_enabled = Column(Boolean, default=False)
    greeting_message = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    linked_at = Column(DateTime, nullable=True)
    user_id = Column(Integer, nullable=True)
    # Dashboard-only fields (not used by bot)
    description = Column(Text, nullable=True)
    freemium = Column(Boolean, default=False)
    freemium_days = Column(String(64), nullable=True)  # "Mon,Tue,Wed"
    integration_id = Column(String(64), nullable=True)

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
    redeemed_name = Column(String(100), nullable=True)
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
    secret_plain = Column(String(64), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    last_heartbeat = Column(DateTime, default=datetime.utcnow)
    revoked = Column(Boolean, default=False)

class Challenge(Base):
    __tablename__ = "challenges"
    id = Column(Integer, primary_key=True)
    challenge_hash = Column(String(64), unique=True, nullable=False)
    device_hash = Column(String(128), nullable=True)
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

class Blocklist(Base):
    __tablename__ = "blocklists"
    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, nullable=True)
    type = Column(String(16), nullable=False)  # "hwid" | "discord"
    value = Column(String(128), nullable=False)
    reason = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ==================== MIGRATIONS ====================
def run_migrations():
    stmts = [
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS redeemed_name VARCHAR(100)",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS anti_tamper_enabled BOOLEAN DEFAULT FALSE",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS greeting_enabled BOOLEAN DEFAULT FALSE",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS greeting_message VARCHAR(200)",
        "ALTER TABLE script ADD COLUMN IF NOT EXISTS server_id INTEGER",
        "ALTER TABLE script ADD COLUMN IF NOT EXISTS name VARCHAR(200)",
        "ALTER TABLE script ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()",
        "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS secret_plain VARCHAR(64)",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS user_id INTEGER",
        # Dashboard-only fields
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS description TEXT",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS freemium BOOLEAN DEFAULT FALSE",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS freemium_days VARCHAR(64)",
        "ALTER TABLE servers ADD COLUMN IF NOT EXISTS integration_id VARCHAR(64)",
        # Auth tables (older deployments may be missing these)
        "ALTER TABLE challenges ADD COLUMN IF NOT EXISTS device_hash VARCHAR(128)",
        "ALTER TABLE challenges ADD COLUMN IF NOT EXISTS device_id INTEGER",
        "ALTER TABLE challenges ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMP",
        "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_id INTEGER",
        "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_heartbeat TIMESTAMP DEFAULT NOW()",
        "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked BOOLEAN DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS banned BOOLEAN DEFAULT FALSE",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP DEFAULT NOW()",
        "ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP DEFAULT NOW()",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS max_devices INTEGER DEFAULT 1",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS key_plain VARCHAR(64)",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS redeemed_by BIGINT",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS redeemed_at TIMESTAMP",
        "ALTER TABLE licenses ADD COLUMN IF NOT EXISTS last_used TIMESTAMP",
        "ALTER TABLE auth_logs ADD COLUMN IF NOT EXISTS ip_address VARCHAR(64)",
        "ALTER TABLE auth_logs ADD COLUMN IF NOT EXISTS event_type VARCHAR(40)",
        "ALTER TABLE auth_logs ADD COLUMN IF NOT EXISTS success BOOLEAN DEFAULT FALSE",
        "ALTER TABLE auth_logs ADD COLUMN IF NOT EXISTS failure_reason VARCHAR(200)",
    ]
    for s in stmts:
        try:
            with engine.begin() as conn:
                conn.execute(text(s))
        except Exception as e:
            print(f"[migrate] skipped: {s} -> {e}")
    print("[migrate] done")


def relax_legacy_not_null():
    """
    Old versions of these tables may have NOT NULL columns that the current models
    never fill in, which makes every INSERT fail with a 500. For each auth table, any
    NOT NULL column with no default that the model doesn't define gets relaxed.
    """
    tables = {
        "challenges": {c.name for c in Challenge.__table__.columns},
        "sessions": {c.name for c in Session.__table__.columns},
        "devices": {c.name for c in Device.__table__.columns},
        "licenses": {c.name for c in License.__table__.columns},
        "auth_logs": {c.name for c in AuthLog.__table__.columns},
    }
    try:
        with engine.begin() as conn:
            for table, known in tables.items():
                rows = conn.execute(text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = :t AND is_nullable = 'NO' AND column_default IS NULL"
                ), {"t": table}).fetchall()
                for (col,) in rows:
                    if col not in known:
                        print(f"[migrate] relaxing legacy NOT NULL: {table}.{col}")
                        conn.execute(text(f'ALTER TABLE {table} ALTER COLUMN "{col}" DROP NOT NULL'))
    except Exception as e:
        print(f"[migrate] relax_legacy_not_null failed: {e}")


run_migrations()
relax_legacy_not_null()

# ==================== APP INITIALIZATION ====================
app = FastAPI()

# ---- Simple in-memory sliding-window rate limiter (no external package) ----
_rate_hits = defaultdict(deque)

def _client_ip(request: Request) -> str:
    # Behind Cloudflare/Render the real IP is in a header, not request.client.
    ip = request.headers.get("cf-connecting-ip")
    if not ip:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            ip = xff.split(",")[0].strip()
    if not ip and request.client:
        ip = request.client.host
    return ip or "unknown"

def rate_limit(name: str, max_calls: int, seconds: int):
    def dep(request: Request):
        key = (name, _client_ip(request))
        now = time.time()
        q = _rate_hits[key]
        while q and now - q[0] > seconds:
            q.popleft()
        if len(q) >= max_calls:
            raise HTTPException(429, "Too many requests")
        q.append(now)
        if not q:
            _rate_hits.pop(key, None)
    return dep

init_limit = rate_limit("init", 5, 60)
verify_limit = rate_limit("verify", 5, 60)
script_limit = rate_limit("script", 10, 60)

BLOCK_PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Not permitted</title>
<style>html,body{margin:0;height:100%;background:#000;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif}span{color:#4a4a4a;font-size:2rem;font-weight:600}</style>
</head><body><span>Not permitted mijo</span></body></html>"""


# Any unexpected crash now returns JSON (so the Lua loader can read it) and logs a traceback.
@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception):
    traceback.print_exc()
    detail = f"{type(exc).__name__}: {str(exc)[:300]}" if DEBUG_ERRORS else "server_error"
    return JSONResponse({"detail": detail}, status_code=500)


# ==================== BACKGROUND TASKS ====================
async def db_cleanup_task():
    while True:
        try:
            db = SessionLocal()
            try:
                cutoff = datetime.utcnow() - timedelta(days=7)
                db.query(AuthLog).filter(AuthLog.created_at < cutoff).delete()
                db.query(Session).filter(Session.expires_at < datetime.utcnow()).delete()
                db.query(Challenge).filter(Challenge.expires_at < datetime.utcnow()).delete()
                db.commit()
            finally:
                db.close()
            print("[cleanup] Old logs and sessions purged.")
        except Exception as e:
            print(f"[cleanup] Error: {e}")
        await asyncio.sleep(3600)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(db_cleanup_task())

# ==================== HELPERS ====================
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

# ==================== FRONTEND ====================
@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    file_path = os.path.join(os.path.dirname(__file__), "frontend.html")
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Frontend not found</h1><p>Please create frontend.html in the root directory.</p>"

@app.get("/health")
def health(db=Depends(get_db)):
    db.execute(text("SELECT 1"))
    return {"ok": True}

# ==================== AUTH ENDPOINTS (executor-facing) ====================
@app.post("/v2/auth/init", dependencies=[Depends(init_limit)])
def auth_init(payload: dict, request: Request, db=Depends(get_db)):
    license_key = (payload.get("license") or "").strip()
    raw_hwid = (payload.get("hwid") or "").strip()
    ip = request.client.host if request.client else None

    if not license_key:
        raise HTTPException(400, "Missing license")
    if not raw_hwid:
        raise HTTPException(400, "Missing hwid")

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

    device_hash = sha256(license_key + "|" + raw_hwid)[:128]
    existing_dev = db.query(Device).filter(
        Device.license_id == lic.id, Device.device_hash == device_hash
    ).first()

    if not existing_dev:
        active = db.query(Device).filter(
            Device.license_id == lic.id, Device.banned == False
        ).count()
        if active >= (lic.max_devices or 1):
            log_auth(db, lic.id, ip, "init", False, "device_limit")
            raise HTTPException(403, "Device limit reached")

    raw_challenge = secrets.token_hex(32)
    ch = Challenge(
        challenge_hash=sha256(raw_challenge),
        device_hash=device_hash,
        expires_at=datetime.utcnow() + timedelta(seconds=CHALLENGE_TTL),
    )
    db.add(ch)
    db.commit()
    challenge_id = ch.id
    log_auth(db, lic.id, ip, "init", True)

    return {"challenge_id": challenge_id, "challenge": raw_challenge, "expires_in": CHALLENGE_TTL}

@app.post("/v2/auth/verify", dependencies=[Depends(verify_limit)])
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

    if not hmac.compare_digest(sha256(proof), ch.challenge_hash):
        log_auth(db, None, ip, "verify", False, "bad_proof")
        raise HTTPException(401, "Invalid proof")

    if not ch.device_hash:
        raise HTTPException(401, "Challenge has no device binding")

    lic = db.query(License).filter(License.key_hash == sha256(license_key)).with_for_update().first()
    if not lic or lic.status != "active":
        raise HTTPException(403, "License invalid")

    if recent_failures(db, lic.id, FAILURE_WINDOW_MINUTES) >= MAX_FAILURES:
        lic.status = "banned"
        db.commit()
        raise HTTPException(403, "License banned due to repeated failures")

    dev = db.query(Device).filter(
        Device.license_id == lic.id, Device.device_hash == ch.device_hash
    ).first()
    if not dev:
        dev = Device(license_id=lic.id, device_hash=ch.device_hash)
        db.add(dev)
        db.flush()
    if dev.banned:
        raise HTTPException(403, "Device banned")

    dev.last_seen = datetime.utcnow()
    ch.consumed_at = datetime.utcnow()
    ch.device_id = dev.id
    lic.last_used = datetime.utcnow()

    raw_token = secrets.token_hex(32)
    raw_secret = secrets.token_hex(32)

    sess = Session(
        license_id=lic.id,
        device_id=dev.id,
        token_hash=sha256(raw_token),
        secret_plain=raw_secret,
        expires_at=datetime.utcnow() + timedelta(seconds=SESSION_TTL),
    )
    db.add(sess)
    db.commit()
    session_id = sess.id
    device_hash_out = ch.device_hash
    log_auth(db, lic.id, ip, "verify", True)

    server = db.query(Server).filter(Server.id == lic.server_id).first() if lic.server_id else None
    script_name = "unknown"
    if lic.server_id:
        s = db.query(Script).filter(Script.server_id == lic.server_id).first()
        if s and s.name:
            script_name = s.name
    project_name = (server.panel_name or server.guild_name or "unknown") if server else "unknown"
    session_count = db.query(Session).filter(
        Session.license_id == lic.id, Session.revoked == False, Session.expires_at > datetime.utcnow()
    ).count()

    time_left = None
    if lic.expires_at:
        delta = (lic.expires_at - datetime.utcnow()).total_seconds()
        time_left = max(0, int(delta))

    exec_count = db.query(AuthLog).filter(
        AuthLog.license_id == lic.id, AuthLog.event_type == "verify", AuthLog.success == True
    ).count()
    anti_tamper = bool(server.anti_tamper_enabled) if server else False
    greeting_enabled = bool(server.greeting_enabled) if server else False
    greeting_message = server.greeting_message if server else None

    return {
        "success": True,
        "session_token": raw_token,
        "session_secret": raw_secret,
        "session_id": session_id,
        "expires_in": SESSION_TTL,
        "anti_tamper": anti_tamper,
        "greeting_enabled": greeting_enabled,
        "greeting_message": greeting_message,
        "discord_id": lic.redeemed_by,
        "discord_name": lic.redeemed_name,
        "hwid": device_hash_out,
        "time_left": time_left,
        "session_count": session_count,
        "script_name": script_name,
        "project_name": project_name,
        "key_executions": exec_count,
    }

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

    if payload.get("tampered") is True:
        sess.revoked = True
        db.commit()
        return {"valid": False, "reason": "tampered"}

    sess.last_heartbeat = datetime.utcnow()
    lic.last_used = datetime.utcnow()
    if dev:
        dev.last_seen = datetime.utcnow()
    db.commit()
    return {"valid": True, "alive": True}

@app.post("/v2/auth/tamper")
def auth_tamper(payload: dict, request: Request, db=Depends(get_db)):
    ip = request.client.host if request.client else None
    license_key = (payload.get("license") or "").strip()
    session_token = (payload.get("session_token") or "").strip()
    reason = (payload.get("reason") or "unspecified")[:200]

    lic = None
    if session_token:
        sess = db.query(Session).filter(Session.token_hash == sha256(session_token)).first()
        if sess:
            lic = db.query(License).filter(License.id == sess.license_id).first()
    if not lic and license_key:
        lic = db.query(License).filter(License.key_hash == sha256(license_key)).first()

    if not lic:
        log_auth(db, None, ip, "tamper", True, f"already_gone:{reason}")
        return {"success": True, "already_deleted": True}

    lic_id = lic.id
    try:
        db.query(Session).filter(Session.license_id == lic_id).delete()
        db.query(Device).filter(Device.license_id == lic_id).delete()
        db.delete(lic)
        db.commit()
        log_auth(db, lic_id, ip, "tamper", True, reason)
    except Exception as e:
        db.rollback()
        print(f"[tamper] error deleting lic {lic_id}: {e}")
        try:
            log_auth(db, lic_id, ip, "tamper", True, f"partial:{reason}")
        except Exception:
            pass

    return {"success": True, "deleted": True}

@app.get("/v2/script", response_class=PlainTextResponse, dependencies=[Depends(script_limit)])
def serve_script(session_token: str, timestamp: int, signature: str, db=Depends(get_db)):
    if abs(time.time() - timestamp) > 10:
        raise HTTPException(401, "Request expired")

    sess = db.query(Session).filter(Session.token_hash == sha256(session_token)).first()
    if not sess or sess.revoked or sess.expires_at < datetime.utcnow():
        raise HTTPException(401, "Invalid session")

    expected_sig = hmac.new(
        sess.secret_plain.encode(),
        f"{session_token}{timestamp}".encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature.lower(), expected_sig):
        raise HTTPException(401, "Invalid signature")

    if (datetime.utcnow() - sess.last_heartbeat).total_seconds() > 60:
        raise HTTPException(403, "Heartbeat timeout - script rejected")

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

# ==================== WEB DASHBOARD (OAuth, /api/*) ====================
from auth import router as auth_router
app.include_router(auth_router)

from dashboard_api import router as dashboard_router
app.include_router(dashboard_router)

@app.get("/dashboard", response_class=HTMLResponse)
def serve_dashboard():
    fp = os.path.join(os.path.dirname(__file__), "dashboard.html")
    if os.path.exists(fp):
        with open(fp, "r", encoding="utf-8") as f:
            return f.read()
    return HTMLResponse("<h1>dashboard.html not found</h1>", status_code=404)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
