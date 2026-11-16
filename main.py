from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse, HTMLResponse, Response
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, BigInteger
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import os
import secrets

# ==================== CONFIG ====================
DATABASE_URL = "postgresql://neondb_owner:npg_S7hoDMeaw2cQ@ep-wandering-dream-ah21egpt-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require"
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

ONLINE_SECONDS = 6

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

class Key(Base):
    __tablename__ = "keys"
    id = Column(Integer, primary_key=True)
    server_id = Column(Integer, nullable=True)
    key_value = Column(String(64), unique=True, nullable=False)
    banned = Column(Boolean, default=False)
    last_seen = Column(DateTime, nullable=True)
    kick = Column(Boolean, default=False)
    redeemed_by = Column(BigInteger, nullable=True)
    redeemed_at = Column(DateTime, nullable=True)
    hwid = Column(String(256), nullable=True)
    hwid_resets = Column(Integer, default=0)
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

# ==================== FASTAPI ====================
app = FastAPI()

BLOCK_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Not permitted</title>
<style>html,body{margin:0;height:100%;background:#000;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif}span{color:#4a4a4a;font-size:2rem;font-weight:600}</style>
</head><body><span>Not permitted mijo</span></body></html>"""

@app.get("/validate", response_class=PlainTextResponse)
def validate(key: str, hwid: str = None, db=Depends(get_db)):
    k = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
    if not k:
        return "invalid"
    if hwid:
        if k.hwid and k.hwid != hwid:
            return "hwid_mismatch"
        if not k.hwid:
            k.hwid = hwid
    k.last_seen = datetime.utcnow()
    db.commit()
    return "valid"

@app.get("/script", response_class=PlainTextResponse)
def serve_script(key: str, db=Depends(get_db)):
    k = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
    if not k:
        raise HTTPException(401, "Invalid key")
    k.last_seen = datetime.utcnow()
    db.commit()
    if not k.server_id:
        return ""
    s = db.query(Script).filter(Script.server_id == k.server_id).first()
    if not s:
        return ""
    return s.content

@app.get("/raw/{token}")
def raw_file(token: str, request: Request, db=Depends(get_db)):
    f = db.query(HostedFile).filter(HostedFile.token == token).first()
    if not f:
        raise HTTPException(404, "Not found")

    ua = (request.headers.get("user-agent") or "").lower()
    looks_like_browser = (
        "mozilla" in ua
        and "text/html" in (request.headers.get("accept") or "").lower()
    )
    if looks_like_browser:
        return HTMLResponse(BLOCK_PAGE, status_code=200)

    return Response(content=f.content, media_type="text/plain")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
