from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func
from datetime import datetime, timedelta
import os
import secrets

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI()

ONLINE_WINDOW = 15  # seconds since last heartbeat = online

class Key(Base):
    __tablename__ = "keys"
    id = Column(Integer, primary_key=True)
    key_value = Column(String(64), unique=True, nullable=False)
    banned = Column(Boolean, default=False)
    last_seen = Column(DateTime, nullable=True)
    kick = Column(Boolean, default=False)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

DASHBOARD = """
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Keys</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.12.10/dist/full.min.css" rel="stylesheet">
<style>
  body { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; }
  .key-row { transition: background 0.15s; }
  .key-row:hover { background: rgba(255,255,255,0.03); }
  .ctx { position: fixed; z-index: 1000; background: #1f2937; border: 1px solid #374151;
         border-radius: 8px; padding: 4px; min-width: 160px; box-shadow: 0 8px 30px rgba(0,0,0,0.5); }
  .ctx button { display: block; width: 100%; text-align: left; padding: 8px 12px;
                font-size: 13px; border-radius: 6px; background: none; border: none; color: #e5e7eb; cursor: pointer; }
  .ctx button:hover { background: #374151; }
  .ctx button.danger { color: #f87171; }
  .ctx button.danger:hover { background: #7f1d1d; }
  .dot-on  { background: #22c55e; box-shadow: 0 0 8px #22c55e; }
  .dot-off { background: #6b7280; }
</style>
</head>
<body class="bg-base-300 min-h-screen">

<div class="max-w-3xl mx-auto px-6 py-12">
  <div class="flex items-end justify-between mb-8">
    <div>
      <h1 class="text-3xl font-bold tracking-tight">Keys</h1>
      <p class="text-sm opacity-50 mt-1">Right-click a key for actions.</p>
    </div>
    <button onclick="generate()" id="genBtn" class="btn btn-primary btn-sm">Generate Key</button>
  </div>

  <div id="list" class="space-y-2"></div>
</div>

<div id="ctx" class="ctx hidden"></div>

<script>
let currentKeys = [];

async function load() {
  const res = await fetch("/api/keys");
  currentKeys = await res.json();
  const list = document.getElementById("list");
  if (currentKeys.length === 0) {
    list.innerHTML = '<div class="text-center opacity-40 py-16 text-sm">No keys yet. Generate one.</div>';
    return;
  }
  const now = Date.now();
  list.innerHTML = currentKeys.map(k => {
    const online = k.last_seen && (now - new Date(k.last_seen).getTime()) < 15000;
    return `
    <div class="key-row flex items-center gap-3 bg-base-100 rounded-lg px-4 py-3"
         oncontextmenu="showCtx(event, ${k.id}, ${online})">
      <span class="w-2 h-2 rounded-full ${online ? 'dot-on' : 'dot-off'}"></span>
      <code class="flex-1 text-sm font-mono truncate">${k.key_value}</code>
      <span class="text-xs opacity-40">${online ? 'online' : 'offline'}</span>
    </div>`;
  }).join('');
}

function showCtx(e, id, online) {
  e.preventDefault();
  const ctx = document.getElementById("ctx");
  ctx.innerHTML = `
    <button onclick="copyKey(${id})">Copy key</button>
    <button onclick="deleteKey(${id})">Delete key</button>
    <button class="danger" onclick="kickKey(${id})" ${online ? '' : 'disabled style="opacity:0.4"}>Kick from game</button>
  `;
  ctx.style.left = e.pageX + "px";
  ctx.style.top = e.pageY + "px";
  ctx.classList.remove("hidden");
}

document.addEventListener("click", () => document.getElementById("ctx").classList.add("hidden"));

function findKey(id) { return currentKeys.find(k => k.id === id); }

async function copyKey(id) {
  await navigator.clipboard.writeText(findKey(id).key_value);
}

async function deleteKey(id) {
  if (!confirm("Delete this key?")) return;
  await fetch("/api/keys/" + id, {method: "DELETE"});
  load();
}

async function kickKey(id) {
  if (!confirm("Kick this user from the game?")) return;
  await fetch("/api/keys/" + id + "/kick", {method: "POST"});
  load();
}

async function generate() {
  const btn = document.getElementById("genBtn");
  btn.disabled = true;
  btn.textContent = "Generating...";
  await fetch("/api/keys", {method: "POST"});
  btn.disabled = false;
  btn.textContent = "Generate Key";
  load();
}

load();
setInterval(load, 3000);  // refresh every 3s
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD

@app.get("/api/keys")
def list_keys(db=Depends(get_db)):
    out = []
    for k in db.query(Key).order_by(Key.id.desc()).all():
        out.append({
            "id": k.id,
            "key_value": k.key_value,
            "last_seen": k.last_seen.isoformat() if k.last_seen else None,
            "kick": k.kick,
        })
    return out

@app.post("/api/keys")
def create_key(db=Depends(get_db)):
    k = Key(key_value=secrets.token_hex(32))
    db.add(k)
    db.commit()
    return {"key": k.key_value}

@app.delete("/api/keys/{key_id}")
def delete_key(key_id: int, db=Depends(get_db)):
    k = db.query(Key).get(key_id)
    if k:
        db.delete(k)
        db.commit()
    return {"success": True}

@app.post("/api/keys/{key_id}/kick")
def kick_key(key_id: int, db=Depends(get_db)):
    k = db.query(Key).get(key_id)
    if not k:
        raise HTTPException(404, "Key not found")
    k.kick = True
    db.commit()
    return {"success": True}

@app.get("/validate", response_class=PlainTextResponse)
def validate(key: str, db=Depends(get_db)):
    k = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
    if not k:
        return "invalid"
    k.last_seen = datetime.utcnow()
    db.commit()
    return "valid"

@app.get("/heartbeat", response_class=PlainTextResponse)
def heartbeat(key: str, db=Depends(get_db)):
    k = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
    if not k:
        return "invalid"
    k.last_seen = datetime.utcnow()
    kicked = k.kick
    if kicked:
        k.kick = False
        db.commit()
        return "kick"
    db.commit()
    return "ok"
