from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from pydantic import BaseModel
from datetime import datetime
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

ONLINE_SECONDS = 6

class Key(Base):
    __tablename__ = "keys"
    id = Column(Integer, primary_key=True)
    key_value = Column(String(64), unique=True, nullable=False)
    banned = Column(Boolean, default=False)
    last_seen = Column(DateTime, nullable=True)
    kick = Column(Boolean, default=False)

class Script(Base):
    __tablename__ = "script"
    id = Column(Integer, primary_key=True)
    content = Column(Text, nullable=False, default="")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
<title>Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.12.10/dist/full.min.css" rel="stylesheet">
<style>
  body { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
  .tab { cursor: pointer; padding: 10px 20px; border-radius: 8px; font-weight: 500; font-size: 14px; }
  .tab-active { background-color: #4f46e5; color: white; }
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

<div class="navbar bg-base-100 shadow-lg border-b border-base-content/10">
  <div class="flex-1 px-4">
    <a class="text-2xl font-bold tracking-tight">Authy</a>
  </div>
</div>

<div class="max-w-4xl mx-auto p-6">
  <div class="flex gap-1 mb-8 bg-base-100 p-1.5 rounded-xl shadow-sm w-fit mx-auto flex-wrap">
    <div data-tab="overview" class="tab tab-active">Overview</div>
    <div data-tab="keys" class="tab">Keys</div>
    <div data-tab="script" class="tab">Lua Script</div>
    <div data-tab="service" class="tab">Service</div>
    <div data-tab="integration" class="tab">Integration</div>
  </div>

  <div id="tab-overview" class="tab-content active">
    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
      <div class="card bg-base-100 shadow-sm">
        <div class="card-body py-6">
          <div class="text-sm opacity-50">Total Keys</div>
          <div id="stat-total" class="text-3xl font-bold">–</div>
        </div>
      </div>
      <div class="card bg-base-100 shadow-sm">
        <div class="card-body py-6">
          <div class="text-sm opacity-50">Online Now</div>
          <div id="stat-online" class="text-3xl font-bold text-success">–</div>
        </div>
      </div>
      <div class="card bg-base-100 shadow-sm">
        <div class="card-body py-6">
          <div class="text-sm opacity-50">Banned</div>
          <div id="stat-banned" class="text-3xl font-bold text-error">–</div>
        </div>
      </div>
    </div>
    <div class="card bg-base-100 shadow-sm mt-6">
      <div class="card-body">
        <h2 class="card-title text-lg">Quick Start</h2>
        <p class="text-sm opacity-60 mt-1">Generate a key in the Keys tab, paste it into your loader, and you're done.</p>
      </div>
    </div>
  </div>

  <div id="tab-keys" class="tab-content">
    <div class="flex items-center justify-between mb-4">
      <p class="text-sm opacity-50">Right-click a key for actions.</p>
      <button id="genBtn" class="btn btn-primary btn-sm">Generate Key</button>
    </div>
    <div id="keyList" class="space-y-2"></div>
  </div>

  <div id="tab-script" class="tab-content">
    <div class="card bg-base-100 shadow-sm">
      <div class="card-body">
        <div class="flex items-center justify-between">
          <h2 class="card-title text-lg">Script Content</h2>
          <button id="saveBtn" class="btn btn-primary btn-sm">Save</button>
        </div>
        <p class="text-xs opacity-50 mt-1">This is what loads when a valid key runs the loader.</p>
        <textarea id="scriptBox" class="textarea textarea-bordered w-full h-96 font-mono text-sm mt-3" placeholder="-- Paste your Lua script here"></textarea>
        <div id="scriptStatus" class="text-xs opacity-50 mt-2"></div>
      </div>
    </div>
  </div>

  <div id="tab-service" class="tab-content">
    <div class="card bg-base-100 shadow-sm">
      <div class="card-body">
        <h2 class="card-title text-lg">Service Status</h2>
        <div class="mt-3 space-y-3">
          <div class="flex items-center gap-3">
            <span id="svc-dot" class="w-2.5 h-2.5 rounded-full dot-off"></span>
            <span id="svc-text" class="text-sm">Checking...</span>
          </div>
          <div class="text-xs opacity-50">Uptime: <span id="svc-uptime">–</span></div>
        </div>
      </div>
    </div>
  </div>

  <div id="tab-integration" class="tab-content">
    <div class="card bg-base-100 shadow-sm">
      <div class="card-body items-center text-center py-16">
        <h2 class="text-xl font-semibold opacity-60">Nothing here yet</h2>
        <p class="text-sm opacity-40 mt-2">Discord bot, webhooks, Stripe — add later.</p>
      </div>
    </div>
  </div>
</div>

<div id="ctx" class="ctx hidden"></div>

<script>
var currentKeys = [];
var currentTab = "overview";

function switchTab(name) {
  currentTab = name;
  document.querySelectorAll(".tab-content").forEach(function(el) {
    el.classList.toggle("active", el.id === "tab-" + name);
  });
  document.querySelectorAll(".tab").forEach(function(el) {
    el.classList.toggle("tab-active", el.dataset.tab === name);
  });
  if (name === "overview") loadStats();
  if (name === "keys") loadKeys();
  if (name === "script") loadScript();
  if (name === "service") loadService();
}

document.querySelectorAll(".tab").forEach(function(el) {
  el.addEventListener("click", function() { switchTab(el.dataset.tab); });
});

async function loadStats() {
  try {
    var res = await fetch("/api/stats");
    var s = await res.json();
    document.getElementById("stat-total").textContent = s.total;
    document.getElementById("stat-online").textContent = s.online;
    document.getElementById("stat-banned").textContent = s.banned;
  } catch (e) {}
}

async function loadKeys() {
  try {
    var res = await fetch("/api/keys");
    currentKeys = await res.json();
    var list = document.getElementById("keyList");
    if (!currentKeys.length) {
      list.innerHTML = '<div class="text-center opacity-40 py-16 text-sm">No keys yet. Generate one.</div>';
      return;
    }
    var now = Date.now();
    list.innerHTML = currentKeys.map(function(k) {
      var online = k.last_seen && (now - new Date(k.last_seen).getTime()) < 6000;
      var cls = online ? "dot-on" : "dot-off";
      var label = online ? "online" : "offline";
      return '<div class="key-row flex items-center gap-3 bg-base-100 rounded-lg px-4 py-3" data-id="' + k.id + '" data-online="' + online + '">' +
        '<span class="w-2 h-2 rounded-full ' + cls + '"></span>' +
        '<code class="flex-1 text-sm font-mono truncate">' + k.key_value + '</code>' +
        '<span class="text-xs opacity-40">' + label + '</span>' +
      '</div>';
    }).join("");
  } catch (e) {}
}

function showCtx(e, id, online) {
  e.preventDefault();
  var ctx = document.getElementById("ctx");
  ctx.innerHTML =
    '<button data-act="copy" data-id="' + id + '">Copy key</button>' +
    '<button data-act="delete" data-id="' + id + '">Delete key</button>' +
    '<button class="danger" data-act="kick" data-id="' + id + '"' + (online ? "" : ' disabled style="opacity:0.4"') + '>Kick from game</button>';
  ctx.style.left = Math.min(e.pageX, window.innerWidth - 180) + "px";
  ctx.style.top = Math.min(e.pageY, window.innerHeight - 130) + "px";
  ctx.classList.remove("hidden");
}

document.getElementById("keyList").addEventListener("contextmenu", function(e) {
  var row = e.target.closest(".key-row");
  if (!row) return;
  showCtx(e, parseInt(row.dataset.id), row.dataset.online === "true");
});

document.getElementById("ctx").addEventListener("click", async function(e) {
  var btn = e.target.closest("button");
  if (!btn || btn.disabled) return;
  var id = parseInt(btn.dataset.id);
  var act = btn.dataset.act;
  document.getElementById("ctx").classList.add("hidden");
  if (act === "copy") {
    var k = currentKeys.find(function(x) { return x.id === id; });
    if (k) await navigator.clipboard.writeText(k.key_value);
  } else if (act === "delete") {
    if (!confirm("Delete this key?")) return;
    await fetch("/api/keys/" + id, {method: "DELETE"});
    loadKeys();
  } else if (act === "kick") {
    if (!confirm("Kick this user?")) return;
    await fetch("/api/keys/" + id + "/kick", {method: "POST"});
    loadKeys();
  }
});

document.addEventListener("click", function() {
  document.getElementById("ctx").classList.add("hidden");
});

document.getElementById("genBtn").addEventListener("click", async function() {
  var btn = document.getElementById("genBtn");
  btn.disabled = true;
  btn.textContent = "Generating...";
  await fetch("/api/keys", {method: "POST"});
  btn.disabled = false;
  btn.textContent = "Generate Key";
  loadKeys();
});

async function loadScript() {
  try {
    var res = await fetch("/api/script");
    var data = await res.json();
    document.getElementById("scriptBox").value = data.content || "";
    if (data.updated_at) {
      document.getElementById("scriptStatus").textContent = "Last saved: " + new Date(data.updated_at).toLocaleString();
    } else {
      document.getElementById("scriptStatus").textContent = "";
    }
  } catch (e) {}
}

document.getElementById("saveBtn").addEventListener("click", async function() {
  var btn = document.getElementById("saveBtn");
  btn.disabled = true;
  btn.textContent = "Saving...";
  var content = document.getElementById("scriptBox").value;
  await fetch("/api/script", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({content: content})
  });
  btn.disabled = false;
  btn.textContent = "Save";
  loadScript();
});

async function loadService() {
  try {
    var res = await fetch("/api/health");
    var h = await res.json();
    var dot = document.getElementById("svc-dot");
    var txt = document.getElementById("svc-text");
    if (h.status === "ok") {
      dot.className = "w-2.5 h-2.5 rounded-full dot-on";
      txt.textContent = "All systems operational";
    } else {
      dot.className = "w-2.5 h-2.5 rounded-full dot-off";
      txt.textContent = "Degraded";
    }
    document.getElementById("svc-uptime").textContent = Math.floor(h.uptime) + "s";
  } catch (e) {
    document.getElementById("svc-dot").className = "w-2.5 h-2.5 rounded-full dot-off";
    document.getElementById("svc-text").textContent = "Unreachable";
  }
}

setInterval(function() {
  if (currentTab === "keys") loadKeys();
  if (currentTab === "overview") loadStats();
  if (currentTab === "service") loadService();
}, 3000);

switchTab("overview");
</script>
</body>
</html>
"""

START_TIME = datetime.utcnow()

class ScriptBody(BaseModel):
    content: str

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD

@app.get("/api/stats")
def stats(db=Depends(get_db)):
    now = datetime.utcnow()
    total = db.query(Key).count()
    banned = db.query(Key).filter(Key.banned == True).count()
    online = 0
    for k in db.query(Key).all():
        if k.last_seen and (now - k.last_seen).total_seconds() < ONLINE_SECONDS:
            online += 1
    return {"total": total, "online": online, "banned": banned}

@app.get("/api/keys")
def list_keys(db=Depends(get_db)):
    return [
        {
            "id": k.id,
            "key_value": k.key_value,
            "last_seen": k.last_seen.isoformat() if k.last_seen else None,
            "kick": k.kick,
        }
        for k in db.query(Key).order_by(Key.id.desc()).all()
    ]

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

@app.get("/api/script")
def get_script(db=Depends(get_db)):
    s = db.query(Script).first()
    if not s:
        return {"content": "", "updated_at": None}
    return {"content": s.content, "updated_at": s.updated_at.isoformat() if s.updated_at else None}

@app.post("/api/script")
def save_script(body: ScriptBody, db=Depends(get_db)):
    s = db.query(Script).first()
    if not s:
        s = Script(content=body.content)
        db.add(s)
    else:
        s.content = body.content
        s.updated_at = datetime.utcnow()
    db.commit()
    return {"success": True}

@app.get("/api/health")
def health(db=Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    uptime = (datetime.utcnow() - START_TIME).total_seconds()
    return {"status": "ok" if db_ok else "degraded", "db": db_ok, "uptime": uptime}

@app.get("/validate", response_class=PlainTextResponse)
def validate(key: str, db=Depends(get_db)):
    k = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
    if not k:
        return "invalid"
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
    s = db.query(Script).first()
    if not s:
        return ""
    return s.content

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
