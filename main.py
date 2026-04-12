from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func
from pydantic import BaseModel
from datetime import datetime
import os
import secrets

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://neondb_owner:npg_S7hoDMeaw2cQ@ep-wandering-dream-ah21egpt-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require")

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI(title="Authy", debug=True)  # debug=True helps show better errors

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Simple Models
class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    killswitch = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())

class Key(Base):
    __tablename__ = "keys"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    key_value = Column(String(64), unique=True, nullable=False)
    hwid = Column(String(256), nullable=True)
    expires_at = Column(DateTime, nullable=True)
    banned = Column(Boolean, default=False)
    last_heartbeat = Column(DateTime, nullable=True)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ====================== SIMPLE DASHBOARD ======================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <title>Authy</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.12.10/dist/full.min.css" rel="stylesheet">
    <style>
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .tab { cursor: pointer; padding: 12px 24px; }
        .tab-active { background-color: #4f46e5; color: white; border-radius: 8px; }
    </style>
</head>
<body class="bg-base-300">
    <div class="navbar bg-base-100 shadow">
        <div class="flex-1"><a href="/dashboard" class="btn btn-ghost text-3xl">🔐 Authy</a></div>
    </div>

    <div class="max-w-5xl mx-auto p-6">
        <h1 class="text-5xl font-bold text-center mb-8">Authy Control Panel</h1>

        <div class="flex gap-2 justify-center mb-10 bg-base-100 p-2 rounded-box">
            <div onclick="switchTab(0)" id="t0" class="tab tab-active">Overview</div>
            <div onclick="switchTab(1)" id="t1" class="tab">Projects & Keys</div>
            <div onclick="switchTab(2)" id="t2" class="tab">Host Script</div>
        </div>

        <!-- Overview -->
        <div id="c0" class="tab-content active card bg-base-100 shadow-xl p-12 text-center">
            <h2 class="text-4xl">Simple Authy Dashboard</h2>
            <p class="mt-4">Click tabs above. If you see errors, check Render Logs.</p>
        </div>

        <!-- Projects -->
        <div id="c1" class="tab-content card bg-base-100 shadow-xl">
            <div class="card-body">
                <input id="pname" placeholder="Project name" class="input input-bordered w-full mb-4">
                <button onclick="createProj()" class="btn btn-success w-full">Create Project</button>
            </div>
            <div id="projList" class="p-6"></div>
        </div>

        <!-- Host Script -->
        <div id="c2" class="tab-content card bg-base-100 shadow-xl">
            <div class="card-body">
                <select id="selProj" class="select select-bordered w-full mb-4"></select>
                <input id="sname" placeholder="main.lua" class="input input-bordered w-full mb-4">
                <textarea id="scode" class="textarea textarea-bordered w-full h-64" placeholder="Paste Lua code..."></textarea>
                <button onclick="upload()" class="btn btn-primary w-full mt-4">Upload Script</button>
            </div>
        </div>

        <!-- Loader -->
        <div class="card bg-base-100 shadow-xl mt-12">
            <div class="card-body">
                <h2 class="card-title">Public Loader</h2>
                <pre id="loader" class="mockup-code p-6 text-xs bg-base-300 overflow-auto max-h-96"></pre>
                <button onclick="copyL()" class="btn btn-primary w-full mt-4">Copy Loader</button>
            </div>
        </div>
    </div>

    <script>
        function switchTab(n) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.getElementById('c' + n).classList.add('active');
            document.querySelectorAll('.tab').forEach((el,i) => el.classList.toggle('tab-active', i===n));
            if (n===1) loadProjs();
            if (n===2) loadSelect();
        }

        async function createProj() {
            const name = document.getElementById("pname").value.trim();
            if (!name) return alert("Enter name");
            const r = await fetch("/api/project", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({name})});
            if (r.ok) { alert("Created"); loadProjs(); } 
            else alert("Error: " + await r.text());
        }

        async function genKey(id) {
            const r = await fetch(`/api/key?project_id=${id}`, {method:"POST"});
            if (r.ok) {
                const d = await r.json();
                alert("Key: " + d.key);
                loadProjs();
            } else alert("Error: " + await r.text());
        }

        async function loadProjs() {
            const r = await fetch("/api/projects");
            const ps = await r.json();
            let h = "";
            ps.forEach(p => h += `<div class="flex justify-between p-4 border-b"><span>${p.name}</span><button onclick="genKey(${p.id})" class="btn btn-sm btn-primary">Generate Key</button></div>`);
            document.getElementById("projList").innerHTML = h || "<p class='p-6'>No projects yet</p>";
        }

        async function loadSelect() {
            const r = await fetch("/api/projects");
            const ps = await r.json();
            let h = "<option value=''>Select project</option>";
            ps.forEach(p => h += `<option value="${p.id}">${p.name}</option>`);
            document.getElementById("selProj").innerHTML = h;
        }

        async function upload() {
            const pid = document.getElementById("selProj").value;
            const name = document.getElementById("sname").value.trim();
            const code = document.getElementById("scode").value.trim();
            if (!pid || !name || !code) return alert("Fill all");
            const r = await fetch("/api/script", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({project_id:parseInt(pid), name, content:code})});
            if (r.ok) alert("Script uploaded");
            else alert("Error: " + await r.text());
        }

        function copyL() {
            navigator.clipboard.writeText(document.getElementById("loader").textContent);
            alert("Copied!");
        }

        // Loader
        document.getElementById("loader").textContent = `script_key = ""  -- PUT YOUR KEY HERE

-- Do not save this file
-- Always use the loadstring

local key = script_key or ""
if key == "" then error("Put key") end

local resp = game:HttpGet("https://authy-o0pm.onrender.com/validate?key=" .. key)

if resp and resp:find('"success"') then
    local data = game:HttpService:JSONDecode(resp)
    return loadstring(game:HttpGet(data.script_url))()
else
    error("Auth failed")
end`;

        switchTab(1);  // start on projects tab
    </script>
</body>
</html>
"""

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)

# Simple API
class ProjectCreate(BaseModel):
    name: str

@app.post("/api/project")
async def create_project(data: ProjectCreate, db=Depends(get_db)):
    if db.query(Project).filter(Project.name == data.name).first():
        raise HTTPException(400, "Exists")
    p = Project(name=data.name)
    db.add(p)
    db.commit()
    return {"success": True}

@app.get("/api/projects")
async def get_projects(db=Depends(get_db)):
    return [{"id": p.id, "name": p.name} for p in db.query(Project).all()]

@app.post("/api/key")
async def generate_key(project_id: int, db=Depends(get_db)):
    if not db.query(Project).get(project_id):
        raise HTTPException(404, "Project not found")
    k = Key(project_id=project_id, key_value=secrets.token_hex(32))
    db.add(k)
    db.commit()
    return {"key": k.key_value}

class ScriptCreate(BaseModel):
    project_id: int
    name: str
    content: str

@app.post("/api/script")
async def upload_script(data: ScriptCreate, db=Depends(get_db)):
    if not db.query(Project).get(data.project_id):
        raise HTTPException(404, "Project not found")
    s = Script(project_id=data.project_id, name=data.name, content=data.content)
    db.add(s)
    db.commit()
    return {"success": True}

@app.get("/validate")
async def validate(key: str, db=Depends(get_db)):
    k = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
    if not k:
        raise HTTPException(401, "Invalid key")
    proj = db.query(Project).get(k.project_id)
    if not proj:
        raise HTTPException(403, "No project")
    return {"success": True, "script_url": f"https://authy-o0pm.onrender.com/raw/default/main.lua"}

@app.get("/raw/{project}/{filename}")
async def raw_script(request: Request, project: str, filename: str):
    if "roblox" in request.headers.get("user-agent", "").lower():
        return PlainTextResponse("-- Script loaded via Authy")
    return HTMLResponse("<h1>403 - No access tardball</h1>", status_code=403)

@app.get("/")
async def root():
    return RedirectResponse("/dashboard")
