from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func
from pydantic import BaseModel
from datetime import datetime
import os
import secrets

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://neondb_owner:npg_S7hoDMeaw2cQ@ep-wandering-dream-ah21egpt-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI(title="Authy")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Models
class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    killswitch = Column(Boolean, default=False)
    created_at = Column(DateTime, default=func.now())

    keys = relationship("Key", back_populates="project")
    scripts = relationship("Script", back_populates="project")

class Key(Base):
    __tablename__ = "keys"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"))
    key_value = Column(String(64), unique=True, nullable=False)
    hwid = Column(String(256), nullable=True)
    expires_at = Column(DateTime, nullable=True)
    banned = Column(Boolean, default=False)
    last_heartbeat = Column(DateTime, nullable=True)
    project = relationship("Project", back_populates="keys")

class Script(Base):
    __tablename__ = "scripts"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"))
    name = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    project = relationship("Project", back_populates="scripts")

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ====================== SIMPLE & RELIABLE DASHBOARD ======================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <title>Authy Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.12.10/dist/full.min.css" rel="stylesheet">
    <style>
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
</head>
<body class="bg-base-300 min-h-screen">
    <div class="navbar bg-base-100 shadow-xl">
        <div class="flex-1 px-4">
            <a href="/dashboard" class="btn btn-ghost text-3xl font-bold">🔐 Authy</a>
        </div>
    </div>

    <div class="max-w-6xl mx-auto p-6">
        <h1 class="text-5xl font-bold text-center mb-10">Authy Control Panel</h1>

        <!-- Tabs -->
        <div class="flex justify-center mb-10 bg-base-100 p-2 rounded-box shadow">
            <button onclick="switchTab(0)" id="tab0" class="tab tab-active px-8 py-3 font-medium">Overview</button>
            <button onclick="switchTab(1)" id="tab1" class="tab px-8 py-3 font-medium">Projects & Keys</button>
            <button onclick="switchTab(2)" id="tab2" class="tab px-8 py-3 font-medium">Host Scripts</button>
        </div>

        <!-- Tab 0: Overview -->
        <div id="content0" class="tab-content active">
            <div class="card bg-base-100 shadow-2xl p-16 text-center">
                <h2 class="text-4xl mb-4">Welcome to Authy</h2>
                <p class="text-lg opacity-70">Create a project, generate keys, upload your Lua scripts, and copy the loader.</p>
            </div>
        </div>

        <!-- Tab 1: Projects & Keys -->
        <div id="content1" class="tab-content">
            <div class="card bg-base-100 shadow-2xl mb-8">
                <div class="card-body">
                    <h2 class="card-title">Create New Project</h2>
                    <div class="flex gap-3">
                        <input id="projName" type="text" placeholder="e.g. SilentAim v2" class="input input-bordered flex-1">
                        <button onclick="createProject()" class="btn btn-success">Create</button>
                    </div>
                </div>
            </div>
            <div id="projectsList" class="card bg-base-100 shadow-2xl"></div>
        </div>

        <!-- Tab 2: Host Scripts -->
        <div id="content2" class="tab-content">
            <div class="card bg-base-100 shadow-2xl">
                <div class="card-body">
                    <h2 class="card-title">Upload Lua Script</h2>
                    <select id="projSelect" class="select select-bordered w-full mb-4"></select>
                    <input id="scriptName" type="text" placeholder="Filename (e.g. main.lua)" class="input input-bordered w-full mb-4">
                    <textarea id="scriptContent" class="textarea textarea-bordered w-full h-64 font-mono" placeholder="Paste your full Lua script here..."></textarea>
                    <button onclick="uploadScript()" class="btn btn-primary w-full mt-6">Upload Script</button>
                </div>
            </div>
        </div>

        <!-- Loader -->
        <div class="card bg-base-100 shadow-2xl mt-12">
            <div class="card-body">
                <h2 class="card-title">🚀 Public Loader - Copy this</h2>
                <pre id="loaderPre" class="mockup-code bg-base-200 p-6 text-sm overflow-auto max-h-96 font-mono"></pre>
                <button onclick="copyLoader()" class="btn btn-primary btn-block mt-6">Copy Loader</button>
            </div>
        </div>
    </div>

    <script>
        function switchTab(n) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.getElementById('content' + n).classList.add('active');

            document.querySelectorAll('.tab').forEach((el, i) => {
                if (i === n) el.classList.add('tab-active');
                else el.classList.remove('tab-active');
            });

            if (n === 1) loadProjects();
            if (n === 2) loadProjectsForSelect();
        }

        async function createProject() {
            const name = document.getElementById("projName").value.trim();
            if (!name) return alert("Enter project name");
            try {
                const res = await fetch("/api/project", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({name})
                });
                if (res.ok) {
                    alert("Project created!");
                    loadProjects();
                } else {
                    alert("Error: " + await res.text());
                }
            } catch(e) { alert("Request failed"); }
        }

        async function generateKey(pid) {
            try {
                const res = await fetch(`/api/key?project_id=${pid}`, { method: "POST" });
                if (res.ok) {
                    const data = await res.json();
                    alert(`✅ New Key:\n${data.key}`);
                    loadProjects();
                } else {
                    alert("Generate key failed: " + await res.text());
                }
            } catch(e) { alert("Error: " + e.message); }
        }

        async function loadProjects() {
            try {
                const res = await fetch("/api/projects");
                const projects = await res.json();
                let html = `<div class="card-body"><h2 class="card-title">Your Projects</h2>`;
                projects.forEach(p => {
                    html += `
                        <div class="flex justify-between p-4 border-b">
                            <span class="font-medium">${p.name}</span>
                            <button onclick="generateKey(${p.id})" class="btn btn-sm btn-primary">Generate Key</button>
                        </div>`;
                });
                html += `</div>`;
                document.getElementById("projectsList").innerHTML = html;
            } catch(e) { console.error(e); }
        }

        async function loadProjectsForSelect() {
            try {
                const res = await fetch("/api/projects");
                const projects = await res.json();
                let html = `<option value="">-- Select Project --</option>`;
                projects.forEach(p => html += `<option value="${p.id}">${p.name}</option>`);
                document.getElementById("projSelect").innerHTML = html;
            } catch(e) { console.error(e); }
        }

        async function uploadScript() {
            const pid = document.getElementById("projSelect").value;
            const name = document.getElementById("scriptName").value.trim();
            const content = document.getElementById("scriptContent").value.trim();
            if (!pid || !name || !content) return alert("Please fill all fields");
            try {
                const res = await fetch("/api/script", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({project_id: parseInt(pid), name, content})
                });
                if (res.ok) alert("Script uploaded successfully!");
                else alert("Upload failed: " + await res.text());
            } catch(e) { alert("Request failed"); }
        }

        function copyLoader() {
            navigator.clipboard.writeText(document.getElementById("loaderPre").textContent);
            alert("✅ Loader copied to clipboard!");
        }

        // Loader Code
        document.getElementById("loaderPre").textContent = `script_key = ""  -- <<< PUT YOUR KEY HERE

-- Do not save this file
-- Always use the loadstring

local function gethwid()
    return game:GetService("RbxAnalyticsService"):GetClientId() .. "_" .. tostring(tick())
end

local key = script_key or ""
if key == "" then error("Authy: Put your key in script_key = \"\"") end

local resp = game:HttpGet("https://authy-o0pm.onrender.com/validate?key=" .. key .. "&hwid=" .. game:HttpService:UrlEncode(gethwid()))

if resp and resp:find('"success":true') then
    local data = game:HttpService:JSONDecode(resp)
    local payload = game:HttpGet(data.script_url)
    return loadstring(payload)()
else
    error("Authy: Invalid key or server error")
end`;

        // Start on Projects tab
        switchTab(1);
    </script>
</body>
</html>
"""

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)

# API Routes
class ProjectCreate(BaseModel):
    name: str

@app.post("/api/project")
async def create_project(data: ProjectCreate, db=Depends(get_db)):
    if db.query(Project).filter(Project.name == data.name).first():
        raise HTTPException(400, "Project already exists")
    proj = Project(name=data.name)
    db.add(proj)
    db.commit()
    return {"success": True}

@app.get("/api/projects")
async def get_projects(db=Depends(get_db)):
    projects = db.query(Project).all()
    return [{"id": p.id, "name": p.name} for p in projects]

@app.post("/api/key")
async def generate_key(project_id: int, db=Depends(get_db)):
    proj = db.query(Project).get(project_id)
    if not proj:
        raise HTTPException(404, "Project not found")
    new_key = secrets.token_hex(32)
    key_obj = Key(project_id=project_id, key_value=new_key)
    db.add(key_obj)
    db.commit()
    return {"key": new_key}

class ScriptCreate(BaseModel):
    project_id: int
    name: str
    content: str

@app.post("/api/script")
async def upload_script(data: ScriptCreate, db=Depends(get_db)):
    if not db.query(Project).get(data.project_id):
        raise HTTPException(404, "Project not found")
    script = Script(project_id=data.project_id, name=data.name, content=data.content)
    db.add(script)
    db.commit()
    return {"success": True}

@app.get("/validate")
async def validate(key: str, hwid: str, db=Depends(get_db)):
    k = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
    if not k:
        raise HTTPException(401, "Invalid key")
    proj = db.query(Project).get(k.project_id)
    if not proj or proj.killswitch:
        raise HTTPException(403, "Access denied")
    k.last_heartbeat = datetime.utcnow()
    db.commit()
    return {"success": True, "script_url": f"https://authy-o0pm.onrender.com/raw/{proj.name.lower()}/main.lua"}

@app.get("/heartbeat")
async def heartbeat(key: str, db=Depends(get_db)):
    k = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
    if k:
        k.last_heartbeat = datetime.utcnow()
        db.commit()
    return {"action": "continue"}

@app.get("/raw/{project}/{filename}")
async def raw_script(request: Request, project: str, filename: str):
    if "roblox" in request.headers.get("user-agent", "").lower():
        return PlainTextResponse("-- Authy protected script loaded successfully")
    return HTMLResponse("<h1 style='color:#ff4444;text-align:center;padding:120px;'>403 - No access tardball</h1>", status_code=403)

@app.get("/")
async def root():
    return RedirectResponse("/dashboard")
