from fastapi import FastAPI, HTTPException, Request, Depends, Form
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

# ====================== MODELS ======================
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
    project_id = Column(Integer, ForeignKey("projects.id"))
    key_value = Column(String(64), unique=True, nullable=False)
    hwid = Column(String(256), nullable=True)
    expires_at = Column(DateTime, nullable=True)
    banned = Column(Boolean, default=False)
    last_heartbeat = Column(DateTime, nullable=True)
    project = relationship("Project", back_populates="keys")

class Script(Base):
    __tablename__ = "scripts"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
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

# ====================== TABBED DASHBOARD ======================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <title>Authy Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.12.10/dist/full.min.css" rel="stylesheet">
</head>
<body class="bg-base-300 min-h-screen">
    <div class="navbar bg-base-100 shadow-xl">
        <div class="flex-1"><a href="/dashboard" class="btn btn-ghost text-3xl font-bold">🔐 Authy</a></div>
    </div>

    <div class="max-w-6xl mx-auto p-8">
        <h1 class="text-5xl font-bold text-center mb-8">Authy Control Panel</h1>

        <!-- Tabs -->
        <div class="tabs tabs-boxed justify-center mb-8">
            <a href="#overview" class="tab tab-active" onclick="switchTab(0)">Overview</a>
            <a href="#projects" class="tab" onclick="switchTab(1)">Projects & Keys</a>
            <a href="#hosting" class="tab" onclick="switchTab(2)">Hosting Files</a>
            <a href="#settings" class="tab" onclick="switchTab(3)">Settings</a>
        </div>

        <!-- Tab Contents -->
        <div id="tab0" class="tab-content">
            <div class="card bg-base-100 shadow-2xl p-8 text-center">
                <h2 class="text-3xl mb-4">Welcome to Authy</h2>
                <p class="opacity-70">Create projects, generate keys, upload scripts, and manage your loaders.</p>
                <button onclick="window.location.reload()" class="btn btn-primary mt-6">Refresh Dashboard</button>
            </div>
        </div>

        <div id="tab1" class="tab-content hidden">
            <!-- Create Project -->
            <div class="card bg-base-100 shadow-2xl mb-8">
                <div class="card-body">
                    <h2 class="card-title">Create New Project</h2>
                    <div class="flex gap-3">
                        <input id="projName" type="text" placeholder="e.g. SilentAim v2" class="input input-bordered flex-1" />
                        <button onclick="createProject()" class="btn btn-success">Create</button>
                    </div>
                </div>
            </div>
            <div id="projectsDiv" class="card bg-base-100 shadow-2xl"></div>
        </div>

        <div id="tab2" class="tab-content hidden">
            <div class="card bg-base-100 shadow-2xl">
                <div class="card-body">
                    <h2 class="card-title">Upload Script (Hosting)</h2>
                    <select id="projectSelect" class="select select-bordered w-full mb-4"></select>
                    <input id="scriptName" type="text" placeholder="Script name (e.g. main.lua)" class="input input-bordered w-full mb-4" />
                    <textarea id="scriptContent" placeholder="Paste your Lua script here..." class="textarea textarea-bordered w-full h-64"></textarea>
                    <button onclick="uploadScript()" class="btn btn-primary mt-4 w-full">Upload Script</button>
                </div>
            </div>
        </div>

        <div id="tab3" class="tab-content hidden">
            <div class="card bg-base-100 shadow-2xl p-8">
                <h2 class="card-title mb-4">Settings</h2>
                <button onclick="recreateDB()" class="btn btn-error">Reset Database (Dev Only)</button>
                <p class="text-xs opacity-60 mt-4">This will drop and recreate all tables.</p>
            </div>
        </div>

        <!-- Loader (always visible) -->
        <div class="card bg-base-100 shadow-2xl mt-12">
            <div class="card-body">
                <h2 class="card-title">🚀 Public Loader</h2>
                <pre id="loaderCode" class="mockup-code bg-base-200 p-6 text-sm overflow-auto max-h-96 whitespace-pre-wrap font-mono"></pre>
                <button onclick="copyLoader()" class="btn btn-primary btn-block mt-6">Copy Loader</button>
            </div>
        </div>
    </div>

    <script>
        const DOMAIN = "https://authy-o0pm.onrender.com";

        function switchTab(n) {
            document.querySelectorAll('.tab-content').forEach((el, i) => {
                el.classList.toggle('hidden', i !== n);
            });
            document.querySelectorAll('.tab').forEach((el, i) => {
                el.classList.toggle('tab-active', i === n);
            });
            if (n === 1) loadProjects();
            if (n === 2) loadProjectsForSelect();
        }

        async function createProject() {
            const name = document.getElementById("projName").value.trim();
            if (!name) return alert("Enter project name");
            try {
                const res = await fetch("/api/project", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({name})});
                if (!res.ok) throw new Error(await res.text());
                alert("Project created!");
                loadProjects();
            } catch(e) { alert("Error: " + e.message); }
        }

        async function generateKey(projectId) {
            try {
                const res = await fetch(`/api/key?project_id=${projectId}`, {method: "POST"});
                if (!res.ok) throw new Error(await res.text());
                const data = await res.json();
                alert(`✅ Key: ${data.key}`);
                loadProjects();
            } catch(e) { alert("Generate key failed: " + e.message); }
        }

        async function loadProjects() {
            const res = await fetch("/api/projects");
            const projects = await res.json();
            let html = `<div class="card-body"><h2 class="card-title">Projects & Keys</h2>`;
            projects.forEach(p => {
                html += `<div class="p-4 border-b flex justify-between"><span>${p.name}</span><button onclick="generateKey(${p.id})" class="btn btn-sm btn-primary">Generate Key</button></div>`;
            });
            html += `</div>`;
            document.getElementById("projectsDiv").innerHTML = html;
        }

        async function loadProjectsForSelect() {
            const res = await fetch("/api/projects");
            const projects = await res.json();
            let html = `<option value="">Select Project</option>`;
            projects.forEach(p => html += `<option value="${p.id}">${p.name}</option>`);
            document.getElementById("projectSelect").innerHTML = html;
        }

        async function uploadScript() {
            const projectId = document.getElementById("projectSelect").value;
            const name = document.getElementById("scriptName").value.trim();
            const content = document.getElementById("scriptContent").value.trim();
            if (!projectId || !name || !content) return alert("Fill all fields");
            try {
                const res = await fetch("/api/script", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({project_id: parseInt(projectId), name, content})
                });
                if (!res.ok) throw new Error(await res.text());
                alert("Script uploaded successfully!");
            } catch(e) { alert("Upload failed: " + e.message); }
        }

        async function recreateDB() {
            if (!confirm("This will DELETE ALL data. Continue?")) return;
            try {
                const res = await fetch("/recreate-db");
                alert(await res.text());
                window.location.reload();
            } catch(e) { alert("Reset failed"); }
        }

        function copyLoader() {
            navigator.clipboard.writeText(document.getElementById("loaderCode").textContent);
            alert("✅ Loader copied!");
        }

        // Load loader code
        const loader = `script_key = ""  -- <<< PUT YOUR KEY HERE

-- Do not save this file
-- Always use the loadstring

local function gethwid()
    return game:GetService("RbxAnalyticsService"):GetClientId() .. "_" .. tostring(tick())
end

local key = script_key or ""
if key == "" then error("Authy: script_key is empty") end

local hwid = gethwid()
local resp = game:HttpGet("${DOMAIN}/validate?key=" .. key .. "&hwid=" .. game:HttpService:UrlEncode(hwid))

if resp and resp:find('"success":true') then
    local data = game:HttpService:JSONDecode(resp)
    local scriptUrl = data.script_url

    pcall(makefolder, "authy_cache")
    local oldFiles = listfiles("authy_cache")
    for _, f in pairs(oldFiles) do pcall(delfile, f) end

    local payload = game:HttpGet(scriptUrl)
    pcall(writefile, "authy_cache/init.lua", payload)

    spawn(function()
        while wait(60) do
            game:HttpGet("${DOMAIN}/heartbeat?key=" .. key)
        end
    end)

    return loadstring(payload)()
else
    error("Authy: Invalid key or server error")
end`;

        document.getElementById("loaderCode").textContent = loader;

        // Default tab
        switchTab(1);
    </script>
</body>
</html>
"""

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)

# ====================== API ======================
class ProjectCreate(BaseModel):
    name: str

@app.post("/api/project")
async def api_create_project(data: ProjectCreate, db=Depends(get_db)):
    if db.query(Project).filter(Project.name == data.name).first():
        raise HTTPException(400, "Project already exists")
    proj = Project(name=data.name)
    db.add(proj)
    db.commit()
    return {"success": True}

@app.get("/api/projects")
async def api_get_projects(db=Depends(get_db)):
    projects = db.query(Project).all()
    return [{"id": p.id, "name": p.name} for p in projects]

@app.post("/api/key")
async def api_generate_key(project_id: int, db=Depends(get_db)):
    proj = db.query(Project).get(project_id)
    if not proj:
        raise HTTPException(404, "Project not found")
    new_key = secrets.token_hex(32)
    key_obj = Key(project_id=project_id, key_value=new_key)
    db.add(key_obj)
    db.commit()
    return {"key": new_key}

class ScriptUpload(BaseModel):
    project_id: int
    name: str
    content: str

@app.post("/api/script")
async def api_upload_script(data: ScriptUpload, db=Depends(get_db)):
    proj = db.query(Project).get(data.project_id)
    if not proj:
        raise HTTPException(404, "Project not found")
    script = Script(project_id=data.project_id, name=data.name, content=data.content)
    db.add(script)
    db.commit()
    return {"success": True}

@app.get("/validate")
async def validate(key: str, hwid: str, db=Depends(get_db)):
    key_obj = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
    if not key_obj:
        raise HTTPException(401, "Invalid key")

    project = db.query(Project).get(key_obj.project_id)
    if not project or project.killswitch:
        raise HTTPException(403, "Access denied")

    if key_obj.expires_at and key_obj.expires_at < datetime.utcnow():
        raise HTTPException(403, "Key expired")

    key_obj.last_heartbeat = datetime.utcnow()
    if not key_obj.hwid:
        key_obj.hwid = hwid
    db.commit()

    script_url = f"https://authy-o0pm.onrender.com/raw/{project.name.lower()}/main.lua"
    return {"success": True, "script_url": script_url}

@app.get("/heartbeat")
async def heartbeat(key: str, db=Depends(get_db)):
    key_obj = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
    if not key_obj:
        return {"action": "kick"}
    key_obj.last_heartbeat = datetime.utcnow()
    db.commit()
    return {"action": "continue"}

# HTML Trap for scripts
@app.get("/raw/{project}/{filename}")
async def raw_script(request: Request, project: str, filename: str):
    ua = request.headers.get("user-agent", "").lower()
    if "roblox" in ua:
        # In production, fetch real script from DB by project name
        return PlainTextResponse("-- Authy protected script loaded\nprint('Welcome from project: " + project + "')")
    return HTMLResponse("<h1 style='color:#ff4444;text-align:center;padding:120px;font-family:monospace;'>403 - No access tardball</h1>", status_code=403)

# DB Reset (for fixing column issues)
@app.get("/recreate-db")
async def recreate_db(db=Depends(get_db)):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    return "Database reset successfully. All tables recreated."

@app.get("/")
async def root():
    return RedirectResponse("/dashboard")
