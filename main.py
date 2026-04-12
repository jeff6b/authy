from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, RedirectResponse
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

# ====================== DASHBOARD ======================
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
        <h1 class="text-5xl font-bold text-center mb-10">Authy Control Panel</h1>

        <!-- Create Project -->
        <div class="card bg-base-100 shadow-2xl mb-10">
            <div class="card-body">
                <h2 class="card-title">Create New Project</h2>
                <div class="flex gap-3">
                    <input id="projName" type="text" placeholder="e.g. SilentAim v2" class="input input-bordered flex-1" />
                    <button onclick="createProject()" class="btn btn-success">Create</button>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
            <div id="projectsDiv" class="card bg-base-100 shadow-2xl"></div>
            <div id="keysDiv" class="card bg-base-100 shadow-2xl"></div>
        </div>

        <!-- Loader -->
        <div class="card bg-base-100 shadow-2xl mt-10">
            <div class="card-body">
                <h2 class="card-title">🚀 Public Loader</h2>
                <pre id="loaderCode" class="mockup-code bg-base-200 p-6 text-sm overflow-auto max-h-96 whitespace-pre-wrap font-mono"></pre>
                <button onclick="copyLoader()" class="btn btn-primary btn-block mt-6">Copy Loader</button>
            </div>
        </div>
    </div>

    <script>
        const DOMAIN = "https://authy-o0pm.onrender.com";

        async function createProject() {
            const name = document.getElementById("projName").value.trim();
            if (!name) return alert("Enter project name");
            try {
                await fetch("/api/project", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({name})});
                alert("Project created!");
                loadDashboard();
            } catch(e) { alert("Error: " + e); }
        }

        async function generateKey(projectId) {
            try {
                const res = await fetch(`/api/key?project_id=${projectId}`, {method: "POST"});
                if (!res.ok) throw new Error("Server error");
                const data = await res.json();
                alert(`✅ Key generated: ${data.key}`);
                loadDashboard();
            } catch(e) { alert("Generate key failed: " + e.message); }
        }

        async function loadDashboard() {
            try {
                const res = await fetch("/api/projects");
                const projects = await res.json();
                
                let html = `<div class="card-body"><h2 class="card-title">Projects</h2>`;
                projects.forEach(p => {
                    html += `
                        <div class="p-4 border-b flex justify-between items-center">
                            <span>${p.name}</span>
                            <button onclick="generateKey(${p.id})" class="btn btn-sm btn-primary">Generate Key</button>
                        </div>`;
                });
                html += `</div>`;
                document.getElementById("projectsDiv").innerHTML = html;

                // Loader with script_key at top
                const loader = `script_key = ""  -- <<< PUT YOUR KEY HERE

-- Do not save this file
-- Always use the loadstring
-- Authy Smart Loader with good protection

local function gethwid()
    local cid = game:GetService("RbxAnalyticsService"):GetClientId()
    return cid .. "_" .. tostring(tick())
end

local key = script_key or ""
if key == "" then error("Authy: Put your key in script_key") end

local hwid = gethwid()

local resp = game:HttpGet("${DOMAIN}/validate?key=" .. key .. "&hwid=" .. game:HttpService:UrlEncode(hwid))

if resp and resp:find('"success":true') then
    local data = game:HttpService:JSONDecode(resp)
    local scriptUrl = data.script_url

    pcall(makefolder, "authy_cache")
    local payload = game:HttpGet(scriptUrl)
    pcall(writefile, "authy_cache/init.lua", payload)

    spawn(function()
        while wait(60) do
            game:HttpGet("${DOMAIN}/heartbeat?key=" .. key)
        end
    end)

    return loadstring(payload)()
else
    error("Authy: Invalid key, expired, or banned")
end`;

                document.getElementById("loaderCode").textContent = loader;
            } catch(e) {
                console.error(e);
            }
        }

        function copyLoader() {
            navigator.clipboard.writeText(document.getElementById("loaderCode").textContent);
            alert("✅ Loader copied! Put your key at the top.");
        }

        loadDashboard();
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

@app.get("/validate")
async def validate(key: str, hwid: str, db=Depends(get_db)):
    try:
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
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/heartbeat")
async def heartbeat(key: str, db=Depends(get_db)):
    key_obj = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
    if not key_obj:
        return {"action": "kick"}
    key_obj.last_heartbeat = datetime.utcnow()
    db.commit()
    return {"action": "continue"}

# Script hosting with HTML trap (basic upload not in UI yet — you can add later via DB or admin)
@app.get("/raw/{project}/{filename}")
async def raw_script(request: Request, project: str, filename: str):
    ua = request.headers.get("user-agent", "").lower()
    if "roblox" in ua:
        return PlainTextResponse("-- Authy protected script\nprint('Loaded from project: " + project + "')")
    return HTMLResponse(content="<h1 style='color:#ff4444;text-align:center;padding:120px;font-family:monospace;'>403 - No access tardball<br><br>Stop trying kid</h1>", status_code=403)

@app.get("/")
async def root():
    return RedirectResponse("/dashboard")
