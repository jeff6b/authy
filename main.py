from fastapi import FastAPI, HTTPException, Request, Depends, Form
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse, RedirectResponse
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

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ====================== BEAUTIFUL DASHBOARD ======================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <title>Authy Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.12.10/dist/full.min.css" rel="stylesheet">
    <script>tailwind.config = {content: ["*"]}</script>
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
                <h2 class="card-title text-2xl">Create New Project</h2>
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

        <!-- Loader Section -->
        <div class="card bg-base-100 shadow-2xl mt-10">
            <div class="card-body">
                <h2 class="card-title">🚀 Public Loader (Copy & Give to Users)</h2>
                <pre id="loaderCode" class="mockup-code bg-base-200 p-6 text-sm overflow-auto max-h-96 whitespace-pre-wrap"></pre>
                <button onclick="copyLoader()" class="btn btn-primary btn-block mt-6 text-lg">Copy Loader to Clipboard</button>
            </div>
        </div>
    </div>

    <script>
        const DOMAIN = "https://authy-o0pm.onrender.com";

        async function createProject() {
            const name = document.getElementById("projName").value.trim();
            if (!name) return alert("Please enter a project name");
            await fetch("/api/project", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({name: name})
            });
            alert("Project created!");
            loadDashboard();
        }

        async function generateKey(projectId) {
            const res = await fetch(`/api/key?project_id=${projectId}`, {method: "POST"});
            const data = await res.json();
            alert(`✅ New Key: ${data.key}\n\nSave this key!`);
            loadDashboard();
        }

        async function loadDashboard() {
            // Load projects
            const res = await fetch("/api/projects");
            const projects = await res.json();
            
            let projHTML = `<div class="card-body"><h2 class="card-title">Your Projects</h2>`;
            projects.forEach(p => {
                projHTML += `
                    <div class="flex justify-between items-center p-4 border-b last:border-none">
                        <span class="font-medium">${p.name}</span>
                        <button onclick="generateKey(${p.id})" class="btn btn-sm btn-primary">Generate Key</button>
                    </div>`;
            });
            projHTML += `</div>`;
            document.getElementById("projectsDiv").innerHTML = projHTML;

            // Smart Loader
            const loader = `-- Do not save this file
-- Always use the loadstring
-- Authy Smart Loader

local function gethwid()
    return game:GetService("RbxAnalyticsService"):GetClientId() .. "_" .. tostring(tick())
end

local key = script_key or "PUT_YOUR_KEY_HERE"
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
    error("Authy: Invalid / expired / banned key")
end`;

            document.getElementById("loaderCode").textContent = loader;
        }

        function copyLoader() {
            navigator.clipboard.writeText(document.getElementById("loaderCode").textContent);
            alert("✅ Loader copied! Paste it as loadstring.");
        }

        // Auto load
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
        raise HTTPException(400, "Project with this name already exists")
    proj = Project(name=data.name)
    db.add(proj)
    db.commit()
    return {"success": True, "id": proj.id}

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

    script_url = f"https://authy-o0pm.onrender.com/raw/{project.name.lower()}/script.lua"

    return {"success": True, "script_url": script_url, "project": project.name}

@app.get("/heartbeat")
async def heartbeat(key: str, db=Depends(get_db)):
    key_obj = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
    if not key_obj:
        return {"action": "kick"}
    key_obj.last_heartbeat = datetime.utcnow()
    db.commit()
    return {"action": "continue"}

# HTML Trap
@app.get("/raw/{project}/{filename}")
async def raw_script(request: Request, project: str, filename: str):
    ua = request.headers.get("user-agent", "").lower()
    if "roblox" in ua:
        return PlainTextResponse("-- Authy protected script loaded\nprint('Welcome to ' .. script_name or 'the script')")
    return HTMLResponse("<h1 style='color:#ff4444;text-align:center;padding:120px;font-family:monospace;'>403 - No access tardball<br><br>You shouldn't be here dumbass</h1>", status_code=403)

@app.get("/")
async def root():
    return RedirectResponse("/dashboard")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
