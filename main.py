from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func, text
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

# Auto-fix missing column (safe, no data loss)
def fix_missing_column():
    try:
        inspector = inspect(engine)
        columns = [c['name'] for c in inspector.get_columns('keys')]
        if 'project_id' not in columns:
            with engine.connect() as conn:
                conn.execute(text("ALTER TABLE keys ADD COLUMN project_id INTEGER REFERENCES projects(id) ON DELETE CASCADE"))
                conn.commit()
            print("✅ Fixed missing project_id column")
    except:
        pass  # ignore if already fixed or other error

fix_missing_column()

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
        <h1 class="text-5xl font-bold text-center mb-8">Authy Control Panel</h1>

        <div class="tabs tabs-boxed bg-base-100 p-2 rounded-box mb-8">
            <a onclick="switchTab(0)" class="tab tab-active" id="btn0">Overview</a>
            <a onclick="switchTab(1)" class="tab" id="btn1">Projects & Keys</a>
            <a onclick="switchTab(2)" class="tab" id="btn2">Host Scripts</a>
        </div>

        <!-- Overview -->
        <div id="content0" class="tab-content">
            <div class="card bg-base-100 shadow-2xl p-12 text-center">
                <h2 class="text-4xl">Welcome to Authy</h2>
                <p class="mt-6 text-lg opacity-70">Create project → Generate key → Upload script → Use loader</p>
            </div>
        </div>

        <!-- Projects & Keys -->
        <div id="content1" class="tab-content hidden">
            <div class="card bg-base-100 shadow-2xl mb-8">
                <div class="card-body">
                    <input id="projName" placeholder="Project Name" class="input input-bordered w-full" />
                    <button onclick="createProject()" class="btn btn-success mt-4 w-full">Create Project</button>
                </div>
            </div>
            <div id="projectsList" class="card bg-base-100 shadow-2xl"></div>
        </div>

        <!-- Host Scripts -->
        <div id="content2" class="tab-content hidden">
            <div class="card bg-base-100 shadow-2xl">
                <div class="card-body">
                    <select id="projSelect" class="select select-bordered w-full mb-4"></select>
                    <input id="scriptName" placeholder="Script name (main.lua)" class="input input-bordered w-full mb-4" />
                    <textarea id="scriptContent" class="textarea textarea-bordered w-full h-64 font-mono" placeholder="Paste your Lua script..."></textarea>
                    <button onclick="uploadScript()" class="btn btn-primary w-full mt-6">Upload Script</button>
                </div>
            </div>
        </div>

        <!-- Loader -->
        <div class="card bg-base-100 shadow-2xl mt-12">
            <div class="card-body">
                <h2 class="card-title">🚀 Public Loader</h2>
                <pre id="loaderPre" class="mockup-code bg-base-200 p-6 text-sm overflow-auto max-h-96 font-mono"></pre>
                <button onclick="copyLoader()" class="btn btn-primary w-full mt-6">Copy Loader</button>
            </div>
        </div>
    </div>

    <script>
        function switchTab(n) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            document.getElementById('content' + n).classList.remove('hidden');
            document.querySelectorAll('.tab').forEach((el, i) => el.classList.toggle('tab-active', i === n));
            if (n === 1) loadProjects();
            if (n === 2) loadProjectsForSelect();
        }

        async function createProject() {
            const name = document.getElementById("projName").value.trim();
            if (!name) return alert("Enter project name");
            try {
                const res = await fetch("/api/project", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({name})});
                if (res.ok) {
                    alert("Project created!");
                    loadProjects();
                } else alert("Error: " + await res.text());
            } catch(e) { alert("Failed: " + e); }
        }

        async function generateKey(pid) {
            try {
                const res = await fetch(`/api/key?project_id=${pid}`, {method: "POST"});
                if (res.ok) {
                    const data = await res.json();
                    alert(`✅ Key: ${data.key}`);
                    loadProjects();
                } else {
                    alert("Generate failed: " + await res.text());
                }
            } catch(e) { alert("Error: " + e); }
        }

        async function loadProjects() {
            const res = await fetch("/api/projects");
            const data = await res.json();
            let html = `<div class="card-body"><h2 class="card-title">Projects</h2>`;
            data.forEach(p => {
                html += `<div class="p-4 border-b flex justify-between items-center"><span>${p.name}</span><button onclick="generateKey(${p.id})" class="btn btn-sm btn-primary">Generate Key</button></div>`;
            });
            html += `</div>`;
            document.getElementById("projectsList").innerHTML = html;
        }

        async function loadProjectsForSelect() {
            const res = await fetch("/api/projects");
            const data = await res.json();
            let html = `<option value="">Select Project</option>`;
            data.forEach(p => html += `<option value="${p.id}">${p.name}</option>`);
            document.getElementById("projSelect").innerHTML = html;
        }

        async function uploadScript() {
            const pid = document.getElementById("projSelect").value;
            const name = document.getElementById("scriptName").value.trim();
            const content = document.getElementById("scriptContent").value.trim();
            if (!pid || !name || !content) return alert("Fill all fields");
            try {
                const res = await fetch("/api/script", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({project_id: parseInt(pid), name, content})});
                if (res.ok) alert("Script uploaded!");
                else alert("Upload error: " + await res.text());
            } catch(e) { alert("Failed: " + e); }
        }

        function copyLoader() {
            navigator.clipboard.writeText(document.getElementById("loaderPre").textContent);
            alert("✅ Loader copied!");
        }

        // Loader
        document.getElementById("loaderPre").textContent = `script_key = ""  -- <<< PUT YOUR KEY HERE

-- Do not save this file
-- Always use the loadstring

local function gethwid()
    return game:GetService("RbxAnalyticsService"):GetClientId() .. "_" .. tostring(tick())
end

local key = script_key or ""
if key == "" then error("Authy: Put your key in script_key") end

local resp = game:HttpGet("https://authy-o0pm.onrender.com/validate?key=" .. key .. "&hwid=" .. game:HttpService:UrlEncode(gethwid()))

if resp and resp:find('"success":true') then
    local data = game:HttpService:JSONDecode(resp)
    local payload = game:HttpGet(data.script_url)
    return loadstring(payload)()
else
    error("Authy: Key invalid or server error")
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

# ====================== API ======================
class ProjectCreate(BaseModel):
    name: str

@app.post("/api/project")
async def create_project(data: ProjectCreate, db=Depends(get_db)):
    if db.query(Project).filter(Project.name == data.name).first():
        raise HTTPException(400, "Project already exists")
    p = Project(name=data.name)
    db.add(p)
    db.commit()
    return {"success": True}

@app.get("/api/projects")
async def get_projects(db=Depends(get_db)):
    return [{"id": p.id, "name": p.name} for p in db.query(Project).all()]

@app.post("/api/key")
async def generate_key(project_id: int, db=Depends(get_db)):
    try:
        if not db.query(Project).get(project_id):
            raise HTTPException(404, "Project not found")
        new_key = secrets.token_hex(32)
        k = Key(project_id=project_id, key_value=new_key)
        db.add(k)
        db.commit()
        return {"key": new_key}
    except Exception as e:
        raise HTTPException(500, f"Error: {str(e)}")

class ScriptCreate(BaseModel):
    project_id: int
    name: str
    content: str

@app.post("/api/script")
async def upload_script(data: ScriptCreate, db=Depends(get_db)):
    if not db.query(Project).get(data.project_id):
        raise HTTPException(404, "Project not found")
    s = Script(**data.dict())
    db.add(s)
    db.commit()
    return {"success": True}

@app.get("/validate")
async def validate(key: str, hwid: str, db=Depends(get_db)):
    k = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
    if not k: raise HTTPException(401, "Invalid key")
    proj = db.query(Project).get(k.project_id)
    if not proj or proj.killswitch: raise HTTPException(403, "Access denied")
    k.last_heartbeat = datetime.utcnow()
    db.commit()
    return {"success": True, "script_url": f"https://authy-o0pm.onrender.com/raw/{proj.name.lower()}/main.lua"}

@app.get("/heartbeat")
async def heartbeat(key: str, db=Depends(get_db)):
    k = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
    if k:
        k.last_heartbeat = datetime.utcnow()
        db.commit()
    return {"action": "continue" if k else "kick"}

@app.get("/raw/{project}/{filename}")
async def raw_script(request: Request, project: str, filename: str):
    if "roblox" in request.headers.get("user-agent", "").lower():
        return PlainTextResponse("-- Authy protected script loaded")
    return HTMLResponse("<h1>403 - No access tardball</h1>", status_code=403)

@app.get("/")
async def root():
    return RedirectResponse("/dashboard")
