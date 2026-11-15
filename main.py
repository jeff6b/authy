from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func
from pydantic import BaseModel
from datetime import datetime
import os
import secrets

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

# Force SQLAlchemy to use psycopg (v3) instead of psycopg2
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
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

class Key(Base):
    __tablename__ = "keys"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    key_value = Column(String(64), unique=True, nullable=False)
    hwid = Column(String(256), nullable=True)
    expires_at = Column(DateTime, nullable=True)
    banned = Column(Boolean, default=False)
    last_heartbeat = Column(DateTime, nullable=True)

class Script(Base):
    __tablename__ = "scripts"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    name = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)

# Create tables only if they don't exist. Never drop.
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authy</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.12.10/dist/full.min.css" rel="stylesheet">
    <style>
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .tab { cursor: pointer; padding: 10px 20px; border-radius: 8px; font-weight: 500; }
        .tab-active { background-color: #4f46e5; color: white; }
    </style>
</head>
<body class="bg-base-300 min-h-screen">
    <div class="navbar bg-base-100 shadow-lg border-b border-base-content/10">
        <div class="flex-1 px-4">
            <a href="/dashboard" class="text-2xl font-bold tracking-tight">Authy</a>
        </div>
        <div class="flex-none px-4">
            <span class="text-xs opacity-50">v1.0</span>
        </div>
    </div>

    <div class="max-w-4xl mx-auto p-6">
        <div class="flex gap-1 mb-8 bg-base-100 p-1.5 rounded-xl shadow-sm w-fit mx-auto">
            <div onclick="switchTab(0)" id="t0" class="tab tab-active">Overview</div>
            <div onclick="switchTab(1)" id="t1" class="tab">Projects</div>
            <div onclick="switchTab(2)" id="t2" class="tab">Scripts</div>
        </div>

        <!-- Overview -->
        <div id="c0" class="tab-content active">
            <div class="card bg-base-100 shadow-sm">
                <div class="card-body items-center text-center py-16">
                    <h2 class="text-3xl font-semibold">Welcome to Authy</h2>
                    <p class="opacity-60 mt-2 max-w-md">Manage projects, generate keys, and host scripts. All in one place.</p>
                    <button onclick="switchTab(1)" class="btn btn-primary mt-6">Get Started</button>
                </div>
            </div>
        </div>

        <!-- Projects -->
        <div id="c1" class="tab-content">
            <div class="card bg-base-100 shadow-sm mb-6">
                <div class="card-body">
                    <h2 class="card-title text-lg">Create Project</h2>
                    <div class="flex gap-3 mt-2">
                        <input id="pname" placeholder="Project name" class="input input-bordered flex-1">
                        <button onclick="createProj()" class="btn btn-primary">Create</button>
                    </div>
                </div>
            </div>
            <div id="projList"></div>
        </div>

        <!-- Scripts -->
        <div id="c2" class="tab-content">
            <div class="card bg-base-100 shadow-sm">
                <div class="card-body">
                    <h2 class="card-title text-lg">Upload Script</h2>
                    <select id="selProj" class="select select-bordered w-full mt-2 mb-3"></select>
                    <input id="sname" placeholder="main.lua" class="input input-bordered w-full mb-3">
                    <textarea id="scode" class="textarea textarea-bordered w-full h-64 font-mono text-sm" placeholder="Paste your Lua script here..."></textarea>
                    <button onclick="uploadScript()" class="btn btn-primary w-full mt-3">Upload</button>
                </div>
            </div>
        </div>

        <!-- Loader -->
        <div class="card bg-base-100 shadow-sm mt-8">
            <div class="card-body">
                <div class="flex justify-between items-center">
                    <h2 class="card-title text-lg">Loader Script</h2>
                    <button onclick="copyLoader()" class="btn btn-sm btn-ghost">Copy</button>
                </div>
                <pre id="loaderPre" class="bg-base-200 p-4 rounded-lg text-xs overflow-auto max-h-72 font-mono mt-2"></pre>
            </div>
        </div>
    </div>

    <script>
        function switchTab(n) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.getElementById('c' + n).classList.add('active');
            document.querySelectorAll('.tab').forEach((el,i) => el.classList.toggle('tab-active', i===n));
            if (n === 1) loadProjects();
            if (n === 2) loadSelect();
        }

        async function createProj() {
            const name = document.getElementById("pname").value.trim();
            if (!name) return alert("Enter a project name");
            const res = await fetch("/api/project", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({name})
            });
            if (res.ok) {
                document.getElementById("pname").value = "";
                loadProjects();
            } else {
                alert("Error: " + await res.text());
            }
        }

        async function generateKey(pid) {
            const res = await fetch(`/api/key?project_id=${pid}`, {method: "POST"});
            if (res.ok) {
                const data = await res.json();
                await navigator.clipboard.writeText(data.key);
                alert("Key generated and copied:\\n" + data.key);
                loadProjects();
            } else {
                alert("Error: " + await res.text());
            }
        }

        async function loadProjects() {
            const res = await fetch("/api/projects");
            const ps = await res.json();
            let html = "";
            if (ps.length === 0) {
                html = '<div class="card bg-base-100 shadow-sm"><div class="card-body text-center opacity-60 py-8">No projects yet</div></div>';
            } else {
                ps.forEach(p => {
                    html += `
                    <div class="card bg-base-100 shadow-sm mb-3">
                        <div class="card-body py-4 flex-row items-center justify-between">
                            <div>
                                <div class="font-semibold">${p.name}</div>
                                <div class="text-xs opacity-50">ID: ${p.id}</div>
                            </div>
                            <button onclick="generateKey(${p.id})" class="btn btn-sm btn-primary">Generate Key</button>
                        </div>
                    </div>`;
                });
            }
            document.getElementById("projList").innerHTML = html;
        }

        async function loadSelect() {
            const res = await fetch("/api/projects");
            const ps = await res.json();
            let html = "<option value=''>Select a project</option>";
            ps.forEach(p => html += `<option value="${p.id}">${p.name}</option>`);
            document.getElementById("selProj").innerHTML = html;
        }

        async function uploadScript() {
            const pid = document.getElementById("selProj").value;
            const name = document.getElementById("sname").value.trim();
            const content = document.getElementById("scode").value.trim();
            if (!pid || !name || !content) return alert("Fill in all fields");
            const res = await fetch("/api/script", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({project_id: parseInt(pid), name, content})
            });
            if (res.ok) {
                alert("Script uploaded");
                document.getElementById("scode").value = "";
            } else {
                alert("Error: " + await res.text());
            }
        }

        function copyLoader() {
            navigator.clipboard.writeText(document.getElementById("loaderPre").textContent);
            alert("Copied");
        }

        document.getElementById("loaderPre").textContent =
`local key = "PUT_YOUR_KEY_HERE"

local resp = game:HttpGet("https://authy-o0pm.onrender.com/validate?key=" .. key)
if not resp or resp:find("Invalid") or resp:find("expired") then
    error("Auth failed")
end
loadstring(resp)()`;

        switchTab(0);
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
    proj = db.query(Project).get(project_id)
    if not proj:
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
    proj = db.query(Project).get(data.project_id)
    if not proj:
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
    if k.expires_at and k.expires_at < datetime.utcnow():
        raise HTTPException(401, "Key expired")

    proj = db.query(Project).get(k.project_id)
    if not proj or proj.killswitch:
        raise HTTPException(403, "Project disabled")

    script = db.query(Script).filter(Script.project_id == k.project_id).first()
    if not script:
        raise HTTPException(404, "No script uploaded for this project")

    k.last_heartbeat = datetime.utcnow()
    db.commit()

    return PlainTextResponse(script.content)

@app.get("/")
async def root():
    return RedirectResponse("/dashboard")
