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

app = FastAPI(title="Authy")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Models
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

# ====================== DASHBOARD WITH ERROR PANEL ======================
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
        .tab { cursor: pointer; padding: 12px 24px; }
        .tab-active { background-color: #4f46e5; color: white; border-radius: 8px; }
        #errorPanel {
            position: fixed;
            bottom: 20px;
            left: 20px;
            width: 380px;
            background: #1f2937;
            border: 1px solid #ef4444;
            border-radius: 12px;
            padding: 12px;
            font-size: 13px;
            max-height: 40vh;
            overflow-y: auto;
            z-index: 9999;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }
    </style>
</head>
<body class="bg-base-300 min-h-screen">
    <div class="navbar bg-base-100 shadow-xl">
        <div class="flex-1"><a href="/dashboard" class="btn btn-ghost text-3xl font-bold">🔐 Authy</a></div>
    </div>

    <div class="max-w-5xl mx-auto p-6">
        <h1 class="text-5xl font-bold text-center mb-8">Authy Control Panel</h1>

        <!-- Tabs -->
        <div class="flex justify-center mb-10 bg-base-100 p-2 rounded-box shadow">
            <div onclick="switchTab(0)" id="t0" class="tab tab-active">Overview</div>
            <div onclick="switchTab(1)" id="t1" class="tab">Projects & Keys</div>
            <div onclick="switchTab(2)" id="t2" class="tab">Host Script</div>
        </div>

        <!-- Overview -->
        <div id="c0" class="tab-content active card bg-base-100 shadow-xl p-12 text-center">
            <h2 class="text-4xl">Welcome to Authy</h2>
            <p class="mt-6 opacity-70">Use the tabs above. Errors will appear in the bottom left panel.</p>
        </div>

        <!-- Projects & Keys -->
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
                <textarea id="scode" class="textarea textarea-bordered w-full h-64 font-mono" placeholder="Paste Lua script..."></textarea>
                <button onclick="uploadScript()" class="btn btn-primary w-full mt-4">Upload Script</button>
            </div>
        </div>

        <!-- Loader -->
        <div class="card bg-base-100 shadow-xl mt-12">
            <div class="card-body">
                <h2 class="card-title">Public Loader</h2>
                <pre id="loaderPre" class="mockup-code bg-base-200 p-6 text-xs overflow-auto max-h-96"></pre>
                <button onclick="copyLoader()" class="btn btn-primary w-full mt-4">Copy Loader</button>
            </div>
        </div>
    </div>

    <!-- ERROR PANEL - Bottom Left -->
    <div id="errorPanel">
        <div class="flex justify-between items-center mb-2 border-b border-red-500 pb-2">
            <strong class="text-red-400">Error Log</strong>
            <button onclick="copyErrors()" class="btn btn-xs btn-error">Copy All Errors</button>
        </div>
        <div id="errorLog" class="text-red-300 font-mono text-xs whitespace-pre-wrap"></div>
        <div class="text-[10px] text-gray-500 mt-2">Check this panel for detailed errors</div>
    </div>

    <script>
        let errors = [];

        function logError(msg) {
            const time = new Date().toLocaleTimeString();
            errors.unshift(`[${time}] ${msg}`);
            if (errors.length > 20) errors.pop();
            document.getElementById("errorLog").textContent = errors.join("\\n\\n");
        }

        function copyErrors() {
            if (errors.length === 0) return alert("No errors to copy");
            navigator.clipboard.writeText(errors.join("\\n\\n"));
            alert("✅ All errors copied to clipboard!");
        }

        function switchTab(n) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.getElementById('c' + n).classList.add('active');
            document.querySelectorAll('.tab').forEach((el,i) => el.classList.toggle('tab-active', i===n));
            if (n === 1) loadProjects();
            if (n === 2) loadProjectsForSelect();
        }

        async function createProj() {
            const name = document.getElementById("pname").value.trim();
            if (!name) return alert("Enter project name");
            try {
                const res = await fetch("/api/project", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({name})});
                if (res.ok) {
                    alert("Project created!");
                    loadProjects();
                } else {
                    const err = await res.text();
                    logError("Create Project: " + err);
                    alert("Error: " + err);
                }
            } catch(e) {
                logError("Create Project failed: " + e);
                alert("Request failed");
            }
        }

        async function generateKey(pid) {
            try {
                const res = await fetch(`/api/key?project_id=${pid}`, {method:"POST"});
                if (res.ok) {
                    const data = await res.json();
                    alert(`✅ Key: ${data.key}`);
                    loadProjects();
                } else {
                    const err = await res.text();
                    logError("Generate Key: " + err);
                    alert("Error: " + err);
                }
            } catch(e) {
                logError("Generate Key failed: " + e);
                alert("Request failed");
            }
        }

        async function loadProjects() {
            try {
                const res = await fetch("/api/projects");
                const ps = await res.json();
                let html = "";
                ps.forEach(p => {
                    html += `<div class="flex justify-between p-4 border-b"><span>${p.name}</span><button onclick="generateKey(${p.id})" class="btn btn-sm btn-primary">Generate Key</button></div>`;
                });
                document.getElementById("projList").innerHTML = html || "<p class='p-6 text-center opacity-60'>No projects yet</p>";
            } catch(e) {
                logError("Load Projects: " + e);
            }
        }

        async function loadProjectsForSelect() {
            try {
                const res = await fetch("/api/projects");
                const ps = await res.json();
                let html = "<option value=''>Select Project</option>";
                ps.forEach(p => html += `<option value="${p.id}">${p.name}</option>`);
                document.getElementById("selProj").innerHTML = html;
            } catch(e) {
                logError("Load Select: " + e);
            }
        }

        async function uploadScript() {
            const pid = document.getElementById("selProj").value;
            const name = document.getElementById("sname").value.trim();
            const content = document.getElementById("scode").value.trim();
            if (!pid || !name || !content) return alert("Fill all fields");
            try {
                const res = await fetch("/api/script", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({project_id: parseInt(pid), name, content})});
                if (res.ok) alert("Script uploaded!");
                else {
                    const err = await res.text();
                    logError("Upload Script: " + err);
                    alert("Error: " + err);
                }
            } catch(e) {
                logError("Upload Script failed: " + e);
                alert("Request failed");
            }
        }

        function copyLoader() {
            navigator.clipboard.writeText(document.getElementById("loaderPre").textContent);
            alert("✅ Loader copied!");
        }

        // Loader
        document.getElementById("loaderPre").textContent = `script_key = ""  -- <<< PUT YOUR KEY HERE

-- Do not save this file
-- Always use the loadstring

local key = script_key or ""
if key == "" then error("Authy: Put your key in script_key") end

local resp = game:HttpGet("https://authy-o0pm.onrender.com/validate?key=" .. key)

if resp and resp:find('"success"') then
    local data = game:HttpService:JSONDecode(resp)
    return loadstring(game:HttpGet(data.script_url))()
else
    error("Authy: Failed to authenticate")
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
        proj = db.query(Project).get(project_id)
        if not proj:
            raise HTTPException(404, "Project not found")
        new_key = secrets.token_hex(32)
        k = Key(project_id=project_id, key_value=new_key)
        db.add(k)
        db.commit()
        return {"key": new_key}
    except Exception as e:
        raise HTTPException(500, f"Database error: {str(e)}")

class ScriptCreate(BaseModel):
    project_id: int
    name: str
    content: str

@app.post("/api/script")
async def upload_script(data: ScriptCreate, db=Depends(get_db)):
    try:
        if not db.query(Project).get(data.project_id):
            raise HTTPException(404, "Project not found")
        s = Script(project_id=data.project_id, name=data.name, content=data.content)
        db.add(s)
        db.commit()
        return {"success": True}
    except Exception as e:
        raise HTTPException(500, f"Error: {str(e)}")

@app.get("/validate")
async def validate(key: str, db=Depends(get_db)):
    try:
        k = db.query(Key).filter(Key.key_value == key, Key.banned == False).first()
        if not k:
            raise HTTPException(401, "Invalid key")
        proj = db.query(Project).get(k.project_id)
        if not proj:
            raise HTTPException(403, "Project not found")
        return {"success": True, "script_url": f"https://authy-o0pm.onrender.com/raw/default/main.lua"}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/raw/{project}/{filename}")
async def raw_script(request: Request, project: str, filename: str):
    if "roblox" in request.headers.get("user-agent", "").lower():
        return PlainTextResponse("-- Authy protected script loaded")
    return HTMLResponse("<h1>403 - No access tardball</h1>", status_code=403)

@app.get("/")
async def root():
    return RedirectResponse("/dashboard")
