from fastapi import FastAPI, HTTPException, Request, Depends, Form
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.sql import func
from pydantic import BaseModel
from datetime import datetime
import os
import secrets

# ========================= CONFIG =========================
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://neondb_owner:npg_S7hoDMeaw2cQ@ep-wandering-dream-ah21egpt-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI(title="Authy")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========================= MODELS =========================
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

# ========================= DASHBOARD HTML (Beautiful Frontend) =========================
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authy Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/npm/daisyui@4.12.10/dist/full.min.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = { content: ["*"], theme: { extend: {} } }
    </script>
</head>
<body class="bg-base-300 min-h-screen">
    <div class="navbar bg-base-100 shadow-xl">
        <div class="flex-1">
            <a href="/" class="btn btn-ghost text-2xl font-bold">🔐 Authy</a>
        </div>
        <div class="flex-none">
            <a href="/dashboard" class="btn btn-primary">Dashboard</a>
        </div>
    </div>

    <div class="container mx-auto p-6 max-w-7xl">
        <h1 class="text-4xl font-bold mb-8 text-center">Authy Control Panel</h1>

        <!-- Create Project -->
        <div class="card bg-base-100 shadow-xl mb-8">
            <div class="card-body">
                <h2 class="card-title">Create New Project</h2>
                <div class="form-control">
                    <input id="projectName" type="text" placeholder="Project Name (e.g. MyCoolScript)" class="input input-bordered w-full" />
                    <button onclick="createProject()" class="btn btn-success mt-4">Create Project</button>
                </div>
            </div>
        </div>

        <!-- Projects & Keys -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div id="projectsList" class="card bg-base-100 shadow-xl"></div>
            <div id="keysList" class="card bg-base-100 shadow-xl"></div>
        </div>

        <!-- Loader Generator -->
        <div class="card bg-base-100 shadow-xl mt-8">
            <div class="card-body">
                <h2 class="card-title">🚀 Public Loader</h2>
                <p class="text-sm opacity-70">Copy this loader and give it to users</p>
                <div class="mockup-code mt-4">
                    <pre id="loaderCode" class="text-xs overflow-auto max-h-96 p-4"></pre>
                </div>
                <button onclick="copyLoader()" class="btn btn-primary mt-4 w-full">Copy Loader to Clipboard</button>
            </div>
        </div>
    </div>

    <script>
        const DOMAIN = "https://authy-o0pm.onrender.com";

        async function loadDashboard() {
            // In real version fetch from /api/projects and /api/keys
            // For now we show static + loader
            document.getElementById("projectsList").innerHTML = `
                <div class="card-body">
                    <h2 class="card-title">Projects</h2>
                    <p class="opacity-60">Create a project above to get started</p>
                </div>`;

            // Generate loader
            const loader = `-- Do not save this file
-- Always use the loadstring
-- Authy Loader - Protected

local function gethwid()
    local clientId = tostring(game:GetService("RbxAnalyticsService"):GetClientId())
    local extra = syn and syn.request or http_request or request
    return game:HttpService:JSONEncode({cid = clientId, ts = tick()})
end

local key = script_key or "PUT_YOUR_KEY_HERE"
local hwid = gethwid()

local res = game:HttpGet(DOMAIN.."/validate?key="..key.."&hwid="..game:HttpService:UrlEncode(hwid))

if res and res:find("success") then
    local scriptUrl = DOMAIN.."/raw/project/script.lua"  -- update per project
    local payload = game:HttpGet(scriptUrl)
    
    pcall(makefolder, "authy_cache")
    pcall(writefile, "authy_cache/init.lua", payload)
    
    spawn(function()
        while wait(60) do
            game:HttpGet(DOMAIN.."/heartbeat?key="..key.."&hwid="..game:HttpService:UrlEncode(hwid))
        end
    end)
    
    return loadstring(payload)()
else
    error("Authy: Invalid key or banned")
end`;

            document.getElementById("loaderCode").textContent = loader;
        }

        function copyLoader() {
            const code = document.getElementById("loaderCode").textContent;
            navigator.clipboard.writeText(code);
            alert("✅ Loader copied! Paste it into your script.");
        }

        // Initial load
        loadDashboard();
    </script>
</body>
</html>
"""

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)

# ========================= HTML TRAP =========================
@app.get("/raw/{project}/{filename}")
async def raw_script(request: Request, project: str, filename: str):
    ua = request.headers.get("user-agent", "").lower()
    if "roblox" in ua or request.headers.get("x-authy-client") == "loader":
        return PlainTextResponse("-- Authy protected script\n-- Loaded successfully")
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html><head><title>403</title><style>body{background:#111;color:#f44;font-family:monospace;text-align:center;padding:100px;}</style></head>
    <body><h1>403 - No access tardball</h1><p>You shouldn't be here dumbass</p></body></html>
    """, status_code=403)

# ========================= API =========================
class ValidateRequest(BaseModel):
    key: str
    hwid: str

@app.post("/validate")
async def validate(data: ValidateRequest, db=Depends(get_db)):
    key_obj = db.query(Key).filter(Key.key_value == data.key, Key.banned == False).first()
    if not key_obj:
        raise HTTPException(401, "Invalid key")

    if key_obj.expires_at and key_obj.expires_at < datetime.utcnow():
        raise HTTPException(403, "Key expired")

    key_obj.last_heartbeat = datetime.utcnow()
    if not key_obj.hwid:
        key_obj.hwid = data.hwid
    db.commit()

    return {"success": True, "message": "Authenticated"}

@app.post("/heartbeat")
async def heartbeat(data: ValidateRequest, db=Depends(get_db)):
    key_obj = db.query(Key).filter(Key.key_value == data.key).first()
    if not key_obj or key_obj.banned:
        return {"action": "kick"}
    key_obj.last_heartbeat = datetime.utcnow()
    db.commit()
    return {"action": "continue"}

@app.get("/")
async def root():
    return {"message": "Authy Backend Running - Visit /dashboard"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
