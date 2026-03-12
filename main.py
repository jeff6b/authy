import os
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import JWTError, jwt
import asyncpg
from dotenv import load_dotenv
import uvicorn
import bcrypt

# Load environment variables
load_dotenv()

# ========== CONFIGURATION ==========
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
DATABASE_URL = os.getenv("DATABASE_URL")
MASTER_API_KEY = "123"

print("🚀 Starting Authy application...")
print(f"📊 DATABASE_URL exists: {bool(DATABASE_URL)}")
print(f"🔑 SECRET_KEY exists: {bool(SECRET_KEY)}")

# ========== PASSWORD HASHING ==========
def hash_password(password: str) -> str:
    password_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        plain_bytes = plain_password.encode('utf-8')[:72]
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(plain_bytes, hashed_bytes)
    except Exception as e:
        print(f"Password verification error: {e}")
        return False

# Test bcrypt at startup
try:
    test_hash = hash_password("test123")
    test_verify = verify_password("test123", test_hash)
    print(f"✅ Bcrypt working: {test_verify}")
except Exception as e:
    print(f"❌ Bcrypt error: {e}")

# ========== DATABASE CONNECTION POOL ==========
class Database:
    def __init__(self):
        self.pool = None

    async def connect(self):
        print(f"🔌 Attempting to connect to database...")
        
        if not DATABASE_URL:
            print("❌ CRITICAL: DATABASE_URL is not set!")
            return
        
        try:
            self.pool = await asyncpg.create_pool(
                DATABASE_URL, 
                min_size=5, 
                max_size=20,
                command_timeout=60
            )
            
            async with self.pool.acquire() as conn:
                await conn.execute("SELECT 1")
                print("✅ Database connection test successful!")
            
            await self.init_db()
            print("✅ Database connected and initialized")
            return True
            
        except Exception as e:
            print(f"❌ Database connection failed: {type(e).__name__}: {e}")
            return False

    async def disconnect(self):
        if self.pool:
            await self.pool.close()
            print("✅ Database disconnected")

    async def init_db(self):
        """Initialize database tables WITHOUT dropping - preserves data!"""
        if not self.pool:
            print("⚠️ Cannot init DB - no connection pool")
            return
            
        try:
            async with self.pool.acquire() as conn:
                print("🔄 Ensuring database tables exist...")
                
                # Users table - CREATE IF NOT EXISTS (preserves data)
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_admin BOOLEAN DEFAULT FALSE
                    )
                ''')
                print("✅ Users table ready")
                
                # Scripts table - CREATE IF NOT EXISTS
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS scripts (
                        id SERIAL PRIMARY KEY,
                        name TEXT NOT NULL,
                        script_type TEXT DEFAULT 'standard',
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        config JSONB DEFAULT '{}',
                        UNIQUE(name, user_id)
                    )
                ''')
                print("✅ Scripts table ready")
                
                # Keys table - CREATE IF NOT EXISTS
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS keys (
                        id SERIAL PRIMARY KEY,
                        key TEXT UNIQUE NOT NULL,
                        script_id INTEGER NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
                        nickname TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP NOT NULL,
                        last_heartbeat TIMESTAMP,
                        hwid TEXT,
                        status TEXT DEFAULT 'active',
                        kicked BOOLEAN DEFAULT FALSE,
                        max_hwid_resets INTEGER DEFAULT 3,
                        hwid_resets_used INTEGER DEFAULT 0,
                        note TEXT
                    )
                ''')
                print("✅ Keys table ready")
                
                # Heartbeat logs table - CREATE IF NOT EXISTS
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS heartbeat_logs (
                        id SERIAL PRIMARY KEY,
                        key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        hwid TEXT NOT NULL,
                        ip_address TEXT
                    )
                ''')
                print("✅ Heartbeat logs table ready")
                
                # Create indexes if they don't exist
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_script_id ON keys(script_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_scripts_user_id ON scripts(user_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_heartbeat_key_id ON heartbeat_logs(key_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_heartbeat_timestamp ON heartbeat_logs(timestamp)')
                
                print("✅ Database tables ready - data preserved!")
                
        except Exception as e:
            print(f"❌ Failed to initialize tables: {e}")
            import traceback
            traceback.print_exc()

db = Database()

# ========== LIFESPAN HANDLER ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Starting up...")
    try:
        await db.connect()
    except Exception as e:
        print(f"⚠️ Startup error: {e}")
    
    yield
    
    print("🛑 Shutting down...")
    await db.disconnect()

# ========== FASTAPI APP ==========
app = FastAPI(
    title="Authy - Lua Auth System",
    description="Complete authentication system for Lua scripts",
    version="2.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer(auto_error=False)

# ========== HELPER FUNCTIONS ==========
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire.timestamp()})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

async def get_current_user(auth: HTTPAuthorizationCredentials = Depends(security)):
    if not auth:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    payload = verify_token(auth.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        user = await conn.fetchrow(
            "SELECT id, username, email, created_at, is_admin FROM users WHERE username = $1",
            payload["sub"]
        )
        
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return dict(user)

def generate_key():
    """Generate a unique license key format: AUTHY-XXXX-XXXX-XXXX"""
    parts = []
    for _ in range(3):
        parts.append(uuid.uuid4().hex[:4].upper())
    return f"AUTHY-{'-'.join(parts)}"

# ========== PYDANTIC MODELS ==========
class UserCreate(BaseModel):
    username: str
    password: str
    api_key: str

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class ScriptCreate(BaseModel):
    name: str
    script_type: Optional[str] = "standard"
    config: Optional[dict] = {}

class ScriptResponse(BaseModel):
    id: int
    name: str
    script_type: str
    created_at: str
    key_count: int
    active_keys: int
    config: dict

class KeyCreate(BaseModel):
    script_id: int
    nickname: Optional[str] = None
    duration_days: int = 30

class KeyResponse(BaseModel):
    key: str
    nickname: Optional[str]
    expires_at: str
    status: str

class KeyAction(BaseModel):
    key: str
    action: str  # 'activate', 'deactivate', 'kick'

class KeyNickname(BaseModel):
    key: str
    nickname: str

class HeartbeatRequest(BaseModel):
    key: str
    hwid: str

class HeartbeatResponse(BaseModel):
    valid: bool
    status: str
    message: str
    script_name: Optional[str] = None
    script_type: Optional[str] = None
    config: Optional[dict] = None
    kicked: bool = False
    expires_at: Optional[str] = None

class HWIDResetRequest(BaseModel):
    key: str
    confirm: bool = False

# ========== AUTH ENDPOINTS ==========
@app.post("/api/auth/register", response_model=TokenResponse)
async def register(user: UserCreate):
    """Register a new user using API key"""
    print(f"📝 Register attempt: {user.username}")
    
    if user.api_key != MASTER_API_KEY:
        print(f"❌ Invalid API key: {user.api_key}")
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        async with db.pool.acquire() as conn:
            existing = await conn.fetchval(
                "SELECT id FROM users WHERE username = $1 OR email = $2",
                user.username, f"{user.username}@placeholder.com"
            )
            
            if existing:
                raise HTTPException(status_code=400, detail="Username already taken")
            
            hashed = hash_password(user.password)
            
            user_id = await conn.fetchval(
                "INSERT INTO users (username, password_hash, email) VALUES ($1, $2, $3) RETURNING id",
                user.username, hashed, f"{user.username}@authy.local"
            )
            
            token = create_access_token({"sub": user.username, "id": user_id})
            
            print(f"✅ Registered: {user.username}")
            return {"access_token": token, "token_type": "bearer"}
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Register error: {e}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(user: UserLogin):
    """Login user"""
    print(f"🔐 Login attempt: {user.username}")
    
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        async with db.pool.acquire() as conn:
            db_user = await conn.fetchrow(
                "SELECT * FROM users WHERE username = $1",
                user.username
            )
            
            if not db_user or not verify_password(user.password, db_user['password_hash']):
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            token = create_access_token({"sub": user.username, "id": db_user['id']})
            
            print(f"✅ Login successful: {user.username}")
            return {"access_token": token, "token_type": "bearer"}
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Login error: {e}")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@app.get("/api/user/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    return current_user

# ========== SCRIPT MANAGEMENT ==========
@app.post("/api/scripts/create")
async def create_script(
    script_data: ScriptCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new script with type differentiation"""
    print(f"📝 Creating script: {script_data.name} for user {current_user['id']}")
    
    if not db.pool:
        print("❌ Database not available")
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        async with db.pool.acquire() as conn:
            # Check if script name already exists
            existing = await conn.fetchval(
                "SELECT id FROM scripts WHERE name = $1 AND user_id = $2",
                script_data.name, current_user['id']
            )
            
            if existing:
                print(f"❌ Script name already exists: {script_data.name}")
                raise HTTPException(status_code=400, detail="Script name already exists")
            
            # Insert new script
            script_id = await conn.fetchval(
                "INSERT INTO scripts (name, script_type, user_id, config) VALUES ($1, $2, $3, $4) RETURNING id",
                script_data.name, script_data.script_type, current_user['id'], script_data.config or {}
            )
            
            print(f"✅ Script created with ID: {script_id}")
            return {
                "id": script_id,
                "name": script_data.name,
                "script_type": script_data.script_type,
                "message": "Script created successfully"
            }
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ Script creation error: {e}")
        raise HTTPException(status_code=500, detail=f"Script creation failed: {str(e)}")

@app.get("/api/scripts")
async def get_scripts(current_user: dict = Depends(get_current_user)):
    """Get all scripts for current user"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        scripts = await conn.fetch(
            """
            SELECT s.*, 
                   COUNT(k.id) as key_count,
                   COUNT(CASE WHEN k.status = 'active' AND k.expires_at > CURRENT_TIMESTAMP THEN 1 END) as active_keys
            FROM scripts s
            LEFT JOIN keys k ON s.id = k.script_id
            WHERE s.user_id = $1
            GROUP BY s.id
            ORDER BY s.created_at DESC
            """,
            current_user['id']
        )
        
        result = []
        for script in scripts:
            result.append({
                "id": script['id'],
                "name": script['name'],
                "script_type": script['script_type'],
                "created_at": script['created_at'].isoformat(),
                "key_count": script['key_count'],
                "active_keys": script['active_keys'],
                "config": script['config']
            })
        
        return result

@app.delete("/api/scripts/{script_id}")
async def delete_script(
    script_id: int,
    current_user: dict = Depends(get_current_user)
):
    """Delete a script and all its keys"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM scripts WHERE id = $1 AND user_id = $2",
            script_id, current_user['id']
        )
        
        if result.split()[-1] == "0":
            raise HTTPException(status_code=404, detail="Script not found")
        
        return {"success": True}

# ========== KEY MANAGEMENT ==========
@app.post("/api/keys/create")
async def create_key(
    key_data: KeyCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new key for a script"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        # Verify script belongs to user
        script = await conn.fetchval(
            "SELECT id FROM scripts WHERE id = $1 AND user_id = $2",
            key_data.script_id, current_user['id']
        )
        
        if not script:
            raise HTTPException(status_code=404, detail="Script not found")
        
        # Generate unique key
        key = generate_key()
        while await conn.fetchval("SELECT id FROM keys WHERE key = $1", key):
            key = generate_key()
        
        # Create key
        expires_at = datetime.now() + timedelta(days=key_data.duration_days) if key_data.duration_days > 0 else datetime.now() + timedelta(days=3650)  # ~10 years for lifetime
        await conn.fetchval(
            """
            INSERT INTO keys 
            (key, script_id, nickname, expires_at, note) 
            VALUES ($1, $2, $3, $4, $5) 
            RETURNING id
            """,
            key, key_data.script_id, key_data.nickname, expires_at, key_data.nickname
        )
        
        return {
            "key": key,
            "nickname": key_data.nickname,
            "expires_at": expires_at.isoformat(),
            "status": "active"
        }

@app.get("/api/keys")
async def get_keys(current_user: dict = Depends(get_current_user)):
    """Get all keys for current user"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        keys = await conn.fetch(
            """
            SELECT k.*, s.name as script_name, s.script_type
            FROM keys k
            JOIN scripts s ON k.script_id = s.id
            WHERE s.user_id = $1
            ORDER BY k.created_at DESC
            """,
            current_user['id']
        )
        
        result = []
        for key in keys:
            key = dict(key)
            online = False
            if key['last_heartbeat']:
                online = (datetime.now() - key['last_heartbeat']).seconds < 120
            
            result.append({
                "key": key['key'],
                "nickname": key['nickname'],
                "script_name": key['script_name'],
                "script_type": key['script_type'],
                "created_at": key['created_at'].isoformat() if key['created_at'] else None,
                "expires_at": key['expires_at'].isoformat() if key['expires_at'] else None,
                "last_heartbeat": key['last_heartbeat'].isoformat() if key['last_heartbeat'] else None,
                "hwid": key['hwid'],
                "status": key['status'],
                "online": online,
                "kicked": key['kicked'],
                "hwid_resets_used": key['hwid_resets_used'],
                "max_hwid_resets": key['max_hwid_resets']
            })
        
        return result

@app.post("/api/keys/action")
async def key_action(
    action: KeyAction,
    current_user: dict = Depends(get_current_user)
):
    """Activate, deactivate, or kick a key"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        key_info = await conn.fetchrow(
            """
            SELECT k.* FROM keys k
            JOIN scripts s ON k.script_id = s.id
            WHERE k.key = $1 AND s.user_id = $2
            """,
            action.key, current_user['id']
        )
        
        if not key_info:
            raise HTTPException(status_code=404, detail="Key not found")
        
        if action.action == "activate":
            await conn.execute(
                "UPDATE keys SET status = 'active', kicked = FALSE WHERE key = $1",
                action.key
            )
            return {"success": True, "message": "Key activated"}
            
        elif action.action == "deactivate":
            await conn.execute(
                "UPDATE keys SET status = 'suspended', kicked = FALSE WHERE key = $1",
                action.key
            )
            return {"success": True, "message": "Key deactivated"}
            
        elif action.action == "kick":
            # Set kicked flag - next heartbeat will fail and client will be kicked
            await conn.execute(
                "UPDATE keys SET kicked = TRUE WHERE key = $1",
                action.key
            )
            return {"success": True, "message": "User will be kicked on next heartbeat"}
        
        raise HTTPException(status_code=400, detail="Invalid action")

@app.post("/api/keys/nickname")
async def set_nickname(
    nick_data: KeyNickname,
    current_user: dict = Depends(get_current_user)
):
    """Set nickname for a key"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        key_info = await conn.fetchrow(
            """
            SELECT k.* FROM keys k
            JOIN scripts s ON k.script_id = s.id
            WHERE k.key = $1 AND s.user_id = $2
            """,
            nick_data.key, current_user['id']
        )
        
        if not key_info:
            raise HTTPException(status_code=404, detail="Key not found")
        
        await conn.execute(
            "UPDATE keys SET nickname = $1 WHERE key = $2",
            nick_data.nickname, nick_data.key
        )
        
        return {"success": True, "message": "Nickname updated"}

@app.post("/api/keys/reset-hwid")
async def reset_hwid(
    request: HWIDResetRequest,
    current_user: dict = Depends(get_current_user)
):
    """Reset HWID for a key"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        key_info = await conn.fetchrow(
            """
            SELECT k.* FROM keys k
            JOIN scripts s ON k.script_id = s.id
            WHERE k.key = $1 AND s.user_id = $2
            """,
            request.key, current_user['id']
        )
        
        if not key_info:
            raise HTTPException(status_code=404, detail="Key not found")
        
        if key_info['hwid_resets_used'] >= key_info['max_hwid_resets']:
            raise HTTPException(status_code=400, detail="No HWID resets remaining")
        
        if not request.confirm:
            return {
                "warning": f"This will reset HWID for {request.key}. {key_info['max_hwid_resets'] - key_info['hwid_resets_used'] - 1} resets remaining.",
                "confirm_needed": True
            }
        
        await conn.execute(
            "UPDATE keys SET hwid = NULL, hwid_resets_used = hwid_resets_used + 1, kicked = FALSE WHERE key = $1",
            request.key
        )
        
        return {
            "success": True,
            "message": f"HWID reset for {request.key}. {key_info['max_hwid_resets'] - key_info['hwid_resets_used'] - 1} resets remaining."
        }

@app.delete("/api/keys/{key}")
async def delete_key(
    key: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a key"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        result = await conn.execute(
            """
            DELETE FROM keys 
            WHERE key = $1 AND script_id IN (
                SELECT id FROM scripts WHERE user_id = $2
            )
            """,
            key, current_user['id']
        )
        
        if result.split()[-1] == "0":
            raise HTTPException(status_code=404, detail="Key not found")
        
        return {"success": True}

# ========== STATS ==========
@app.get("/api/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    """Get dashboard stats"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        total_scripts = await conn.fetchval(
            "SELECT COUNT(*) FROM scripts WHERE user_id = $1",
            current_user['id']
        )
        
        total_keys = await conn.fetchval(
            """
            SELECT COUNT(*) FROM keys k
            JOIN scripts s ON k.script_id = s.id
            WHERE s.user_id = $1
            """,
            current_user['id']
        )
        
        active_keys = await conn.fetchval(
            """
            SELECT COUNT(*) FROM keys k
            JOIN scripts s ON k.script_id = s.id
            WHERE s.user_id = $1 
            AND k.status = 'active' 
            AND k.expires_at > CURRENT_TIMESTAMP
            """,
            current_user['id']
        )
        
        online_now = await conn.fetchval(
            """
            SELECT COUNT(*) FROM keys k
            JOIN scripts s ON k.script_id = s.id
            WHERE s.user_id = $1 
            AND k.last_heartbeat IS NOT NULL
            AND EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - k.last_heartbeat)) < 120
            """,
            current_user['id']
        )
        
        expiring_soon = await conn.fetchval(
            """
            SELECT COUNT(*) FROM keys k
            JOIN scripts s ON k.script_id = s.id
            WHERE s.user_id = $1 
            AND k.status = 'active'
            AND k.expires_at > CURRENT_TIMESTAMP
            AND k.expires_at < CURRENT_TIMESTAMP + INTERVAL '7 days'
            """,
            current_user['id']
        )
        
        return {
            "total_scripts": total_scripts or 0,
            "total_keys": total_keys or 0,
            "active_keys": active_keys or 0,
            "online_now": online_now or 0,
            "expiring_soon": expiring_soon or 0
        }

# ========== LOADER GENERATION ==========
@app.post("/api/loader/generate")
async def generate_loader(
    data: dict,
    current_user: dict = Depends(get_current_user)
):
    """Generate a differentiated loader for a specific script"""
    script_id = data.get('script_id')
    
    if not script_id:
        raise HTTPException(status_code=400, detail="Script ID required")
    
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        script = await conn.fetchrow(
            "SELECT * FROM scripts WHERE id = $1 AND user_id = $2",
            script_id, current_user['id']
        )
        
        if not script:
            raise HTTPException(status_code=404, detail="Script not found")
        
        # Generate differentiated loader based on script type
        script_type = script['script_type']
        config = script['config'] or {}
        
        loader = f'''-- =============================================
-- AUTHY LOADER FOR: {script['name']}
-- TYPE: {script_type}
-- GENERATED: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
-- =============================================

local AUTH_URL = "https://authy-o0pm.onrender.com"
local API_BASE = AUTH_URL

-- Get HWID
local function get_hwid()
    local hwid = gethwid and gethwid()
    if not hwid then
        hwid = "TEST-HWID-123456"
    end
    return hwid
end

-- HTTP request
local function request_api(endpoint, data)
    local response = syn and syn.request or http and http.request or request
    if not response then
        error("No HTTP request function found")
    end
    
    local result = response({{
        Url = API_BASE .. endpoint,
        Method = "POST",
        Headers = {{
            ["Content-Type"] = "application/json"
        }},
        Body = game:GetService("HttpService"):JSONEncode(data)
    }})
    
    return game:GetService("HttpService"):JSONDecode(result.Body)
end

-- Validate key
local function validate_key(key, hwid)
    local response = request_api("/api/validate", {{
        key = key,
        hwid = hwid
    }})
    return response.valid, response
end

-- Heartbeat
local function send_heartbeat(key, hwid)
    local response = request_api("/api/heartbeat", {{
        key = key,
        hwid = hwid
    }})
    return response.valid, response
end

-- Main authentication
local function authenticate(key)
    local hwid = get_hwid()
    print("🔑 HWID: " .. hwid)
    
    local valid, response = validate_key(key, hwid)
    
    if not valid then
        print("❌ Authentication failed: " .. (response.reason or "unknown error"))
        return false
    end
    
    print("✅ Authentication successful!")
    print("📜 Script: {script['name']} ({script_type})")
    
    -- Check if kicked
    if response.kicked then
        print("❌ You have been kicked from this script!")
        return false
    end
    
    -- Start heartbeat
    spawn(function()
        while wait(60) do
            local valid, hb_response = send_heartbeat(key, hwid)
            if not valid or hb_response.kicked then
                print("❌ You have been kicked or license invalidated!")
                return
            end
            print("💓 Heartbeat OK")
        end
    end)
    
    return true
end

-- Export functions
return {{
    authenticate = authenticate,
    get_hwid = get_hwid,
    validate = validate_key
}}
'''
        
        return {
            "loader": loader,
            "script_name": script['name'],
            "script_type": script_type,
            "instructions": "Copy this loader and paste it at the bottom of your script. The user will need to provide their key."
        }

# ========== PUBLIC API ENDPOINTS ==========
@app.post("/api/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(request: HeartbeatRequest, req: Request):
    """Lua clients call this - checks if kicked"""
    if not db.pool:
        return HeartbeatResponse(
            valid=False, 
            status="error", 
            message="Database not available"
        )
    
    async with db.pool.acquire() as conn:
        key_info = await conn.fetchrow(
            """
            SELECT k.*, s.name as script_name, s.script_type, s.config
            FROM keys k
            JOIN scripts s ON k.script_id = s.id
            WHERE k.key = $1
            """,
            request.key
        )
        
        if not key_info:
            return HeartbeatResponse(
                valid=False, 
                status="invalid", 
                message="Key not found"
            )
        
        key_info = dict(key_info)
        
        # Check if kicked
        if key_info['kicked']:
            return HeartbeatResponse(
                valid=False,
                status="kicked",
                message="You have been kicked from this script",
                kicked=True
            )
        
        # Check if expired
        if key_info['expires_at'] < datetime.now():
            await conn.execute(
                "UPDATE keys SET status = 'expired' WHERE id = $1",
                key_info['id']
            )
            return HeartbeatResponse(
                valid=False, 
                status="expired", 
                message="Key expired"
            )
        
        # Check if suspended
        if key_info['status'] != 'active':
            return HeartbeatResponse(
                valid=False, 
                status=key_info['status'], 
                message=f"Key {key_info['status']}"
            )
        
        # HWID binding
        client_ip = req.client.host if req.client else "unknown"
        
        if not key_info['hwid']:
            await conn.execute(
                "UPDATE keys SET hwid = $1, last_heartbeat = CURRENT_TIMESTAMP WHERE id = $2",
                request.hwid, key_info['id']
            )
        elif key_info['hwid'] != request.hwid:
            return HeartbeatResponse(
                valid=False, 
                status="hwid_mismatch", 
                message="Invalid HWID"
            )
        else:
            await conn.execute(
                "UPDATE keys SET last_heartbeat = CURRENT_TIMESTAMP WHERE id = $1",
                key_info['id']
            )
        
        # Log heartbeat
        await conn.execute(
            "INSERT INTO heartbeat_logs (key_id, hwid, ip_address) VALUES ($1, $2, $3)",
            key_info['id'], request.hwid, client_ip
        )
        
        days_left = (key_info['expires_at'] - datetime.now()).days if key_info['expires_at'] > datetime.now() else 0
        
        return HeartbeatResponse(
            valid=True, 
            status="active", 
            message=f"Valid - {days_left} days remaining",
            script_name=key_info['script_name'],
            script_type=key_info['script_type'],
            config=key_info['config'],
            kicked=False,
            expires_at=key_info['expires_at'].isoformat()
        )

@app.post("/api/validate")
async def validate_key(request: HeartbeatRequest):
    """Simple validation"""
    if not db.pool:
        return {"valid": False, "reason": "database_error"}
    
    async with db.pool.acquire() as conn:
        key_info = await conn.fetchrow(
            """
            SELECT k.*, s.name as script_name, s.script_type
            FROM keys k
            JOIN scripts s ON k.script_id = s.id
            WHERE k.key = $1
            """,
            request.key
        )
        
        if not key_info:
            return {"valid": False, "reason": "not_found"}
        
        key_info = dict(key_info)
        
        if key_info['kicked']:
            return {"valid": False, "reason": "kicked"}
        
        if key_info['expires_at'] < datetime.now():
            return {"valid": False, "reason": "expired"}
        
        if key_info['status'] != 'active':
            return {"valid": False, "reason": key_info['status']}
        
        if key_info['hwid'] and key_info['hwid'] != request.hwid:
            return {"valid": False, "reason": "hwid_mismatch"}
        
        if not key_info['hwid']:
            await conn.execute(
                "UPDATE keys SET hwid = $1 WHERE id = $2",
                request.hwid, key_info['id']
            )
        
        return {
            "valid": True,
            "script_name": key_info['script_name'],
            "script_type": key_info['script_type'],
            "expires": key_info['expires_at'].isoformat()
        }

# ========== ORIGINAL HOMEPAGE ==========
HOMEPAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Authy - Protect Your Lua Scripts</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
  <style>
    *{margin:0;padding:0;box-sizing:border-box;}
    html{scroll-behavior:smooth;}
    body{
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      background: #15171e;
      color: #f9fafb;
      min-height: 100vh;
      overflow-x: hidden;
      position: relative;
    }
    body::before {
      content: "";
      position: fixed;
      inset: 0;
      background-image:
        radial-gradient(circle at 2px 2px, #4a90e2 1px, transparent 1px),
        radial-gradient(circle at 17px 17px, #4a90e2 1px, transparent 1px);
      background-size: 30px 30px;
      opacity: 0.07;
      pointer-events: none;
      z-index: -1;
    }
    .navbar{
      position:fixed;
      top:12px;
      left:5%;
      right:5%;
      height:60px;
      border-radius:16px;
      box-shadow:0 4px 20px rgba(0,0,0,0.35);
      background:rgba(21,23,30,0.65);
      backdrop-filter:blur(16px);
      -webkit-backdrop-filter:blur(16px);
      border:1px solid rgba(63,72,90,0.4);
      z-index:1000;
      display:flex;
      align-items:center;
      justify-content:space-between;
      padding:0 25px;
    }
    .logo {
      font-size:1.4rem;
      font-weight:800;
      color: #4a90e2;
      letter-spacing:-0.02em;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .logo i {
      color: #4a90e2;
      font-size: 1.8rem;
    }
    .nav-menu{
      display:flex;
      align-items:center;
      gap:1.8rem;
      margin: 0 auto;
    }
    .nav-link{
      color:#b6bcc8;
      font-size:0.98rem;
      font-weight:500;
      text-decoration:none;
      transition:color 0.25s ease;
    }
    .nav-link:hover{
      color:#4a90e2;
    }
    .nav-right{
      display:flex;
      align-items:center;
      gap:1.5rem;
    }
    .sign-in {
      color:#f9fafb;
      font-size:1rem;
      font-weight:500;
      cursor:pointer;
      transition:color 0.25s ease;
    }
    .sign-in:hover{
      color:#4a90e2;
    }
    .sign-up-btn{
      background:#4a90e2;
      color:#ffffff;
      font-size:1rem;
      font-weight:600;
      padding:0.6rem 1.1rem;
      border-radius:8px;
      border:none;
      cursor:pointer;
      transition: all 0.25s ease;
    }
    .sign-up-btn:hover{
      transform:translateY(-1px);
      background:#60c0ff;
    }
    .hero-section{
      min-height:100vh;
      display:flex;
      flex-direction:column;
      justify-content:center;
      align-items:center;
      text-align:center;
      padding:0 20px;
      position:relative;
      z-index:10;
    }
    .hero-text{
      font-size: clamp(2.8rem, 6.5vw, 4.2rem);
      font-weight:800;
      letter-spacing:-0.02em;
      line-height:1.1;
      margin-bottom:0.6rem;
    }
    .hero-subtitle {
      font-size: clamp(1.1rem, 3vw, 1.45rem);
      font-weight: 500;
      color: #a0a0a0;
      margin-top: 0.4rem;
      letter-spacing: -0.01em;
      max-width: 640px;
    }
    .highlight{
      color:#4a90e2;
    }
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(10, 12, 22, 0.88);
      backdrop-filter: blur(8px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 2000;
      opacity: 0;
      transition: opacity 0.3s ease;
    }
    .modal-overlay.show {
      opacity: 1;
    }
    .modal {
      background: rgba(21, 23, 30, 0.96);
      backdrop-filter: blur(14px);
      border-radius: 18px;
      width: 420px;
      max-width: 92%;
      padding: 32px 30px 24px;
      border: 1px solid #2a2f3a;
      box-shadow: 0 16px 50px rgba(0,0,0,0.6);
      position: relative;
      transform: translateY(20px);
      opacity: 0;
      transition: all 0.35s cubic-bezier(0.34, 1.56, 0.64, 1);
    }
    .modal-overlay.show .modal {
      transform: translateY(0);
      opacity: 1;
    }
    .modal-close {
      position: absolute;
      top: 16px;
      right: 20px;
      font-size: 1.8rem;
      color: #555;
      cursor: pointer;
      transition: color 0.2s, transform 0.2s;
    }
    .modal-close:hover {
      color: #ccc;
      transform: rotate(90deg);
    }
    .authy-title {
      font-size: 2.2rem;
      font-weight: 800;
      color: #ffffff;
      letter-spacing: -0.02em;
      text-align: center;
      margin-bottom: 28px;
    }
    .floating-input {
      position: relative;
      margin-bottom: 20px;
      --label-float-top: -1px;
      --notch-left: 11px;
      --notch-width: 45px;
    }
    .floating-input input {
      width: 100%;
      padding: 16px 18px 12px;
      background: rgba(30,35,45,0.7);
      border: 1px solid #2a2f3a;
      border-radius: 12px;
      color: #fff;
      font-size: 1.02rem;
      outline: none;
      transition: border-color 0.25s ease;
    }
    .floating-input input:focus {
      border-color: #4a90e2;
    }
    .floating-input label {
      position: absolute;
      top: 50%;
      left: 18px;
      transform: translateY(-50%);
      color: #aaa;
      font-size: 1rem;
      pointer-events: none;
      transition: all 0.25s ease;
      transform-origin: left center;
      padding: 0 6px;
      z-index: 2;
    }
    .floating-input input:focus + label,
    .floating-input input:not(:placeholder-shown) + label {
      top: var(--label-float-top);
      left: calc(var(--notch-left) + 2px);
      font-size: 0.82rem;
      color: #4a90e2;
      background: rgba(21, 23, 30, 0.96);
    }
    .notch-cover {
      position: absolute;
      top: -1px;
      left: var(--notch-left);
      height: 2px;
      background: rgba(21, 23, 30, 0.96);
      z-index: 1;
      pointer-events: none;
      width: 0;
      transition: width 0.25s ease;
    }
    .floating-input input:focus ~ .notch-cover,
    .floating-input input:not(:placeholder-shown) ~ .notch-cover {
      width: var(--notch-width);
    }
    .login-btn {
      width: 100%;
      padding: 15px;
      background: #ffffff;
      color: #1a1f2e;
      font-weight: 600;
      font-size: 1.05rem;
      border: none;
      border-radius: 12px;
      cursor: pointer;
      transition: all 0.3s ease;
      box-shadow: 0 5px 18px rgba(0,0,0,0.25);
    }
    .login-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 28px rgba(0,0,0,0.35);
      background: #f0f0f0;
    }
    .terms {
      margin-top: 24px;
      font-size: 0.83rem;
      color: #777;
      text-align: center;
    }
    .terms a {
      color: #888;
      text-decoration: underline;
    }
    .terms a:hover { color: #aaa; }
    @media (max-width:768px){
      .navbar{flex-wrap:wrap;height:auto;padding:12px 15px;justify-content:center;gap:1rem;}
      .nav-menu{order:2;width:100%;justify-content:center;margin:8px 0;}
      .logo{order:1;flex:1;}
      .nav-right{order:3;width:100%;justify-content:center;}
      .hero-text{font-size: clamp(2.4rem, 6vw, 3.6rem);}
      .hero-subtitle{font-size: clamp(1rem, 2.8vw, 1.3rem);}
      .modal{width:90%;padding:28px 24px;}
      .authy-title{font-size:1.95rem;}
    }
    @media (max-width:480px){
      .hero-text{font-size: clamp(2rem, 5.5vw, 3rem);}
      .hero-subtitle{font-size: clamp(0.95rem, 2.6vw, 1.15rem);}
      .nav-link{font-size:0.95rem;}
      .sign-up-btn{padding:0.55rem 0.9rem;font-size:0.95rem;}
      .logo{font-size:1.25rem;}
      .authy-title{font-size:1.8rem;}
    }
  </style>
</head>
<body>
  <nav class="navbar">
    <div class="logo">
      <i class="fas fa-shield-alt"></i>
      Authy
    </div>
    <div class="nav-menu">
      <a href="#" class="nav-link">Docs</a>
      <a href="/dashboard" class="nav-link">Dashboard</a>
      <a href="#" class="nav-link">Features</a>
      <a href="#" class="nav-link">Pricing</a>
      <a href="#" class="nav-link">FAQ</a>
    </div>
    <div class="nav-right" id="navRight">
      <span class="sign-in" id="openLogin">Sign in</span>
      <button class="sign-up-btn" id="openRegister">Sign up</button>
    </div>
  </nav>

  <section class="hero-section" id="heroSection">
    <div class="hero-text">
      Protect Your Lua <span class="highlight">Scripts</span>
    </div>
    <div class="hero-subtitle">
      The most secure and reliable authentication system for Roblox executors
    </div>
  </section>

  <!-- Login Modal -->
  <div class="modal-overlay" id="loginModal">
    <div class="modal">
      <span class="modal-close" id="closeLoginModal">×</span>
      <h2 class="authy-title">Welcome Back</h2>
      <div class="floating-input">
        <input type="text" id="loginUsername" placeholder="">
        <label for="loginUsername">Username</label>
        <div class="notch-cover"></div>
      </div>
      <div class="floating-input">
        <input type="password" id="loginPassword" placeholder="">
        <label for="loginPassword">Password</label>
        <div class="notch-cover"></div>
      </div>
      <button class="login-btn" id="loginBtn">Log in</button>
      <div class="terms">
        Don't have an account? <a href="#" id="switchToRegister">Sign up</a>
      </div>
    </div>
  </div>

  <!-- Register Modal -->
  <div class="modal-overlay" id="registerModal">
    <div class="modal">
      <span class="modal-close" id="closeRegisterModal">×</span>
      <h2 class="authy-title">Create Account</h2>
      <div class="floating-input">
        <input type="text" id="registerUsername" placeholder="">
        <label for="registerUsername">Username</label>
        <div class="notch-cover"></div>
      </div>
      <div class="floating-input">
        <input type="email" id="registerEmail" placeholder="">
        <label for="registerEmail">Email</label>
        <div class="notch-cover"></div>
      </div>
      <div class="floating-input">
        <input type="password" id="registerPassword" placeholder="">
        <label for="registerPassword">Password</label>
        <div class="notch-cover"></div>
      </div>
      <div class="floating-input">
        <input type="password" id="registerApiKey" placeholder="">
        <label for="registerApiKey">API Key</label>
        <div class="notch-cover"></div>
      </div>
      <button class="login-btn" id="registerBtn">Sign up</button>
      <div class="terms">
        Already have an account? <a href="#" id="switchToLogin">Sign in</a>
      </div>
    </div>
  </div>

  <!-- Toast -->
  <div class="toast" id="toast">
    <div class="toast-content">
      <i class="fas fa-check-circle" id="toastIcon"></i>
      <span id="toastMessage">Notification</span>
    </div>
  </div>

  <style>
    .toast {
      position: fixed;
      bottom: 30px;
      right: 30px;
      background: rgba(21, 23, 30, 0.95);
      backdrop-filter: blur(16px);
      border: 1px solid #2a2f3a;
      border-radius: 12px;
      padding: 15px 25px;
      color: white;
      transform: translateX(400px);
      transition: transform 0.3s ease;
      z-index: 3000;
    }
    .toast.show {
      transform: translateX(0);
    }
    .toast.success {
      border-left: 4px solid #4a90e2;
    }
    .toast.error {
      border-left: 4px solid #ff4b4b;
    }
  </style>

  <script>
    const API_BASE = window.location.origin;
    let token = localStorage.getItem('token');

    // Modal elements
    const loginModal = document.getElementById('loginModal');
    const registerModal = document.getElementById('registerModal');
    const toast = document.getElementById('toast');
    const toastMessage = document.getElementById('toastMessage');
    const toastIcon = document.getElementById('toastIcon');

    function showToast(message, type = 'success') {
      toastMessage.textContent = message;
      toast.className = `toast show ${type}`;
      toastIcon.className = type === 'success' ? 'fas fa-check-circle' : 
                           type === 'error' ? 'fas fa-exclamation-circle' : 
                           'fas fa-info-circle';
      setTimeout(() => toast.classList.remove('show'), 3000);
    }

    async function apiCall(endpoint, method = 'GET', data = null) {
      const headers = {'Content-Type': 'application/json'};
      if (token) headers['Authorization'] = `Bearer ${token}`;
      
      const response = await fetch(`${API_BASE}${endpoint}`, {
        method, headers,
        body: data ? JSON.stringify(data) : null
      });
      
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || 'API call failed');
      return result;
    }

    // Open modals
    document.getElementById('openLogin').onclick = () => {
      loginModal.style.display = 'flex';
      setTimeout(() => loginModal.classList.add('show'), 10);
    };

    document.getElementById('openRegister').onclick = () => {
      registerModal.style.display = 'flex';
      setTimeout(() => registerModal.classList.add('show'), 10);
    };

    // Close modals
    document.getElementById('closeLoginModal').onclick = () => {
      loginModal.classList.remove('show');
      setTimeout(() => loginModal.style.display = 'none', 300);
    };

    document.getElementById('closeRegisterModal').onclick = () => {
      registerModal.classList.remove('show');
      setTimeout(() => registerModal.style.display = 'none', 300);
    };

    // Switch between modals
    document.getElementById('switchToRegister').onclick = (e) => {
      e.preventDefault();
      loginModal.classList.remove('show');
      setTimeout(() => {
        loginModal.style.display = 'none';
        registerModal.style.display = 'flex';
        setTimeout(() => registerModal.classList.add('show'), 10);
      }, 300);
    };

    document.getElementById('switchToLogin').onclick = (e) => {
      e.preventDefault();
      registerModal.classList.remove('show');
      setTimeout(() => {
        registerModal.style.display = 'none';
        loginModal.style.display = 'flex';
        setTimeout(() => loginModal.classList.add('show'), 10);
      }, 300);
    };

    // Login
    document.getElementById('loginBtn').onclick = async () => {
      const username = document.getElementById('loginUsername').value;
      const password = document.getElementById('loginPassword').value;
      
      if (!username || !password) {
        showToast('Please fill in all fields', 'error');
        return;
      }
      
      try {
        const result = await apiCall('/api/auth/login', 'POST', { username, password });
        token = result.access_token;
        localStorage.setItem('token', token);
        
        loginModal.classList.remove('show');
        setTimeout(() => loginModal.style.display = 'none', 300);
        
        showToast('Login successful! Redirecting...');
        setTimeout(() => {
          window.location.href = '/dashboard';
        }, 1000);
      } catch (error) {
        showToast(error.message, 'error');
      }
    };

    // Register
    document.getElementById('registerBtn').onclick = async () => {
      const username = document.getElementById('registerUsername').value;
      const email = document.getElementById('registerEmail').value;
      const password = document.getElementById('registerPassword').value;
      const apiKey = document.getElementById('registerApiKey').value;
      
      if (!username || !email || !password || !apiKey) {
        showToast('Please fill in all fields', 'error');
        return;
      }
      
      try {
        const result = await apiCall('/api/auth/register', 'POST', { 
          username, 
          password, 
          api_key: apiKey 
        });
        token = result.access_token;
        localStorage.setItem('token', token);
        
        registerModal.classList.remove('show');
        setTimeout(() => registerModal.style.display = 'none', 300);
        
        showToast('Registration successful! Redirecting...');
        setTimeout(() => {
          window.location.href = '/dashboard';
        }, 1000);
      } catch (error) {
        showToast(error.message, 'error');
      }
    };

    // Check if already logged in
    if (token) {
      window.location.href = '/dashboard';
    }
  </script>
</body>
</html>
"""

# ========== DASHBOARD TEMPLATE (Full dashboard from previous response) ==========
# For brevity, I'm referencing that the full dashboard HTML from previous response goes here
# In your actual implementation, paste the ENTIRE dashboard HTML from the previous response here

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authy Dashboard</title>
    <!-- Full dashboard HTML from previous response goes here -->
    <!-- Paste the ENTIRE dashboard HTML that I provided in the previous response -->
</head>
<body>
    <!-- Dashboard content -->
</body>
</html>
"""

# ========== FRONTEND ROUTES ==========
@app.get("/", response_class=HTMLResponse)
async def serve_homepage():
    """Serve the original beautiful homepage"""
    return HOMEPAGE_TEMPLATE

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the dashboard (requires login)"""
    # In a real implementation, you'd check token here
    # For now, just serve the dashboard template
    return DASHBOARD_TEMPLATE

@app.get("/{full_path:path}", response_class=HTMLResponse)
async def catch_all(full_path: str):
    """Catch all routes - redirect to homepage"""
    return HOMEPAGE_TEMPLATE

# ========== RUN ==========
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
