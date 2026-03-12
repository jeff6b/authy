import os
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
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
MASTER_API_KEY = "123"  # Hardcoded for now

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
    """Initialize database tables with correct schema"""
    if not self.pool:
        print("⚠️ Cannot init DB - no connection pool")
        return
        
    try:
        async with self.pool.acquire() as conn:
            print("🔄 Recreating database tables with correct schema...")
            
            # Drop existing tables in correct order (due to foreign keys)
            await conn.execute('DROP TABLE IF EXISTS heartbeat_logs CASCADE')
            await conn.execute('DROP TABLE IF EXISTS keys CASCADE')
            await conn.execute('DROP TABLE IF EXISTS scripts CASCADE')
            await conn.execute('DROP TABLE IF EXISTS users CASCADE')
            print("✅ Dropped existing tables")
            
            # Users table
            await conn.execute('''
                CREATE TABLE users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_admin BOOLEAN DEFAULT FALSE
                )
            ''')
            print("✅ Users table ready")
            
            # Scripts table
            await conn.execute('''
                CREATE TABLE scripts (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(name, user_id)
                )
            ''')
            print("✅ Scripts table ready")
            
            # Keys table (with script_id foreign key)
            await conn.execute('''
                CREATE TABLE keys (
                    id SERIAL PRIMARY KEY,
                    key TEXT UNIQUE NOT NULL,
                    script_id INTEGER NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
                    nickname TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    last_heartbeat TIMESTAMP,
                    hwid TEXT,
                    status TEXT DEFAULT 'active',
                    max_hwid_resets INTEGER DEFAULT 3,
                    hwid_resets_used INTEGER DEFAULT 0,
                    note TEXT
                )
            ''')
            print("✅ Keys table ready with script_id column")
            
            # Heartbeat logs table
            await conn.execute('''
                CREATE TABLE heartbeat_logs (
                    id SERIAL PRIMARY KEY,
                    key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    hwid TEXT NOT NULL,
                    ip_address TEXT
                )
            ''')
            print("✅ Heartbeat logs table ready")
            
            # Create indexes for performance
            await conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key)')
            await conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_script_id ON keys(script_id)')
            await conn.execute('CREATE INDEX IF NOT EXISTS idx_scripts_user_id ON scripts(user_id)')
            await conn.execute('CREATE INDEX IF NOT EXISTS idx_heartbeat_key_id ON heartbeat_logs(key_id)')
            await conn.execute('CREATE INDEX IF NOT EXISTS idx_heartbeat_timestamp ON heartbeat_logs(timestamp)')
            
            print("✅ Database tables recreated successfully!")
            
    except Exception as e:
        print(f"❌ Failed to initialize tables: {e}")
        import traceback
        traceback.print_exc()

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

class ScriptResponse(BaseModel):
    id: int
    name: str
    created_at: str
    key_count: int
    active_keys: int

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
    expires_at: Optional[str] = None

class HWIDResetRequest(BaseModel):
    key: str
    confirm: bool = False

# ========== AUTH ENDPOINTS ==========
@app.post("/api/auth/register", response_model=TokenResponse)
async def register(user: UserCreate):
    """Register a new user using API key"""
    print(f"📝 Register attempt: {user.username}")
    
    # Check API key
    if user.api_key != MASTER_API_KEY:
        print(f"❌ Invalid API key: {user.api_key}")
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        async with db.pool.acquire() as conn:
            # Check if user exists
            existing = await conn.fetchval(
                "SELECT id FROM users WHERE username = $1 OR email = $2",
                user.username, f"{user.username}@placeholder.com"
            )
            
            if existing:
                raise HTTPException(status_code=400, detail="Username already taken")
            
            # Create user with placeholder email
            hashed = hash_password(user.password)
            
            user_id = await conn.fetchval(
                "INSERT INTO users (username, password_hash, email) VALUES ($1, $2, $3) RETURNING id",
                user.username, hashed, f"{user.username}@authy.local"
            )
            
            # Create token
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
            
            if not db_user:
                print(f"❌ User not found: {user.username}")
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            if not verify_password(user.password, db_user['password_hash']):
                print(f"❌ Invalid password for: {user.username}")
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
    """Create a new script"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        # Check if script name already exists for this user
        existing = await conn.fetchval(
            "SELECT id FROM scripts WHERE name = $1 AND user_id = $2",
            script_data.name, current_user['id']
        )
        
        if existing:
            raise HTTPException(status_code=400, detail="Script name already exists")
        
        script_id = await conn.fetchval(
            "INSERT INTO scripts (name, user_id) VALUES ($1, $2) RETURNING id",
            script_data.name, current_user['id']
        )
        
        return {
            "id": script_id,
            "name": script_data.name,
            "message": "Script created successfully"
        }

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
                "created_at": script['created_at'].isoformat(),
                "key_count": script['key_count'],
                "active_keys": script['active_keys']
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
        expires_at = datetime.now() + timedelta(days=key_data.duration_days)
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
            SELECT k.*, s.name as script_name
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
                "created_at": key['created_at'].isoformat() if key['created_at'] else None,
                "expires_at": key['expires_at'].isoformat() if key['expires_at'] else None,
                "last_heartbeat": key['last_heartbeat'].isoformat() if key['last_heartbeat'] else None,
                "hwid": key['hwid'],
                "status": key['status'],
                "online": online,
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
        # Verify key belongs to user
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
                "UPDATE keys SET status = 'active' WHERE key = $1",
                action.key
            )
            return {"success": True, "message": "Key activated"}
            
        elif action.action == "deactivate":
            await conn.execute(
                "UPDATE keys SET status = 'suspended' WHERE key = $1",
                action.key
            )
            return {"success": True, "message": "Key deactivated"}
            
        elif action.action == "kick":
            # Just log that they were kicked - next heartbeat will fail
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
        # Verify key belongs to user
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
            "UPDATE keys SET hwid = NULL, hwid_resets_used = hwid_resets_used + 1 WHERE key = $1",
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
        # Total scripts
        total_scripts = await conn.fetchval(
            "SELECT COUNT(*) FROM scripts WHERE user_id = $1",
            current_user['id']
        )
        
        # Total keys
        total_keys = await conn.fetchval(
            """
            SELECT COUNT(*) FROM keys k
            JOIN scripts s ON k.script_id = s.id
            WHERE s.user_id = $1
            """,
            current_user['id']
        )
        
        # Active keys
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
        
        # Online now
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
        
        # Expiring soon
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
    """Generate a loader for a script"""
    script_id = data.get('script_id')
    
    if not script_id:
        raise HTTPException(status_code=400, detail="Script ID required")
    
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        # Verify script belongs to user
        script = await conn.fetchrow(
            "SELECT * FROM scripts WHERE id = $1 AND user_id = $2",
            script_id, current_user['id']
        )
        
        if not script:
            raise HTTPException(status_code=404, detail="Script not found")
        
        # Generate loader code
        loader = f'''-- =============================================
-- AUTHY LOADER FOR: {script['name']}
-- GENERATED: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
-- =============================================

local AUTH_URL = "https://authy-o0pm.onrender.com"
local API_BASE = AUTH_URL

-- Get HWID using executor's gethwid()
local function get_hwid()
    local hwid = gethwid and gethwid()
    if not hwid then
        -- Fallback for testing
        hwid = "TEST-HWID-123456"
    end
    return hwid
end

-- HTTP request function
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

-- Validate key function
local function validate_key(key, hwid)
    local response = request_api("/api/validate", {{
        key = key,
        hwid = hwid
    }})
    
    return response.valid, response
end

-- Heartbeat function
local function send_heartbeat(key, hwid)
    local response = request_api("/api/heartbeat", {{
        key = key,
        hwid = hwid
    }})
    return response.valid, response
end

-- Main authentication function
local function authenticate(key)
    local hwid = get_hwid()
    print("🔑 HWID: " .. hwid)
    
    -- Validate key
    local valid, response = validate_key(key, hwid)
    
    if not valid then
        print("❌ Authentication failed: " .. (response.reason or "unknown error"))
        return false
    end
    
    print("✅ Authentication successful!")
    if response.expires then
        print("📅 Expires: " .. response.expires)
    end
    
    -- Start heartbeat loop
    spawn(function()
        while wait(60) do
            local valid, hb_response = send_heartbeat(key, hwid)
            if not valid then
                print("❌ License invalidated: " .. (hb_response.message or "unknown"))
                return
            end
            print("💓 Heartbeat OK")
        end
    end)
    
    return true
end

-- ========== YOUR SCRIPT BELOW ==========
-- PASTE YOUR SCRIPT AFTER THIS LINE
-- The key will be provided by your main script

-- Example:
-- local success = authenticate("YOUR-KEY-HERE")
-- if success then
--     print("🚀 Loading script...")
--     -- Your actual script code here
-- end

return {{
    authenticate = authenticate,
    get_hwid = get_hwid,
    validate = validate_key
}}
'''
        
        return {
            "loader": loader,
            "script_name": script['name'],
            "instructions": "Copy this loader and paste it at the bottom of your script. The user will need to provide their key."
        }

# ========== PUBLIC API ENDPOINTS ==========
@app.post("/api/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(request: HeartbeatRequest, req: Request):
    """Lua clients call this every 60 seconds"""
    if not db.pool:
        return HeartbeatResponse(
            valid=False, 
            status="error", 
            message="Database not available"
        )
    
    async with db.pool.acquire() as conn:
        # Get key
        key_info = await conn.fetchrow(
            "SELECT * FROM keys WHERE key = $1",
            request.key
        )
        
        if not key_info:
            return HeartbeatResponse(
                valid=False, 
                status="invalid", 
                message="Key not found"
            )
        
        key_info = dict(key_info)
        expires_at = key_info['expires_at']
        
        # Check if expired
        if expires_at < datetime.now():
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
        
        days_left = (expires_at - datetime.now()).days
        
        return HeartbeatResponse(
            valid=True, 
            status="active", 
            message=f"Valid - {days_left} days remaining",
            expires_at=expires_at.isoformat()
        )

@app.post("/api/validate")
async def validate_key(request: HeartbeatRequest):
    """Simple validation without heartbeat logging"""
    if not db.pool:
        return {"valid": False, "reason": "database_error"}
    
    async with db.pool.acquire() as conn:
        key_info = await conn.fetchrow(
            "SELECT * FROM keys WHERE key = $1",
            request.key
        )
        
        if not key_info:
            return {"valid": False, "reason": "not_found"}
        
        key_info = dict(key_info)
        
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
            "expires": key_info['expires_at'].isoformat()
        }

# ========== FRONTEND ==========
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authy - Advanced Lua Authentication</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg-primary: #0A0C10;
            --bg-secondary: #12141A;
            --bg-tertiary: #1A1E26;
            --accent-primary: #3B82F6;
            --accent-secondary: #6366F1;
            --accent-success: #10B981;
            --accent-warning: #F59E0B;
            --accent-danger: #EF4444;
            --text-primary: #FFFFFF;
            --text-secondary: #9CA3AF;
            --text-muted: #6B7280;
            --border-color: #2A2F3A;
            --gradient-primary: linear-gradient(135deg, #3B82F6 0%, #6366F1 100%);
            --gradient-success: linear-gradient(135deg, #10B981 0%, #059669 100%);
            --gradient-warning: linear-gradient(135deg, #F59E0B 0%, #D97706 100%);
            --gradient-danger: linear-gradient(135deg, #EF4444 0%, #DC2626 100%);
            --shadow-sm: 0 2px 4px rgba(0,0,0,0.1);
            --shadow-md: 0 4px 6px rgba(0,0,0,0.1);
            --shadow-lg: 0 10px 15px rgba(0,0,0,0.2);
            --shadow-xl: 0 20px 25px rgba(0,0,0,0.25);
            --blur-bg: rgba(10, 12, 16, 0.7);
        }

        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.5;
            position: relative;
        }

        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: 
                radial-gradient(circle at 20% 20%, rgba(59, 130, 246, 0.05) 0%, transparent 30%),
                radial-gradient(circle at 80% 70%, rgba(99, 102, 241, 0.05) 0%, transparent 30%),
                radial-gradient(circle at 40% 90%, rgba(16, 185, 129, 0.03) 0%, transparent 40%);
            pointer-events: none;
            z-index: -1;
        }

        /* Navbar */
        .navbar {
            position: fixed;
            top: 20px;
            left: 50%;
            transform: translateX(-50%);
            width: 90%;
            max-width: 1400px;
            height: 70px;
            background: rgba(18, 20, 26, 0.8);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 30px;
            z-index: 1000;
            box-shadow: var(--shadow-lg);
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 1.5rem;
            font-weight: 800;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .logo i {
            font-size: 2rem;
        }

        .nav-links {
            display: flex;
            gap: 40px;
        }

        .nav-link {
            color: var(--text-secondary);
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s ease;
            position: relative;
        }

        .nav-link:hover {
            color: var(--text-primary);
        }

        .nav-link::after {
            content: '';
            position: absolute;
            bottom: -4px;
            left: 0;
            width: 0;
            height: 2px;
            background: var(--gradient-primary);
            transition: width 0.3s ease;
        }

        .nav-link:hover::after {
            width: 100%;
        }

        .nav-user {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .user-menu {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 16px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .user-menu:hover {
            border-color: var(--accent-primary);
        }

        .username {
            font-weight: 600;
            color: var(--text-primary);
        }

        .btn-logout {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            width: 40px;
            height: 40px;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .btn-logout:hover {
            border-color: var(--accent-danger);
            color: var(--accent-danger);
        }

        /* Main Content */
        .main-content {
            padding: 120px 30px 40px;
            max-width: 1400px;
            margin: 0 auto;
        }

        /* Auth Container */
        .auth-container {
            min-height: calc(100vh - 200px);
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .auth-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 24px;
            padding: 50px;
            width: 100%;
            max-width: 480px;
            box-shadow: var(--shadow-xl);
            position: relative;
            overflow: hidden;
        }

        .auth-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--gradient-primary);
        }

        .auth-header {
            text-align: center;
            margin-bottom: 40px;
        }

        .auth-header i {
            font-size: 3rem;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 20px;
        }

        .auth-header h2 {
            font-size: 2rem;
            margin-bottom: 10px;
        }

        .auth-header p {
            color: var(--text-secondary);
        }

        .auth-tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
            background: var(--bg-tertiary);
            padding: 5px;
            border-radius: 12px;
        }

        .tab-btn {
            flex: 1;
            padding: 12px;
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-weight: 600;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .tab-btn.active {
            background: var(--accent-primary);
            color: white;
        }

        .auth-form {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }

        .auth-form.hidden {
            display: none;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .form-group label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            font-weight: 500;
        }

        .form-group input {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 14px 16px;
            color: var(--text-primary);
            font-size: 1rem;
            transition: all 0.3s ease;
        }

        .form-group input:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }

        .btn-primary {
            background: var(--gradient-primary);
            border: none;
            padding: 14px;
            border-radius: 12px;
            color: white;
            font-weight: 600;
            font-size: 1rem;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(59, 130, 246, 0.3);
        }

        .btn-secondary {
            background: transparent;
            border: 1px solid var(--border-color);
            padding: 12px 24px;
            border-radius: 10px;
            color: var(--text-primary);
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .btn-secondary:hover {
            background: var(--bg-tertiary);
            border-color: var(--accent-primary);
        }

        .btn-danger {
            background: var(--gradient-danger);
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .btn-danger:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(239, 68, 68, 0.3);
        }

        .btn-success {
            background: var(--gradient-success);
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .btn-success:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(16, 185, 129, 0.3);
        }

        .btn-warning {
            background: var(--gradient-warning);
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            color: white;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .btn-warning:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(245, 158, 11, 0.3);
        }

        .btn-icon {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            width: 36px;
            height: 36px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            justify-content: center;
        }

        .btn-icon:hover {
            border-color: var(--accent-primary);
            color: var(--accent-primary);
        }

        /* Dashboard */
        .dashboard-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }

        .dashboard-header h1 {
            font-size: 2.5rem;
            font-weight: 700;
        }

        .dashboard-header h1 span {
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 24px;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--gradient-primary);
            opacity: 0;
            transition: opacity 0.3s ease;
        }

        .stat-card:hover::before {
            opacity: 1;
        }

        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-xl);
        }

        .stat-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }

        .stat-title {
            color: var(--text-secondary);
            font-size: 0.95rem;
            font-weight: 500;
        }

        .stat-icon {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
        }

        .stat-icon.blue {
            background: rgba(59, 130, 246, 0.1);
            color: var(--accent-primary);
        }

        .stat-icon.green {
            background: rgba(16, 185, 129, 0.1);
            color: var(--accent-success);
        }

        .stat-icon.purple {
            background: rgba(99, 102, 241, 0.1);
            color: var(--accent-secondary);
        }

        .stat-icon.orange {
            background: rgba(245, 158, 11, 0.1);
            color: var(--accent-warning);
        }

        .stat-value {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 8px;
        }

        .stat-change {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .stat-change.positive {
            color: var(--accent-success);
        }

        .stat-change.negative {
            color: var(--accent-danger);
        }

        /* Charts */
        .charts-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }

        .chart-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 24px;
        }

        .chart-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .chart-header h3 {
            font-size: 1.2rem;
            font-weight: 600;
        }

        .chart-container {
            height: 300px;
        }

        /* Scripts Section */
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .section-header h2 {
            font-size: 1.5rem;
            font-weight: 600;
        }

        .scripts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }

        .script-card {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 24px;
            transition: all 0.3s ease;
        }

        .script-card:hover {
            border-color: var(--accent-primary);
            box-shadow: var(--shadow-lg);
        }

        .script-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }

        .script-name {
            font-size: 1.3rem;
            font-weight: 600;
        }

        .script-badge {
            background: rgba(59, 130, 246, 0.1);
            color: var(--accent-primary);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
        }

        .script-stats {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
            padding: 16px 0;
            border-top: 1px solid var(--border-color);
            border-bottom: 1px solid var(--border-color);
        }

        .script-stat {
            flex: 1;
        }

        .script-stat-label {
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-bottom: 4px;
        }

        .script-stat-value {
            font-size: 1.2rem;
            font-weight: 600;
        }

        .script-actions {
            display: flex;
            gap: 10px;
        }

        .script-actions button {
            flex: 1;
        }

        /* Keys Table */
        .keys-table-container {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            padding: 24px;
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th {
            text-align: left;
            padding: 16px;
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 0.9rem;
            border-bottom: 1px solid var(--border-color);
        }

        td {
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
        }

        tr:hover td {
            background: var(--bg-tertiary);
        }

        .key-cell {
            font-family: monospace;
            font-size: 0.95rem;
        }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
        }

        .status-badge.active {
            background: rgba(16, 185, 129, 0.1);
            color: var(--accent-success);
        }

        .status-badge.inactive {
            background: rgba(239, 68, 68, 0.1);
            color: var(--accent-danger);
        }

        .status-badge.expired {
            background: rgba(107, 114, 128, 0.1);
            color: var(--text-secondary);
        }

        .status-badge.online {
            background: rgba(59, 130, 246, 0.1);
            color: var(--accent-primary);
        }

        .status-badge::before {
            content: '';
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
        }

        .status-badge.active::before {
            background: var(--accent-success);
        }

        .status-badge.inactive::before {
            background: var(--accent-danger);
        }

        .status-badge.expired::before {
            background: var(--text-secondary);
        }

        .status-badge.online::before {
            background: var(--accent-primary);
        }

        .action-group {
            display: flex;
            gap: 6px;
        }

        /* Modal */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(8px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 2000;
        }

        .modal-overlay.show {
            display: flex;
        }

        .modal {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 24px;
            width: 90%;
            max-width: 500px;
            animation: modalSlide 0.3s ease;
        }

        @keyframes modalSlide {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .modal-header {
            padding: 24px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-header h3 {
            font-size: 1.3rem;
            font-weight: 600;
        }

        .modal-close {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-size: 1.5rem;
            cursor: pointer;
            transition: color 0.3s ease;
        }

        .modal-close:hover {
            color: var(--text-primary);
        }

        .modal-body {
            padding: 24px;
        }

        .modal-footer {
            padding: 24px;
            border-top: 1px solid var(--border-color);
            display: flex;
            justify-content: flex-end;
            gap: 12px;
        }

        /* Loader Preview */
        .loader-preview {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 16px;
            margin: 20px 0;
            max-height: 400px;
            overflow-y: auto;
        }

        .loader-preview pre {
            color: var(--text-primary);
            font-family: monospace;
            font-size: 0.9rem;
            line-height: 1.6;
            white-space: pre-wrap;
        }

        /* Toast */
        .toast {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 16px 24px;
            transform: translateX(400px);
            transition: transform 0.3s ease;
            z-index: 3000;
            box-shadow: var(--shadow-xl);
        }

        .toast.show {
            transform: translateX(0);
        }

        .toast-content {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .toast.success {
            border-left: 4px solid var(--accent-success);
        }

        .toast.error {
            border-left: 4px solid var(--accent-danger);
        }

        .toast.info {
            border-left: 4px solid var(--accent-primary);
        }

        /* Utility */
        .hidden {
            display: none !important;
        }

        .loader {
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
        }

        .loader i {
            font-size: 2rem;
            margin-bottom: 16px;
        }

        @media (max-width: 768px) {
            .navbar {
                width: 95%;
                padding: 0 20px;
            }

            .nav-links {
                display: none;
            }

            .charts-grid {
                grid-template-columns: 1fr;
            }

            .scripts-grid {
                grid-template-columns: 1fr;
            }

            .dashboard-header {
                flex-direction: column;
                gap: 20px;
                align-items: flex-start;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="logo">
            <i class="fas fa-shield-alt"></i>
            Authy
        </div>
        <div class="nav-links" id="navLinks">
            <a href="#" class="nav-link">Dashboard</a>
            <a href="#" class="nav-link">Scripts</a>
            <a href="#" class="nav-link">Keys</a>
            <a href="#" class="nav-link">Analytics</a>
            <a href="#" class="nav-link">Docs</a>
        </div>
        <div class="nav-user" id="navUser">
            <div class="user-menu" id="userMenu">
                <i class="fas fa-user-circle"></i>
                <span class="username" id="usernameDisplay">Guest</span>
                <i class="fas fa-chevron-down"></i>
            </div>
            <button class="btn-logout" id="logoutBtn">
                <i class="fas fa-sign-out-alt"></i>
            </button>
        </div>
    </nav>

    <div class="main-content" id="mainContent">
        <!-- Auth Container -->
        <div class="auth-container" id="authContainer">
            <div class="auth-card">
                <div class="auth-header">
                    <i class="fas fa-shield-alt"></i>
                    <h2>Welcome to Authy</h2>
                    <p>Advanced Lua Authentication System</p>
                </div>
                <div class="auth-tabs">
                    <button class="tab-btn active" id="loginTab">Login</button>
                    <button class="tab-btn" id="registerTab">Register</button>
                </div>
                <div class="auth-form" id="loginForm">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" id="loginUsername" placeholder="Enter your username">
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" id="loginPassword" placeholder="Enter your password">
                    </div>
                    <button class="btn-primary" id="loginBtn">
                        <i class="fas fa-sign-in-alt"></i>
                        Login
                    </button>
                </div>
                <div class="auth-form hidden" id="registerForm">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" id="registerUsername" placeholder="Choose a username">
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" id="registerPassword" placeholder="Choose a password">
                    </div>
                    <div class="form-group">
                        <label>API Key</label>
                        <input type="password" id="registerApiKey" placeholder="Enter API key">
                    </div>
                    <button class="btn-primary" id="registerBtn">
                        <i class="fas fa-user-plus"></i>
                        Register
                    </button>
                </div>
            </div>
        </div>

        <!-- Dashboard Container -->
        <div class="dashboard-container hidden" id="dashboardContainer">
            <div class="dashboard-header">
                <h1>Welcome back, <span id="dashboardUsername">User</span></h1>
                <button class="btn-primary" id="createScriptBtn">
                    <i class="fas fa-plus"></i>
                    New Script
                </button>
            </div>

            <!-- Stats Grid -->
            <div class="stats-grid" id="statsGrid">
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-title">Total Scripts</span>
                        <div class="stat-icon blue">
                            <i class="fas fa-code"></i>
                        </div>
                    </div>
                    <div class="stat-value" id="totalScripts">0</div>
                    <div class="stat-change">Active projects</div>
                </div>
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-title">Total Keys</span>
                        <div class="stat-icon purple">
                            <i class="fas fa-key"></i>
                        </div>
                    </div>
                    <div class="stat-value" id="totalKeys">0</div>
                    <div class="stat-change">All time</div>
                </div>
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-title">Active Keys</span>
                        <div class="stat-icon green">
                            <i class="fas fa-check-circle"></i>
                        </div>
                    </div>
                    <div class="stat-value" id="activeKeys">0</div>
                    <div class="stat-change positive">+12% this week</div>
                </div>
                <div class="stat-card">
                    <div class="stat-header">
                        <span class="stat-title">Online Now</span>
                        <div class="stat-icon orange">
                            <i class="fas fa-wifi"></i>
                        </div>
                    </div>
                    <div class="stat-value" id="onlineNow">0</div>
                    <div class="stat-change">Currently active</div>
                </div>
            </div>

            <!-- Charts -->
            <div class="charts-grid">
                <div class="chart-card">
                    <div class="chart-header">
                        <h3>Key Activity (Last 7 Days)</h3>
                        <select class="btn-secondary" id="activityRange" style="width: auto; padding: 8px;">
                            <option>Daily</option>
                            <option>Weekly</option>
                            <option>Monthly</option>
                        </select>
                    </div>
                    <div class="chart-container">
                        <canvas id="activityChart"></canvas>
                    </div>
                </div>
                <div class="chart-card">
                    <div class="chart-header">
                        <h3>Key Distribution</h3>
                    </div>
                    <div class="chart-container">
                        <canvas id="distributionChart"></canvas>
                    </div>
                </div>
            </div>

            <!-- Scripts Section -->
            <div class="section-header">
                <h2>Your Scripts</h2>
            </div>
            <div class="scripts-grid" id="scriptsGrid">
                <div class="loader">
                    <i class="fas fa-spinner fa-spin"></i>
                    <p>Loading scripts...</p>
                </div>
            </div>

            <!-- Keys Table -->
            <div class="section-header">
                <h2>Recent Keys</h2>
                <button class="btn-secondary" id="viewAllKeysBtn">
                    View All
                </button>
            </div>
            <div class="keys-table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Key</th>
                            <th>Nickname</th>
                            <th>Script</th>
                            <th>Status</th>
                            <th>HWID</th>
                            <th>Expires</th>
                            <th>Last Seen</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="keysBody">
                        <tr>
                            <td colspan="8" style="text-align: center; padding: 40px;">
                                <i class="fas fa-key" style="font-size: 2rem; opacity: 0.5; margin-bottom: 10px;"></i>
                                <p>No keys yet. Create a script and generate keys!</p>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Create Script Modal -->
    <div class="modal-overlay" id="createScriptModal">
        <div class="modal">
            <div class="modal-header">
                <h3>Create New Script</h3>
                <button class="modal-close" id="closeScriptModal">&times;</button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label>Script Name</label>
                    <input type="text" id="scriptName" placeholder="e.g., 'Lua Executor' or 'DarkHub'">
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn-secondary" id="cancelScriptBtn">Cancel</button>
                <button class="btn-primary" id="createScriptSubmit">
                    <i class="fas fa-plus"></i>
                    Create Script
                </button>
            </div>
        </div>
    </div>

    <!-- Create Key Modal -->
    <div class="modal-overlay" id="createKeyModal">
        <div class="modal">
            <div class="modal-header">
                <h3>Generate New Key</h3>
                <button class="modal-close" id="closeKeyModal">&times;</button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label>Select Script</label>
                    <select id="keyScriptSelect" class="btn-secondary" style="width: 100%; padding: 12px;">
                        <option value="">Loading scripts...</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Nickname (optional)</label>
                    <input type="text" id="keyNickname" placeholder="e.g., 'VIP User' or 'Test Key'">
                </div>
                <div class="form-group">
                    <label>Duration</label>
                    <select id="keyDuration" class="btn-secondary" style="width: 100%; padding: 12px;">
                        <option value="7">7 days</option>
                        <option value="30" selected>30 days</option>
                        <option value="90">90 days</option>
                        <option value="365">1 year</option>
                        <option value="0">Lifetime</option>
                    </select>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn-secondary" id="cancelKeyBtn">Cancel</button>
                <button class="btn-primary" id="createKeySubmit">
                    <i class="fas fa-key"></i>
                    Generate Key
                </button>
            </div>
        </div>
    </div>

    <!-- View Keys Modal -->
    <div class="modal-overlay" id="viewKeysModal">
        <div class="modal" style="max-width: 800px;">
            <div class="modal-header">
                <h3 id="viewKeysTitle">Keys for Script</h3>
                <button class="modal-close" id="closeViewKeysModal">&times;</button>
            </div>
            <div class="modal-body">
                <div class="keys-table-container" style="max-height: 400px; overflow-y: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>Key</th>
                                <th>Nickname</th>
                                <th>Status</th>
                                <th>HWID</th>
                                <th>Expires</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="modalKeysBody">
                            <tr>
                                <td colspan="6" style="text-align: center; padding: 20px;">Loading...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn-primary" id="generateKeyFromModal">
                    <i class="fas fa-plus"></i>
                    New Key
                </button>
                <button class="btn-secondary" id="closeViewKeysBtn">Close</button>
            </div>
        </div>
    </div>

    <!-- Generate Loader Modal -->
    <div class="modal-overlay" id="loaderModal">
        <div class="modal" style="max-width: 700px;">
            <div class="modal-header">
                <h3>Loader Generated</h3>
                <button class="modal-close" id="closeLoaderModal">&times;</button>
            </div>
            <div class="modal-body">
                <p>Copy this loader and paste it at the <strong>bottom</strong> of your script:</p>
                <div class="loader-preview">
                    <pre id="loaderCode">Loading...</pre>
                </div>
                <p class="text-secondary" style="margin-top: 10px;">
                    <i class="fas fa-info-circle"></i>
                    The user will need to provide their key. Use <code>authenticate("KEY-HERE")</code> in your script.
                </p>
            </div>
            <div class="modal-footer">
                <button class="btn-primary" id="copyLoaderBtn">
                    <i class="fas fa-copy"></i>
                    Copy to Clipboard
                </button>
                <button class="btn-secondary" id="closeLoaderBtn">Close</button>
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

    <script src="https://kit.fontawesome.com/your-kit.js" crossorigin="anonymous"></script>
    <script>
        // API Configuration
        const API_BASE = window.location.origin;
        let token = localStorage.getItem('token');
        let currentUser = null;
        let activityChart = null;
        let distributionChart = null;

        // DOM Elements
        const authContainer = document.getElementById('authContainer');
        const dashboardContainer = document.getElementById('dashboardContainer');
        const usernameDisplay = document.getElementById('usernameDisplay');
        const dashboardUsername = document.getElementById('dashboardUsername');
        const logoutBtn = document.getElementById('logoutBtn');
        const loginTab = document.getElementById('loginTab');
        const registerTab = document.getElementById('registerTab');
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        const loginBtn = document.getElementById('loginBtn');
        const registerBtn = document.getElementById('registerBtn');
        const toast = document.getElementById('toast');
        const toastMessage = document.getElementById('toastMessage');
        const toastIcon = document.getElementById('toastIcon');

        // Modal elements
        const createScriptModal = document.getElementById('createScriptModal');
        const createKeyModal = document.getElementById('createKeyModal');
        const viewKeysModal = document.getElementById('viewKeysModal');
        const loaderModal = document.getElementById('loaderModal');

        // ========== UTILITY FUNCTIONS ==========
        function showToast(message, type = 'success') {
            toastMessage.textContent = message;
            toast.className = `toast show ${type}`;
            toastIcon.className = type === 'success' ? 'fas fa-check-circle' : 
                                 type === 'error' ? 'fas fa-exclamation-circle' : 
                                 'fas fa-info-circle';
            
            setTimeout(() => {
                toast.classList.remove('show');
            }, 3000);
        }

        async function apiCall(endpoint, method = 'GET', data = null) {
            const headers = {
                'Content-Type': 'application/json'
            };
            
            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }
            
            const response = await fetch(`${API_BASE}${endpoint}`, {
                method,
                headers,
                body: data ? JSON.stringify(data) : null
            });
            
            const contentType = response.headers.get('content-type');
            if (!contentType || !contentType.includes('application/json')) {
                const text = await response.text();
                console.error('Non-JSON response:', text.substring(0, 200));
                throw new Error('Server error');
            }
            
            const result = await response.json();
            if (!response.ok) {
                throw new Error(result.detail || 'API call failed');
            }
            return result;
        }

        // ========== AUTH FUNCTIONS ==========
        async function loadDashboard() {
            try {
                currentUser = await apiCall('/api/user/me');
                usernameDisplay.textContent = currentUser.username;
                dashboardUsername.textContent = currentUser.username;
                
                await Promise.all([
                    loadStats(),
                    loadScripts(),
                    loadKeys()
                ]);
                
                initCharts();
                
                authContainer.classList.add('hidden');
                dashboardContainer.classList.remove('hidden');
            } catch (error) {
                console.error('Failed to load dashboard:', error);
                logout();
            }
        }

        async function loadStats() {
            try {
                const stats = await apiCall('/api/stats');
                document.getElementById('totalScripts').textContent = stats.total_scripts;
                document.getElementById('totalKeys').textContent = stats.total_keys;
                document.getElementById('activeKeys').textContent = stats.active_keys;
                document.getElementById('onlineNow').textContent = stats.online_now;
            } catch (error) {
                console.error('Failed to load stats:', error);
            }
        }

        async function loadScripts() {
            try {
                const scripts = await apiCall('/api/scripts');
                const grid = document.getElementById('scriptsGrid');
                
                if (scripts.length === 0) {
                    grid.innerHTML = `
                        <div style="grid-column: 1/-1; text-align: center; padding: 60px;">
                            <i class="fas fa-code" style="font-size: 3rem; opacity: 0.5; margin-bottom: 20px;"></i>
                            <h3>No scripts yet</h3>
                            <p style="color: var(--text-secondary); margin-bottom: 20px;">Create your first script to get started</p>
                            <button class="btn-primary" onclick="document.getElementById('createScriptBtn').click()">
                                <i class="fas fa-plus"></i>
                                Create Script
                            </button>
                        </div>
                    `;
                    return;
                }
                
                grid.innerHTML = scripts.map(script => `
                    <div class="script-card">
                        <div class="script-header">
                            <span class="script-name">${script.name}</span>
                            <span class="script-badge">ID: ${script.id}</span>
                        </div>
                        <div class="script-stats">
                            <div class="script-stat">
                                <div class="script-stat-label">Total Keys</div>
                                <div class="script-stat-value">${script.key_count}</div>
                            </div>
                            <div class="script-stat">
                                <div class="script-stat-label">Active</div>
                                <div class="script-stat-value">${script.active_keys}</div>
                            </div>
                            <div class="script-stat">
                                <div class="script-stat-label">Created</div>
                                <div class="script-stat-value">${new Date(script.created_at).toLocaleDateString()}</div>
                            </div>
                        </div>
                        <div class="script-actions">
                            <button class="btn-success" onclick="showGenerateKeyModal(${script.id}, '${script.name}')">
                                <i class="fas fa-plus"></i>
                                Key
                            </button>
                            <button class="btn-primary" onclick="generateLoader(${script.id})">
                                <i class="fas fa-download"></i>
                                Loader
                            </button>
                            <button class="btn-secondary" onclick="viewScriptKeys(${script.id}, '${script.name}')">
                                <i class="fas fa-eye"></i>
                                View
                            </button>
                        </div>
                    </div>
                `).join('');
            } catch (error) {
                console.error('Failed to load scripts:', error);
            }
        }

        async function loadKeys() {
            try {
                const keys = await apiCall('/api/keys');
                const tbody = document.getElementById('keysBody');
                
                if (keys.length === 0) {
                    tbody.innerHTML = `
                        <tr>
                            <td colspan="8" style="text-align: center; padding: 40px;">
                                <i class="fas fa-key" style="font-size: 2rem; opacity: 0.5; margin-bottom: 10px;"></i>
                                <p>No keys yet. Create a script and generate keys!</p>
                            </td>
                        </tr>
                    `;
                    return;
                }
                
                tbody.innerHTML = keys.slice(0, 5).map(key => {
                    const statusClass = key.online ? 'online' : (key.status === 'active' ? 'active' : 'inactive');
                    const statusText = key.online ? 'ONLINE' : (key.status === 'active' ? 'ACTIVE' : 'INACTIVE');
                    
                    return `
                        <tr>
                            <td class="key-cell">${key.key}</td>
                            <td>${key.nickname || '-'}</td>
                            <td>${key.script_name}</td>
                            <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                            <td>${key.hwid ? key.hwid.substring(0, 8) + '...' : 'Not bound'}</td>
                            <td>${new Date(key.expires_at).toLocaleDateString()}</td>
                            <td>${key.last_heartbeat ? new Date(key.last_heartbeat).toLocaleString() : 'Never'}</td>
                            <td>
                                <div class="action-group">
                                    <button class="btn-icon" onclick="toggleKeyStatus('${key.key}', '${key.status}')" title="${key.status === 'active' ? 'Deactivate' : 'Activate'}">
                                        <i class="fas ${key.status === 'active' ? 'fa-pause' : 'fa-play'}"></i>
                                    </button>
                                    <button class="btn-icon" onclick="kickKey('${key.key}')" title="Kick User">
                                        <i class="fas fa-user-slash"></i>
                                    </button>
                                    <button class="btn-icon" onclick="resetKeyHWID('${key.key}')" title="Reset HWID">
                                        <i class="fas fa-undo-alt"></i>
                                    </button>
                                    <button class="btn-icon" onclick="setKeyNickname('${key.key}')" title="Set Nickname">
                                        <i class="fas fa-tag"></i>
                                    </button>
                                </div>
                            </td>
                        </tr>
                    `;
                }).join('');
            } catch (error) {
                console.error('Failed to load keys:', error);
            }
        }

        function initCharts() {
            // Activity Chart
            const activityCtx = document.getElementById('activityChart').getContext('2d');
            if (activityChart) activityChart.destroy();
            
            activityChart = new Chart(activityCtx, {
                type: 'line',
                data: {
                    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                    datasets: [{
                        label: 'Active Keys',
                        data: [65, 72, 80, 78, 85, 90, 95],
                        borderColor: '#3B82F6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            grid: {
                                color: 'rgba(255, 255, 255, 0.05)'
                            },
                            ticks: {
                                color: '#9CA3AF'
                            }
                        },
                        x: {
                            grid: {
                                display: false
                            },
                            ticks: {
                                color: '#9CA3AF'
                            }
                        }
                    }
                }
            });

            // Distribution Chart
            const distCtx = document.getElementById('distributionChart').getContext('2d');
            if (distributionChart) distributionChart.destroy();
            
            distributionChart = new Chart(distCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Active', 'Inactive', 'Expired'],
                    datasets: [{
                        data: [65, 25, 10],
                        backgroundColor: [
                            '#10B981',
                            '#EF4444',
                            '#6B7280'
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: '#9CA3AF'
                            }
                        }
                    },
                    cutout: '70%'
                }
            });
        }

        function logout() {
            token = null;
            localStorage.removeItem('token');
            authContainer.classList.remove('hidden');
            dashboardContainer.classList.add('hidden');
            showToast('Logged out successfully');
        }

        // ========== SCRIPT ACTIONS ==========
        document.getElementById('createScriptBtn').addEventListener('click', () => {
            createScriptModal.classList.add('show');
        });

        document.getElementById('closeScriptModal').addEventListener('click', () => {
            createScriptModal.classList.remove('show');
        });

        document.getElementById('cancelScriptBtn').addEventListener('click', () => {
            createScriptModal.classList.remove('show');
        });

        document.getElementById('createScriptSubmit').addEventListener('click', async () => {
            const name = document.getElementById('scriptName').value;
            
            if (!name) {
                showToast('Please enter a script name', 'error');
                return;
            }
            
            try {
                await apiCall('/api/scripts/create', 'POST', { name });
                createScriptModal.classList.remove('show');
                document.getElementById('scriptName').value = '';
                showToast('Script created successfully!');
                await loadScripts();
            } catch (error) {
                showToast(error.message, 'error');
            }
        });

        // ========== KEY ACTIONS ==========
        window.showGenerateKeyModal = (scriptId, scriptName) => {
            document.getElementById('keyScriptSelect').innerHTML = `<option value="${scriptId}" selected>${scriptName}</option>`;
            createKeyModal.classList.add('show');
        };

        document.getElementById('closeKeyModal').addEventListener('click', () => {
            createKeyModal.classList.remove('show');
        });

        document.getElementById('cancelKeyBtn').addEventListener('click', () => {
            createKeyModal.classList.remove('show');
        });

        document.getElementById('createKeySubmit').addEventListener('click', async () => {
            const scriptId = document.getElementById('keyScriptSelect').value;
            const nickname = document.getElementById('keyNickname').value;
            const duration = parseInt(document.getElementById('keyDuration').value);
            
            if (!scriptId) {
                showToast('Please select a script', 'error');
                return;
            }
            
            try {
                await apiCall('/api/keys/create', 'POST', {
                    script_id: parseInt(scriptId),
                    nickname: nickname || null,
                    duration_days: duration
                });
                
                createKeyModal.classList.remove('show');
                document.getElementById('keyNickname').value = '';
                showToast('Key generated successfully!');
                await loadKeys();
            } catch (error) {
                showToast(error.message, 'error');
            }
        });

        window.toggleKeyStatus = async (key, currentStatus) => {
            try {
                await apiCall('/api/keys/action', 'POST', {
                    key: key,
                    action: currentStatus === 'active' ? 'deactivate' : 'activate'
                });
                showToast(`Key ${currentStatus === 'active' ? 'deactivated' : 'activated'}`);
                await loadKeys();
            } catch (error) {
                showToast(error.message, 'error');
            }
        };

        window.kickKey = async (key) => {
            if (!confirm('Kick this user? They will be disconnected on next heartbeat.')) return;
            
            try {
                await apiCall('/api/keys/action', 'POST', {
                    key: key,
                    action: 'kick'
                });
                showToast('User will be kicked on next heartbeat');
            } catch (error) {
                showToast(error.message, 'error');
            }
        };

        window.resetKeyHWID = async (key) => {
            if (!confirm('Reset HWID for this key? The user will need to authenticate again.')) return;
            
            try {
                await apiCall('/api/keys/reset-hwid', 'POST', {
                    key: key,
                    confirm: true
                });
                showToast('HWID reset successfully');
                await loadKeys();
            } catch (error) {
                showToast(error.message, 'error');
            }
        };

        window.setKeyNickname = async (key) => {
            const nickname = prompt('Enter nickname for this key:');
            if (nickname === null) return;
            
            try {
                await apiCall('/api/keys/nickname', 'POST', {
                    key: key,
                    nickname: nickname
                });
                showToast('Nickname updated');
                await loadKeys();
            } catch (error) {
                showToast(error.message, 'error');
            }
        };

        window.viewScriptKeys = async (scriptId, scriptName) => {
            try {
                const keys = await apiCall('/api/keys');
                const scriptKeys = keys.filter(k => k.script_name === scriptName);
                
                document.getElementById('viewKeysTitle').textContent = `Keys for ${scriptName}`;
                
                const tbody = document.getElementById('modalKeysBody');
                if (scriptKeys.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 20px;">No keys for this script</td></tr>';
                } else {
                    tbody.innerHTML = scriptKeys.map(key => {
                        const statusClass = key.online ? 'online' : (key.status === 'active' ? 'active' : 'inactive');
                        const statusText = key.online ? 'ONLINE' : (key.status === 'active' ? 'ACTIVE' : 'INACTIVE');
                        
                        return `
                            <tr>
                                <td class="key-cell">${key.key}</td>
                                <td>${key.nickname || '-'}</td>
                                <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                                <td>${key.hwid ? key.hwid.substring(0, 8) + '...' : 'Not bound'}</td>
                                <td>${new Date(key.expires_at).toLocaleDateString()}</td>
                                <td>
                                    <div class="action-group">
                                        <button class="btn-icon" onclick="toggleKeyStatus('${key.key}', '${key.status}')">
                                            <i class="fas ${key.status === 'active' ? 'fa-pause' : 'fa-play'}"></i>
                                        </button>
                                        <button class="btn-icon" onclick="kickKey('${key.key}')">
                                            <i class="fas fa-user-slash"></i>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        `;
                    }).join('');
                }
                
                viewKeysModal.classList.add('show');
            } catch (error) {
                showToast(error.message, 'error');
            }
        };

        document.getElementById('closeViewKeysModal').addEventListener('click', () => {
            viewKeysModal.classList.remove('show');
        });

        document.getElementById('closeViewKeysBtn').addEventListener('click', () => {
            viewKeysModal.classList.remove('show');
        });

        document.getElementById('generateKeyFromModal').addEventListener('click', () => {
            viewKeysModal.classList.remove('show');
            createKeyModal.classList.add('show');
        });

        // ========== LOADER GENERATION ==========
        window.generateLoader = async (scriptId) => {
            try {
                const response = await apiCall('/api/loader/generate', 'POST', { script_id: scriptId });
                document.getElementById('loaderCode').textContent = response.loader;
                loaderModal.classList.add('show');
            } catch (error) {
                showToast(error.message, 'error');
            }
        };

        document.getElementById('closeLoaderModal').addEventListener('click', () => {
            loaderModal.classList.remove('show');
        });

        document.getElementById('closeLoaderBtn').addEventListener('click', () => {
            loaderModal.classList.remove('show');
        });

        document.getElementById('copyLoaderBtn').addEventListener('click', () => {
            const loaderText = document.getElementById('loaderCode').textContent;
            navigator.clipboard.writeText(loaderText);
            showToast('Loader copied to clipboard!');
        });

        // ========== AUTH EVENT LISTENERS ==========
        loginTab.addEventListener('click', () => {
            loginTab.classList.add('active');
            registerTab.classList.remove('active');
            loginForm.classList.remove('hidden');
            registerForm.classList.add('hidden');
        });

        registerTab.addEventListener('click', () => {
            registerTab.classList.add('active');
            loginTab.classList.remove('active');
            registerForm.classList.remove('hidden');
            loginForm.classList.add('hidden');
        });

        loginBtn.addEventListener('click', async () => {
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
                
                await loadDashboard();
                showToast('Login successful!');
            } catch (error) {
                showToast(error.message, 'error');
            }
        });

        registerBtn.addEventListener('click', async () => {
            const username = document.getElementById('registerUsername').value;
            const password = document.getElementById('registerPassword').value;
            const apiKey = document.getElementById('registerApiKey').value;
            
            if (!username || !password || !apiKey) {
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
                
                await loadDashboard();
                showToast('Registration successful!');
            } catch (error) {
                showToast(error.message, 'error');
            }
        });

        logoutBtn.addEventListener('click', logout);

        // ========== INIT ==========
        if (token) {
            loadDashboard().catch(() => logout());
        }

        // Auto-refresh every 30 seconds
        setInterval(async () => {
            if (token && !dashboardContainer.classList.contains('hidden')) {
                await Promise.all([
                    loadStats(),
                    loadKeys()
                ]);
            }
        }, 30000);

        // Close modals on overlay click
        document.querySelectorAll('.modal-overlay').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('show');
                }
            });
        });
    </script>
</body>
</html>
"""

# ========== FRONTEND ROUTES ==========
@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    return HTML_TEMPLATE

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTML_TEMPLATE

@app.get("/{full_path:path}", response_class=HTMLResponse)
async def catch_all(full_path: str):
    return HTML_TEMPLATE

# ========== RUN ==========
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
