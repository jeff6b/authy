import os
import secrets
import uuid
import json
import random
import string
import hashlib
import hmac
import base64
import time
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request, Header, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
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
MASTER_API_KEY = os.getenv("MASTER_API_KEY", "123")  # For Discord bot

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("authy-backend")

print("🚀 Starting Authy Backend System...")
print(f"📊 DATABASE_URL exists: {bool(DATABASE_URL)}")
print(f"🔑 SECRET_KEY exists: {bool(SECRET_KEY)}")

# ========== RATE LIMITING ==========
rate_limits = {}

def check_rate_limit(ip: str) -> bool:
    """Simple rate limiting - 10 requests per minute"""
    now = time.time()
    if ip not in rate_limits:
        rate_limits[ip] = []
    
    # Clean old entries
    rate_limits[ip] = [t for t in rate_limits[ip] if now - t < 60]
    
    if len(rate_limits[ip]) >= 10:
        return False
    
    rate_limits[ip].append(now)
    return True

# ========== FILE STORAGE ==========
# Using dictionary for now - consider Redis for production
hosted_files = {}

def cleanup_old_files():
    """Remove files older than 24 hours"""
    now = datetime.now()
    expired = []
    for token, info in hosted_files.items():
        created = datetime.fromisoformat(info['created_at'])
        if (now - created).total_seconds() > 86400:  # 24 hours
            expired.append(token)
    
    for token in expired:
        del hosted_files[token]
    
    if expired:
        logger.info(f"Cleaned up {len(expired)} expired files")

# ========== PASSWORD HASHING ==========
def hash_password(password: str) -> str:
    """Hash password with bcrypt"""
    password_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    try:
        plain_bytes = plain_password.encode('utf-8')[:72]
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(plain_bytes, hashed_bytes)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

# ========== DATABASE CONNECTION POOL ==========
class Database:
    def __init__(self):
        self.pool = None
        self.connected = False

    async def connect(self):
        """Connect to database with retry logic"""
        logger.info("Attempting to connect to database...")
        
        if not DATABASE_URL:
            logger.error("CRITICAL: DATABASE_URL is not set!")
            return False
        
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                self.pool = await asyncpg.create_pool(
                    DATABASE_URL, 
                    min_size=5, 
                    max_size=20,
                    command_timeout=60,
                    max_queries=50000,
                    max_inactive_connection_lifetime=300
                )
                
                # Test connection
                async with self.pool.acquire() as conn:
                    await conn.execute("SELECT 1")
                
                logger.info("Database connection test successful!")
                await self.init_db()
                logger.info("Database connected and initialized")
                self.connected = True
                return True
                
            except Exception as e:
                retry_count += 1
                logger.error(f"Database connection failed (attempt {retry_count}/{max_retries}): {e}")
                if retry_count < max_retries:
                    wait_time = retry_count * 2
                    logger.info(f"Retrying in {wait_time} seconds...")
                    await asyncio.sleep(wait_time)
                else:
                    logger.error("All database connection attempts failed")
                    return False

    async def disconnect(self):
        """Close database connection pool"""
        if self.pool:
            await self.pool.close()
            logger.info("Database disconnected")
            self.connected = False

    async def init_db(self):
        """Initialize database tables"""
        if not self.pool:
            logger.error("Cannot init DB - no connection pool")
            return
            
        try:
            async with self.pool.acquire() as conn:
                logger.info("Ensuring database tables exist...")
                
                # Users table
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
                
                # Scripts table
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS scripts (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(name, user_id)
                    )
                ''')
                
                # Keys table
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS keys (
                        id SERIAL PRIMARY KEY,
                        key TEXT UNIQUE NOT NULL,
                        script_id TEXT NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
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
                
                # Heartbeat logs table
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS heartbeat_logs (
                        id SERIAL PRIMARY KEY,
                        key_id INTEGER NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        hwid TEXT NOT NULL,
                        ip_address TEXT
                    )
                ''')
                
                # Create indexes for better performance
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_script_id ON keys(script_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_scripts_user_id ON scripts(user_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_heartbeat_key_id ON heartbeat_logs(key_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_heartbeat_timestamp ON heartbeat_logs(timestamp)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(status)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_expires ON keys(expires_at)')
                
                logger.info("Database tables ready!")
                
        except Exception as e:
            logger.error(f"Failed to initialize tables: {e}")
            import traceback
            traceback.print_exc()

db = Database()

# ========== LIFESPAN HANDLER ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events"""
    logger.info("Starting up Authy Backend System...")
    try:
        await db.connect()
    except Exception as e:
        logger.error(f"Startup error: {e}")
    
    yield
    
    logger.info("Shutting down...")
    await db.disconnect()
    # Cleanup old files on shutdown
    cleanup_old_files()

# ========== FASTAPI APP ==========
app = FastAPI(
    title="Authy Backend System",
    description="Backend for Discord bot integration",
    version="1.0.0",
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

# ========== API KEY AUTH ==========
async def verify_api_key(api_key: str = Header(None, alias="X-API-Key")):
    """Verify API key for Discord bot endpoints"""
    if not api_key or api_key != MASTER_API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return True

# ========== HELPER FUNCTIONS ==========
def create_access_token(data: dict):
    """Create JWT token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire.timestamp()})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        logger.warning(f"Token verification failed: {e}")
        return None

async def get_current_user(auth: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from token"""
    if not auth:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    payload = verify_token(auth.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if not db.pool or not db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        async with db.pool.acquire() as conn:
            user = await conn.fetchrow(
                "SELECT id, username, email, created_at, is_admin FROM users WHERE username = $1",
                payload["sub"]
            )
    except Exception as e:
        logger.error(f"Database error in get_current_user: {e}")
        raise HTTPException(status_code=503, detail="Database error")
        
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return dict(user)

def generate_key():
    """Generate a unique license key format: AUTHY-XXXX-XXXX-XXXX"""
    parts = []
    for _ in range(3):
        parts.append(uuid.uuid4().hex[:4].upper())
    return f"AUTHY-{'-'.join(parts)}"

def generate_script_id():
    """Generate a random 7-character script ID"""
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choices(characters, k=7))

def generate_token():
    """Generate a random token for file hosting"""
    return secrets.token_urlsafe(16)

def generate_basic_loader(script_url: str) -> str:
    """Generate a basic loader with heartbeat auth"""
    return f'''-- =============================================
-- AUTHY BASIC LOADER
-- =============================================

-- CONFIG - User must set their key
local LICENSE_KEY = "YOUR_KEY_HERE"

-- Get HWID (works on most executors)
local function getHWID()
    local hwid = gethwid and gethwid()
    if not hwid then
        hwid = getexecutorhwid and getexecutorhwid()
    end
    if not hwid then
        hwid = get_hwid and get_hwid()
    end
    if not hwid then
        hwid = "FALLBACK-HWID-" .. game:GetService("RbxAnalyticsService"):GetClientId()
    end
    return hwid
end

-- Authenticate with heartbeat
local function authenticate()
    local success, response = pcall(function()
        return request({{
            Url = "https://authy-o0pm.onrender.com/api/heartbeat",
            Method = "POST",
            Headers = {{
                ["Content-Type"] = "application/json"
            }},
            Body = game:GetService("HttpService"):JSONEncode({{
                key = LICENSE_KEY,
                hwid = getHWID()
            }})
        }})
    end)
    
    if success and response and response.StatusCode == 200 then
        local data = game:GetService("HttpService"):JSONDecode(response.Body)
        return data.valid, data
    end
    return false, {{message = "Connection failed"}}
end

-- Main execution
local valid, result = authenticate()

if not valid then
    print("❌ Authentication failed: " .. (result.message or "Invalid key"))
    return
end

print("✅ Authentication successful!")
if result.script_name then
    print("📜 Script: " .. result.script_name)
end
if result.expires_at then
    print("📅 Expires: " .. result.expires_at)
end

-- Fetch actual script
local scriptResponse = request({{
    Url = "{script_url}",
    Method = "GET"
}})

if scriptResponse and scriptResponse.StatusCode == 200 then
    local loadSuccess, loadError = pcall(loadstring, scriptResponse.Body)
    if loadSuccess then
        loadError()
    else
        print("❌ Failed to load script: " .. tostring(loadError))
    end
else
    print("❌ Failed to fetch script")
end
'''

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
    name: str = Field(..., min_length=1, max_length=50)

class KeyCreate(BaseModel):
    script_id: str
    nickname: Optional[str] = None
    duration_days: int = Field(30, ge=1, le=3650)

class KeyAction(BaseModel):
    key: str
    action: str

class KeyNickname(BaseModel):
    key: str
    nickname: Optional[str] = None

class HeartbeatRequest(BaseModel):
    key: str
    hwid: str

class HeartbeatResponse(BaseModel):
    valid: bool
    status: str
    message: str
    script_name: Optional[str] = None
    script_type: Optional[str] = None
    kicked: bool = False
    expires_at: Optional[str] = None

class HWIDResetRequest(BaseModel):
    key: str
    confirm: bool = False

class HostScriptRequest(BaseModel):
    content: str
    enhanced: bool = False

# ========== SCRIPT MANAGEMENT ==========
@app.post("/api/scripts/create")
async def create_script(
    script_data: ScriptCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new script"""
    logger.info(f"Creating script: {script_data.name} for user {current_user['id']}")
    
    if not db.pool or not db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        async with db.pool.acquire() as conn:
            existing = await conn.fetchval(
                "SELECT id FROM scripts WHERE name = $1 AND user_id = $2",
                script_data.name, current_user['id']
            )
            
            if existing:
                raise HTTPException(status_code=400, detail="Script name already exists")
            
            script_id = generate_script_id()
            while await conn.fetchval("SELECT id FROM scripts WHERE id = $1", script_id):
                script_id = generate_script_id()
            
            await conn.execute(
                """
                INSERT INTO scripts (id, name, user_id) 
                VALUES ($1, $2, $3)
                """,
                script_id, script_data.name, current_user['id']
            )
            
            return {
                "id": script_id,
                "name": script_data.name,
                "message": "Script created successfully"
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Script creation error: {e}")
        raise HTTPException(status_code=500, detail=f"Script creation failed: {str(e)}")

@app.get("/api/scripts")
async def get_scripts(current_user: dict = Depends(get_current_user)):
    """Get all scripts for current user"""
    if not db.pool or not db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
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
                    "created_at": script['created_at'].isoformat() if script['created_at'] else None,
                    "key_count": script['key_count'] or 0,
                    "active_keys": script['active_keys'] or 0
                })
            
            return result
    except Exception as e:
        logger.error(f"Error getting scripts: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scripts")

@app.get("/api/scripts/{script_id}")
async def get_script(
    script_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a specific script by ID"""
    if not db.pool or not db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        async with db.pool.acquire() as conn:
            script = await conn.fetchrow(
                "SELECT id, name, created_at FROM scripts WHERE id = $1 AND user_id = $2",
                script_id, current_user['id']
            )
            
            if not script:
                raise HTTPException(status_code=404, detail="Script not found")
            
            return dict(script)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting script: {e}")
        raise HTTPException(status_code=500, detail="Failed to get script")

@app.delete("/api/scripts/{script_id}")
async def delete_script(
    script_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a script and all its keys"""
    if not db.pool or not db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        async with db.pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM scripts WHERE id = $1 AND user_id = $2",
                script_id, current_user['id']
            )
            
            if result.split()[-1] == "0":
                raise HTTPException(status_code=404, detail="Script not found")
            
            return {"success": True, "message": "Script deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting script: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete script")

# ========== KEY MANAGEMENT ==========
@app.post("/api/keys/create")
async def create_key(
    key_data: KeyCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new key for a script"""
    if not db.pool or not db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        async with db.pool.acquire() as conn:
            script = await conn.fetchval(
                "SELECT id FROM scripts WHERE id = $1 AND user_id = $2",
                key_data.script_id, current_user['id']
            )
            
            if not script:
                raise HTTPException(status_code=404, detail="Script not found")
            
            key = generate_key()
            while await conn.fetchval("SELECT id FROM keys WHERE key = $1", key):
                key = generate_key()
            
            expires_at = datetime.now() + timedelta(days=key_data.duration_days)
            await conn.execute(
                """
                INSERT INTO keys 
                (key, script_id, nickname, expires_at, note) 
                VALUES ($1, $2, $3, $4, $5)
                """,
                key, key_data.script_id, key_data.nickname, expires_at, key_data.nickname
            )
            
            return {
                "key": key,
                "nickname": key_data.nickname,
                "expires_at": expires_at.isoformat(),
                "status": "active"
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating key: {e}")
        raise HTTPException(status_code=500, detail="Failed to create key")

@app.get("/api/keys")
async def get_keys(current_user: dict = Depends(get_current_user)):
    """Get all keys for current user"""
    if not db.pool or not db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
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
                key_dict = dict(key)
                online = False
                if key_dict['last_heartbeat']:
                    online = (datetime.now() - key_dict['last_heartbeat']).total_seconds() < 120
                
                result.append({
                    "key": key_dict['key'],
                    "nickname": key_dict['nickname'],
                    "script_name": key_dict['script_name'],
                    "created_at": key_dict['created_at'].isoformat() if key_dict['created_at'] else None,
                    "expires_at": key_dict['expires_at'].isoformat() if key_dict['expires_at'] else None,
                    "last_heartbeat": key_dict['last_heartbeat'].isoformat() if key_dict['last_heartbeat'] else None,
                    "hwid": key_dict['hwid'],
                    "status": key_dict['status'],
                    "online": online,
                    "kicked": key_dict['kicked'],
                    "hwid_resets_used": key_dict['hwid_resets_used'],
                    "max_hwid_resets": key_dict['max_hwid_resets']
                })
            
            return result
    except Exception as e:
        logger.error(f"Error getting keys: {e}")
        raise HTTPException(status_code=500, detail="Failed to get keys")

@app.get("/api/keys/script/{script_id}")
async def get_script_keys(
    script_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get all keys for a specific script"""
    if not db.pool or not db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        async with db.pool.acquire() as conn:
            script = await conn.fetchval(
                "SELECT id FROM scripts WHERE id = $1 AND user_id = $2",
                script_id, current_user['id']
            )
            
            if not script:
                raise HTTPException(status_code=404, detail="Script not found")
            
            keys = await conn.fetch(
                """
                SELECT * FROM keys 
                WHERE script_id = $1 
                ORDER BY created_at DESC
                """,
                script_id
            )
            
            result = []
            for key in keys:
                key_dict = dict(key)
                online = False
                if key_dict['last_heartbeat']:
                    online = (datetime.now() - key_dict['last_heartbeat']).total_seconds() < 120
                
                result.append({
                    "key": key_dict['key'],
                    "nickname": key_dict['nickname'],
                    "created_at": key_dict['created_at'].isoformat() if key_dict['created_at'] else None,
                    "expires_at": key_dict['expires_at'].isoformat() if key_dict['expires_at'] else None,
                    "last_heartbeat": key_dict['last_heartbeat'].isoformat() if key_dict['last_heartbeat'] else None,
                    "hwid": key_dict['hwid'],
                    "status": key_dict['status'],
                    "online": online,
                    "kicked": key_dict['kicked'],
                    "hwid_resets_used": key_dict['hwid_resets_used'],
                    "max_hwid_resets": key_dict['max_hwid_resets'],
                    "note": key_dict['note']
                })
            
            return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting script keys: {e}")
        raise HTTPException(status_code=500, detail="Failed to get keys")

@app.post("/api/keys/action")
async def key_action(
    action: KeyAction,
    current_user: dict = Depends(get_current_user)
):
    """Activate, deactivate, or kick a key"""
    if not db.pool or not db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    valid_actions = ["activate", "deactivate", "kick"]
    if action.action not in valid_actions:
        raise HTTPException(status_code=400, detail=f"Invalid action. Must be one of: {', '.join(valid_actions)}")
    
    try:
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
                await conn.execute(
                    "UPDATE keys SET kicked = TRUE WHERE key = $1",
                    action.key
                )
                return {"success": True, "message": "User will be kicked on next heartbeat"}
            
            return {"success": False, "message": "No action taken"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error performing key action: {e}")
        raise HTTPException(status_code=500, detail="Failed to perform action")

@app.post("/api/keys/nickname")
async def set_nickname(
    nick_data: KeyNickname,
    current_user: dict = Depends(get_current_user)
):
    """Set nickname for a key"""
    if not db.pool or not db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
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
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error setting nickname: {e}")
        raise HTTPException(status_code=500, detail="Failed to update nickname")

@app.post("/api/keys/reset-hwid")
async def reset_hwid(
    request: HWIDResetRequest,
    current_user: dict = Depends(get_current_user)
):
    """Reset HWID for a key"""
    if not db.pool or not db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
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
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resetting HWID: {e}")
        raise HTTPException(status_code=500, detail="Failed to reset HWID")

@app.delete("/api/keys/{key}")
async def delete_key(
    key: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a key"""
    if not db.pool or not db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
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
            
            return {"success": True, "message": "Key deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting key: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete key")

# ========== HEARTBEAT ENDPOINT ==========
@app.post("/api/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(request: HeartbeatRequest, req: Request):
    """Lua clients call this - checks if kicked"""
    if not db.pool or not db.connected:
        logger.warning("Heartbeat attempted but database not available")
        return HeartbeatResponse(
            valid=False, 
            status="error", 
            message="Database not available"
        )
    
    try:
        async with db.pool.acquire() as conn:
            key_info = await conn.fetchrow(
                "SELECT k.*, s.name as script_name FROM keys k JOIN scripts s ON k.script_id = s.id WHERE k.key = $1",
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
            
            # Check expiration
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
            
            # Check status
            if key_info['status'] != 'active':
                return HeartbeatResponse(
                    valid=False, 
                    status=key_info['status'], 
                    message=f"Key {key_info['status']}"
                )
            
            client_ip = req.client.host if req.client else "unknown"
            
            # HWID handling
            if not key_info['hwid']:
                # First time binding
                await conn.execute(
                    "UPDATE keys SET hwid = $1, last_heartbeat = CURRENT_TIMESTAMP WHERE id = $2",
                    request.hwid, key_info['id']
                )
            elif key_info['hwid'] != request.hwid:
                # HWID mismatch
                return HeartbeatResponse(
                    valid=False, 
                    status="hwid_mismatch", 
                    message="Invalid HWID"
                )
            else:
                # Valid heartbeat
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
                kicked=False,
                expires_at=key_info['expires_at'].isoformat()
            )
    except Exception as e:
        logger.error(f"Heartbeat error: {e}")
        return HeartbeatResponse(
            valid=False,
            status="error",
            message=f"Server error"
        )

# ========== STATS ==========
@app.get("/api/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    """Get dashboard stats"""
    if not db.pool or not db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
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
            
            return {
                "total_scripts": total_scripts or 0,
                "total_keys": total_keys or 0,
                "active_keys": active_keys or 0,
                "online_now": online_now or 0
            }
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get stats")

@app.get("/api/stats/script/{script_id}")
async def get_script_stats(
    script_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get stats for a specific script"""
    if not db.pool or not db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        async with db.pool.acquire() as conn:
            script = await conn.fetchrow(
                "SELECT * FROM scripts WHERE id = $1 AND user_id = $2",
                script_id, current_user['id']
            )
            
            if not script:
                raise HTTPException(status_code=404, detail="Script not found")
            
            total_keys = await conn.fetchval(
                "SELECT COUNT(*) FROM keys WHERE script_id = $1",
                script_id
            )
            
            active_keys = await conn.fetchval(
                """
                SELECT COUNT(*) FROM keys 
                WHERE script_id = $1 
                AND status = 'active' 
                AND expires_at > CURRENT_TIMESTAMP
                """,
                script_id
            )
            
            online_now = await conn.fetchval(
                """
                SELECT COUNT(*) FROM keys 
                WHERE script_id = $1 
                AND last_heartbeat IS NOT NULL
                AND EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - last_heartbeat)) < 120
                """,
                script_id
            )
            
            return {
                "script_id": script_id,
                "script_name": script['name'],
                "total_keys": total_keys or 0,
                "active_keys": active_keys or 0,
                "online_now": online_now or 0
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting script stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to get script stats")

# ========== FILE HOSTING ENDPOINTS ==========
@app.post("/api/hostscript")
async def host_script(
    request: Request,
    current_user: dict = Depends(get_current_user),
    api_key: bool = Depends(verify_api_key)
):
    """Host a script and return a URL"""
    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded. Try again later."}
        )
    
    try:
        data = await request.json()
        content = data.get('content')
        enhanced = data.get('enhanced', False)
        
        if not content:
            return JSONResponse(
                status_code=400,
                content={"error": "No content provided"}
            )
        
        # Cleanup old files occasionally
        if random.random() < 0.1:  # 10% chance on each upload
            cleanup_old_files()
        
        # Generate token
        token = generate_token()
        
        # Store the script
        hosted_files[token] = {
            "content": content,
            "user_id": current_user['id'],
            "enhanced": enhanced,
            "created_at": datetime.now().isoformat()
        }
        
        script_url = f"/raw/{token}"
        
        return {
            "success": True,
            "token": token,
            "url": script_url,
            "full_url": f"https://authy-o0pm.onrender.com{script_url}",
            "enhanced": enhanced,
            "message": "Script hosted successfully"
        }
        
    except Exception as e:
        logger.error(f"Error hosting script: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e)}
        )

@app.get("/raw/{token}")
async def get_raw_script(token: str, request: Request):
    """Get the raw script content"""
    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(client_ip):
        return HTMLResponse(
            content="<h1>Rate Limit Exceeded</h1><p>Too many requests. Try again later.</p>",
            status_code=429
        )
    
    if token not in hosted_files:
        return HTMLResponse(
            content="<h1>404 - Script Not Found</h1>",
            status_code=404
        )
    
    file_info = hosted_files[token]
    
    # Check if browser access for enhanced files
    user_agent = request.headers.get("user-agent", "").lower()
    if file_info['enhanced'] and ("mozilla" in user_agent or "chrome" in user_agent or "safari" in user_agent):
        return HTMLResponse(
            content="<h1>Access Denied</h1><p>This URL is for loader use only.</p>",
            status_code=403
        )
    
    return PlainTextResponse(
        content=file_info['content'],
        media_type="text/plain"
    )

@app.get("/api/hosted-files")
async def get_hosted_files(
    current_user: dict = Depends(get_current_user),
    api_key: bool = Depends(verify_api_key)
):
    """Get all files hosted by current user"""
    user_files = []
    
    for token, info in hosted_files.items():
        if info['user_id'] == current_user['id']:
            user_files.append({
                "token": token,
                "url": f"/raw/{token}",
                "enhanced": info.get('enhanced', False),
                "created_at": info['created_at']
            })
    
    return {"files": user_files}

# ========== LOADER GENERATION ENDPOINT ==========
@app.post("/api/loader")
async def generate_loader(
    request: Request,
    current_user: dict = Depends(get_current_user),
    api_key: bool = Depends(verify_api_key)
):
    """Generate a loader for a hosted script"""
    try:
        data = await request.json()
        token = data.get('token')
        enhanced = data.get('enhanced', False)
        
        if not token:
            return JSONResponse(
                status_code=400,
                content={"error": "No script token provided"}
            )
        
        if token not in hosted_files:
            return JSONResponse(
                status_code=404,
                content={"error": "Script not found"}
            )
        
        if hosted_files[token]['user_id'] != current_user['id']:
            return JSONResponse(
                status_code=403,
                content={"error": "Not authorized to access this script"}
            )
        
        script_url = f"https://authy-o0pm.onrender.com/raw/{token}"
        loader = generate_basic_loader(script_url)
        
        if enhanced:
            # Add anti-debug for enhanced version
            loader = loader.replace(
                "-- Main execution",
                """-- Anti-Debug Check
local function antiDebug()
    if debug and debug.getinfo then
        return false
    end
    return true
end

if not antiDebug() then
    print("⚠️ Security check failed")
    return
end

-- Main execution"""
            )
        
        return {
            "success": True,
            "loader": loader,
            "enhanced": enhanced,
            "message": "Loader generated successfully"
        }
        
    except Exception as e:
        logger.error(f"Error generating loader: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e)}
        )

# ========== HEALTH CHECK ==========
@app.get("/health")
async def health_check():
    """Health check endpoint for Render"""
    return {
        "status": "healthy", 
        "database": "connected" if db.connected else "disconnected",
        "timestamp": datetime.now().isoformat()
    }

# ========== RUN ==========
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
