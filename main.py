import os
import secrets
import uuid
import json
import random
import string
from datetime import datetime, timedelta
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
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

print("Starting Authy application...")
print(f"DATABASE_URL exists: {bool(DATABASE_URL)}")
print(f"SECRET_KEY exists: {bool(SECRET_KEY)}")

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
    print(f"Bcrypt working: {test_verify}")
except Exception as e:
    print(f"Bcrypt error: {e}")

# ========== DATABASE CONNECTION POOL ==========
class Database:
    def __init__(self):
        self.pool = None

    async def connect(self):
        print("Attempting to connect to database...")
        
        if not DATABASE_URL:
            print("CRITICAL: DATABASE_URL is not set!")
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
                print("Database connection test successful!")
            
            await self.init_db()
            print("Database connected and initialized")
            return True
            
        except Exception as e:
            print(f"Database connection failed: {type(e).__name__}: {e}")
            return False

    async def disconnect(self):
        if self.pool:
            await self.pool.close()
            print("Database disconnected")

    async def init_db(self):
        """Initialize database tables WITHOUT dropping - preserves data!"""
        if not self.pool:
            print("Cannot init DB - no connection pool")
            return
            
        try:
            async with self.pool.acquire() as conn:
                print("Ensuring database tables exist...")
                
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
                print("Users table ready")
                
                # Scripts table with TEXT id for random IDs
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS scripts (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        script_type TEXT DEFAULT 'standard',
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        config JSONB DEFAULT '{}',
                        UNIQUE(name, user_id)
                    )
                ''')
                print("Scripts table ready (with TEXT IDs)")
                
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
                print("Keys table ready")
                
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
                print("Heartbeat logs table ready")
                
                # Create indexes
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_script_id ON keys(script_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_scripts_user_id ON scripts(user_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_heartbeat_key_id ON heartbeat_logs(key_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_heartbeat_timestamp ON heartbeat_logs(timestamp)')
                
                print("Database tables ready - data preserved!")
                
        except Exception as e:
            print(f"Failed to initialize tables: {e}")
            import traceback
            traceback.print_exc()

db = Database()

# ========== LIFESPAN HANDLER ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starting up...")
    try:
        await db.connect()
    except Exception as e:
        print(f"Startup error: {e}")
    
    yield
    
    print("Shutting down...")
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

def generate_script_id():
    """Generate a random 7-character script ID (letters and numbers)"""
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choices(characters, k=7))

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
    id: str
    name: str
    script_type: str
    created_at: str
    key_count: int
    active_keys: int
    config: dict

class KeyCreate(BaseModel):
    script_id: str
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
    print(f"Register attempt: {user.username}")
    
    if user.api_key != MASTER_API_KEY:
        print(f"Invalid API key: {user.api_key}")
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
            
            print(f"Registered: {user.username}")
            return {"access_token": token, "token_type": "bearer"}
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Register error: {e}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(user: UserLogin):
    """Login user"""
    print(f"Login attempt: {user.username}")
    
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
            
            print(f"Login successful: {user.username}")
            return {"access_token": token, "token_type": "bearer"}
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {e}")
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
    """Create a new script with random 7-character ID"""
    print(f"Creating script: {script_data.name} for user {current_user['id']}")
    
    if not db.pool:
        print("Database not available")
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        async with db.pool.acquire() as conn:
            # Check if script name already exists
            existing = await conn.fetchval(
                "SELECT id FROM scripts WHERE name = $1 AND user_id = $2",
                script_data.name, current_user['id']
            )
            
            if existing:
                print(f"Script name already exists: {script_data.name}")
                raise HTTPException(status_code=400, detail="Script name already exists")
            
            # Generate random 7-character ID
            script_id = generate_script_id()
            while await conn.fetchval("SELECT id FROM scripts WHERE id = $1", script_id):
                script_id = generate_script_id()
            
            config_json = '{}'
            if script_data.config:
                config_json = json.dumps(script_data.config)
            
            await conn.fetchval(
                "INSERT INTO scripts (id, name, script_type, user_id, config) VALUES ($1, $2, $3, $4, $5::jsonb) RETURNING id",
                script_id, script_data.name, script_data.script_type, current_user['id'], config_json
            )
            
            print(f"Script created with ID: {script_id}")
            return {
                "id": script_id,
                "name": script_data.name,
                "script_type": script_data.script_type,
                "message": "Script created successfully"
            }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Script creation error: {e}")
        import traceback
        traceback.print_exc()
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

@app.get("/api/scripts/{script_id}")
async def get_script(
    script_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get a specific script by ID"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        script = await conn.fetchrow(
            "SELECT * FROM scripts WHERE id = $1 AND user_id = $2",
            script_id, current_user['id']
        )
        
        if not script:
            raise HTTPException(status_code=404, detail="Script not found")
        
        return dict(script)

@app.delete("/api/scripts/{script_id}")
async def delete_script(
    script_id: str,
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
        script = await conn.fetchval(
            "SELECT id FROM scripts WHERE id = $1 AND user_id = $2",
            key_data.script_id, current_user['id']
        )
        
        if not script:
            raise HTTPException(status_code=404, detail="Script not found")
        
        key = generate_key()
        while await conn.fetchval("SELECT id FROM keys WHERE key = $1", key):
            key = generate_key()
        
        expires_at = datetime.now() + timedelta(days=key_data.duration_days) if key_data.duration_days > 0 else datetime.now() + timedelta(days=3650)
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

@app.get("/api/keys/script/{script_id}")
async def get_script_keys(
    script_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get all keys for a specific script"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        # Verify script belongs to user
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
            key = dict(key)
            online = False
            if key['last_heartbeat']:
                online = (datetime.now() - key['last_heartbeat']).seconds < 120
            
            result.append({
                "key": key['key'],
                "nickname": key['nickname'],
                "created_at": key['created_at'].isoformat() if key['created_at'] else None,
                "expires_at": key['expires_at'].isoformat() if key['expires_at'] else None,
                "last_heartbeat": key['last_heartbeat'].isoformat() if key['last_heartbeat'] else None,
                "hwid": key['hwid'],
                "status": key['status'],
                "online": online,
                "kicked": key['kicked'],
                "hwid_resets_used": key['hwid_resets_used'],
                "max_hwid_resets": key['max_hwid_resets'],
                "note": key['note']
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

@app.get("/api/stats/script/{script_id}")
async def get_script_stats(
    script_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get stats for a specific script"""
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
            "script_type": script['script_type'],
            "total_keys": total_keys or 0,
            "active_keys": active_keys or 0,
            "online_now": online_now or 0
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
        
        script_type = script['script_type']
        config = script['config'] or {}
        
        loader = f'''-- =============================================
-- AUTHY LOADER FOR: {script['name']}
-- ID: {script_id}
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
    print("HWID: " .. hwid)
    
    local valid, response = validate_key(key, hwid)
    
    if not valid then
        print("Authentication failed: " .. (response.reason or "unknown error"))
        return false
    end
    
    print("Authentication successful!")
    print("Script: {script['name']} (ID: {script_id})")
    
    if response.kicked then
        print("You have been kicked from this script!")
        return false
    end
    
    spawn(function()
        while wait(60) do
            local valid, hb_response = send_heartbeat(key, hwid)
            if not valid or hb_response.kicked then
                print("You have been kicked or license invalidated!")
                return
            end
        end
    end)
    
    return true
end

return {{
    authenticate = authenticate,
    get_hwid = get_hwid,
    validate = validate_key
}}
'''
        
        return {
            "loader": loader,
            "script_name": script['name'],
            "script_id": script_id,
            "script_type": script_type,
            "instructions": "Copy this loader and paste it at the bottom of your script."
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
    
    try:
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
            
            # Parse config if it's a string
            config = key_info['config']
            if isinstance(config, str):
                try:
                    config = json.loads(config)
                except:
                    config = {}
            
            if key_info['kicked']:
                return HeartbeatResponse(
                    valid=False,
                    status="kicked",
                    message="You have been kicked from this script",
                    kicked=True
                )
            
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
            
            if key_info['status'] != 'active':
                return HeartbeatResponse(
                    valid=False, 
                    status=key_info['status'], 
                    message=f"Key {key_info['status']}"
                )
            
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
                config=config,
                kicked=False,
                expires_at=key_info['expires_at'].isoformat()
            )
    except Exception as e:
        print(f"Heartbeat error: {e}")
        import traceback
        traceback.print_exc()
        return HeartbeatResponse(
            valid=False,
            status="error",
            message=f"Server error: {str(e)}"
        )

@app.post("/api/validate")
async def validate_key(request: HeartbeatRequest):
    """Simple validation"""
    if not db.pool:
        return {"valid": False, "reason": "database_error"}
    
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
            return {"valid": False, "reason": "not_found"}
        
        key_info = dict(key_info)
        
        config = key_info['config']
        if isinstance(config, str):
            try:
                config = json.loads(config)
            except:
                config = {}
        
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
            "config": config,
            "expires": key_info['expires_at'].isoformat()
        }

# ========== HOMEPAGE TEMPLATE ==========
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

# ========== DASHBOARD TEMPLATE ==========
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authy Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
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
        }

        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.5;
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
            color: #3B82F6;
            -webkit-text-fill-color: initial;
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

        .main-content {
            padding: 120px 30px 40px;
            max-width: 1400px;
            margin: 0 auto;
        }

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

        .btn-primary {
            background: var(--gradient-primary);
            border: none;
            padding: 14px 24px;
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
            padding: 8px 16px;
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
            display: flex;
            align-items: center;
            gap: 6px;
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
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .btn-success:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(16, 185, 129, 0.3);
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
            font-size: 1rem;
        }

        .btn-icon:hover {
            border-color: var(--accent-primary);
            color: var(--accent-primary);
        }

        .btn-icon.danger:hover {
            border-color: var(--accent-danger);
            color: var(--accent-danger);
        }

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
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }

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
            color: var(--accent-primary);
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
        <div class="nav-links">
            <a href="/dashboard" class="nav-link">Dashboard</a>
            <a href="#" class="nav-link">Scripts</a>
            <a href="#" class="nav-link">Keys</a>
            <a href="#" class="nav-link">Analytics</a>
            <a href="#" class="nav-link">Docs</a>
        </div>
        <div class="nav-user">
            <div class="user-menu">
                <i class="fas fa-user-circle"></i>
                <span class="username" id="usernameDisplay">Loading...</span>
                <i class="fas fa-chevron-down"></i>
            </div>
            <button class="btn-logout" id="logoutBtn">
                <i class="fas fa-sign-out-alt"></i>
            </button>
        </div>
    </nav>

    <div class="main-content">
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

    <!-- Create Script Modal -->
    <div class="modal-overlay" id="createScriptModal">
        <div class="modal">
            <div class="modal-header">
                <h3>Create New Script</h3>
                <button class="modal-close" id="closeScriptModal">&times;</button>
            </div>
            <div class="modal-body">
                <div class="form-group" style="margin-bottom: 20px;">
                    <label style="display: block; margin-bottom: 8px; color: var(--text-secondary);">Script Name</label>
                    <input type="text" id="scriptName" placeholder="e.g., 'Lua Executor' or 'DarkHub'" style="width: 100%; padding: 12px; background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-primary);">
                </div>
                <div class="form-group">
                    <label style="display: block; margin-bottom: 8px; color: var(--text-secondary);">Script Type</label>
                    <select id="scriptType" style="width: 100%; padding: 12px; background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-primary);">
                        <option value="standard">Standard</option>
                        <option value="premium">Premium</option>
                        <option value="custom">Custom</option>
                    </select>
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
                <div class="form-group" style="margin-bottom: 20px;">
                    <label style="display: block; margin-bottom: 8px; color: var(--text-secondary);">Select Script</label>
                    <select id="keyScriptSelect" style="width: 100%; padding: 12px; background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-primary);">
                        <option value="">Loading scripts...</option>
                    </select>
                </div>
                <div class="form-group" style="margin-bottom: 20px;">
                    <label style="display: block; margin-bottom: 8px; color: var(--text-secondary);">Nickname (optional)</label>
                    <input type="text" id="keyNickname" placeholder="e.g., 'VIP User'" style="width: 100%; padding: 12px; background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-primary);">
                </div>
                <div class="form-group">
                    <label style="display: block; margin-bottom: 8px; color: var(--text-secondary);">Duration</label>
                    <select id="keyDuration" style="width: 100%; padding: 12px; background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-primary);">
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
                <p style="color: var(--text-secondary); margin-top: 10px;">
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

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // API Configuration
        const API_BASE = window.location.origin;
        let token = localStorage.getItem('token');
        let currentUser = null;
        let activityChart = null;
        let distributionChart = null;

        // Check if token exists
        if (!token) {
            window.location.href = '/';
        }

        // DOM Elements
        const usernameDisplay = document.getElementById('usernameDisplay');
        const dashboardUsername = document.getElementById('dashboardUsername');
        const logoutBtn = document.getElementById('logoutBtn');
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

        // ========== DASHBOARD FUNCTIONS ==========
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
                
            } catch (error) {
                console.error('Failed to load dashboard:', error);
                showToast('Failed to load dashboard', 'error');
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
                            <button class="btn-success" onclick="showGenerateKeyModal('${script.id}', '${script.name}')">
                                <i class="fas fa-plus"></i>
                                Key
                            </button>
                            <button class="btn-primary" onclick="generateLoader('${script.id}')">
                                <i class="fas fa-download"></i>
                                Loader
                            </button>
                            <button class="btn-secondary" onclick="viewScriptKeys('${script.id}', '${script.name}')">
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
                    plugins: { legend: { display: false } },
                    scales: {
                        y: {
                            grid: { color: 'rgba(255, 255, 255, 0.05)' },
                            ticks: { color: '#9CA3AF' }
                        },
                        x: {
                            grid: { display: false },
                            ticks: { color: '#9CA3AF' }
                        }
                    }
                }
            });

            const distCtx = document.getElementById('distributionChart').getContext('2d');
            if (distributionChart) distributionChart.destroy();
            
            distributionChart = new Chart(distCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Active', 'Inactive', 'Expired'],
                    datasets: [{
                        data: [65, 25, 10],
                        backgroundColor: ['#10B981', '#EF4444', '#6B7280'],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#9CA3AF' }
                        }
                    },
                    cutout: '70%'
                }
            });
        }

        function logout() {
            token = null;
            localStorage.removeItem('token');
            window.location.href = '/';
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
            const scriptType = document.getElementById('scriptType').value;
            
            if (!name) {
                showToast('Please enter a script name', 'error');
                return;
            }
            
            try {
                await apiCall('/api/scripts/create', 'POST', { name, script_type: scriptType });
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
                    script_id: scriptId,
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
                const keys = await apiCall('/api/keys/script/' + scriptId);
                
                document.getElementById('viewKeysTitle').textContent = `Keys for ${scriptName}`;
                
                const tbody = document.getElementById('modalKeysBody');
                if (keys.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 20px;">No keys for this script</td></tr>';
                } else {
                    tbody.innerHTML = keys.map(key => {
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

        // ========== LOGOUT ==========
        logoutBtn.addEventListener('click', logout);

        // ========== INIT ==========
        loadDashboard();

        // Auto-refresh every 30 seconds
        setInterval(async () => {
            if (token) {
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
@app.get("/", response_class=HTMLResponse)
async def serve_homepage():
    """Serve the homepage"""
    return HOMEPAGE_TEMPLATE

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the dashboard"""
    return DASHBOARD_TEMPLATE

# ========== RUN ==========
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
