import os
import secrets
import uuid
import json
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
        """Initialize database tables"""
        if not self.pool:
            print("⚠️ Cannot init DB - no connection pool")
            return
            
        try:
            async with self.pool.acquire() as conn:
                print("🔄 Ensuring database tables exist...")
                
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
                print("✅ Users table ready")
                
                # Scripts table
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
                
                # Keys table
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS keys (
                        id SERIAL PRIMARY KEY,
                        key TEXT UNIQUE NOT NULL,
                        script_id INTEGER NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
                        nickname TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP NOT NULL,
                        last_heartbeat TIMESTAMP,
                        status TEXT DEFAULT 'active',
                        kicked BOOLEAN DEFAULT FALSE,
                        note TEXT
                    )
                ''')
                print("✅ Keys table ready")
                
                # Create indexes
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_script_id ON keys(script_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_scripts_user_id ON scripts(user_id)')
                
                print("✅ Database tables ready!")
                
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
    title="Authy - Key System",
    description="Simple key authentication system",
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

class ValidateRequest(BaseModel):
    key: str

class ValidateResponse(BaseModel):
    valid: bool
    status: str
    message: str
    script_name: Optional[str] = None
    script_type: Optional[str] = None
    expires_at: Optional[str] = None
    kicked: bool = False

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
                "SELECT id FROM users WHERE username = $1",
                user.username
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

# ========== SCRIPT MANAGEMENT ==========
@app.post("/api/scripts/create")
async def create_script(
    script_data: ScriptCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new script"""
    print(f"📝 Creating script: {script_data.name} for user {current_user['id']}")
    
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        async with db.pool.acquire() as conn:
            existing = await conn.fetchval(
                "SELECT id FROM scripts WHERE name = $1 AND user_id = $2",
                script_data.name, current_user['id']
            )
            
            if existing:
                raise HTTPException(status_code=400, detail="Script name already exists")
            
            config_json = json.dumps(script_data.config) if script_data.config else '{}'
            
            script_id = await conn.fetchval(
                "INSERT INTO scripts (name, script_type, user_id, config) VALUES ($1, $2, $3, $4::jsonb) RETURNING id",
                script_data.name, script_data.script_type, current_user['id'], config_json
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
            SELECT s.*, COUNT(k.id) as key_count
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
            config = script['config']
            if isinstance(config, str):
                try:
                    config = json.loads(config)
                except:
                    config = {}
            
            result.append({
                "id": script['id'],
                "name": script['name'],
                "script_type": script['script_type'],
                "created_at": script['created_at'].isoformat(),
                "key_count": script['key_count'],
                "config": config
            })
        
        return result

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
        
        await conn.execute(
            """
            INSERT INTO keys (key, script_id, nickname, expires_at, note) 
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
            result.append({
                "key": key['key'],
                "nickname": key['nickname'],
                "script_name": key['script_name'],
                "script_type": key['script_type'],
                "created_at": key['created_at'].isoformat() if key['created_at'] else None,
                "expires_at": key['expires_at'].isoformat() if key['expires_at'] else None,
                "status": key['status'],
                "kicked": key['kicked']
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
            return {"success": True, "message": "Key kicked"}
        
        raise HTTPException(status_code=400, detail="Invalid action")

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

# ========== PUBLIC API ENDPOINTS ==========
@app.post("/api/validate", response_model=ValidateResponse)
async def validate_key(request: ValidateRequest):
    """Simple key validation - no HWID, no login required"""
    print(f"🔑 Key validation attempt: {request.key}")
    
    if not db.pool:
        return ValidateResponse(
            valid=False,
            status="error",
            message="Database not available"
        )
    
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
            print(f"❌ Key not found: {request.key}")
            return ValidateResponse(
                valid=False,
                status="invalid",
                message="Key not found"
            )
        
        key_info = dict(key_info)
        
        if key_info['kicked']:
            print(f"❌ Key is kicked: {request.key}")
            return ValidateResponse(
                valid=False,
                status="kicked",
                message="This key has been kicked",
                kicked=True
            )
        
        if key_info['expires_at'] < datetime.now():
            print(f"❌ Key expired: {request.key}")
            await conn.execute(
                "UPDATE keys SET status = 'expired' WHERE id = $1",
                key_info['id']
            )
            return ValidateResponse(
                valid=False,
                status="expired",
                message="Key has expired"
            )
        
        if key_info['status'] != 'active':
            return ValidateResponse(
                valid=False,
                status=key_info['status'],
                message=f"Key is {key_info['status']}"
            )
        
        # Update last heartbeat
        await conn.execute(
            "UPDATE keys SET last_heartbeat = CURRENT_TIMESTAMP WHERE id = $1",
            key_info['id']
        )
        
        print(f"✅ Key validated: {request.key}")
        
        return ValidateResponse(
            valid=True,
            status="active",
            message="Key is valid",
            script_name=key_info['script_name'],
            script_type=key_info['script_type'],
            expires_at=key_info['expires_at'].isoformat(),
            kicked=False
        )

# ========== SIMPLE FRONTEND ==========
@app.get("/", response_class=HTMLResponse)
async def serve_homepage():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Authy Key System</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                background: #f5f5f5;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            h1 { color: #333; }
            .endpoint {
                background: #f0f0f0;
                padding: 10px;
                margin: 10px 0;
                border-radius: 5px;
                font-family: monospace;
            }
            .method {
                color: #0066cc;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔑 Authy Key System</h1>
            <p>Your key authentication system is running!</p>
            
            <h2>API Endpoints:</h2>
            <div class="endpoint">
                <span class="method">POST</span> /api/validate - Validate a license key
            </div>
            <div class="endpoint">
                <span class="method">POST</span> /api/auth/register - Register a new user
            </div>
            <div class="endpoint">
                <span class="method">POST</span> /api/auth/login - Login
            </div>
            <div class="endpoint">
                <span class="method">GET</span> /api/scripts - Get your scripts
            </div>
            <div class="endpoint">
                <span class="method">POST</span> /api/keys/create - Create a new key
            </div>
            
            <h2>Test Key Validation:</h2>
            <input type="text" id="key" placeholder="Enter license key" style="width: 100%; padding: 10px; margin: 10px 0;">
            <button onclick="validateKey()" style="padding: 10px 20px; background: #0066cc; color: white; border: none; border-radius: 5px; cursor: pointer;">Validate</button>
            <div id="result" style="margin-top: 20px;"></div>
        </div>
        
        <script>
            async function validateKey() {
                const key = document.getElementById('key').value;
                const resultDiv = document.getElementById('result');
                
                if (!key) {
                    resultDiv.innerHTML = '<p style="color: red;">Please enter a key</p>';
                    return;
                }
                
                try {
                    const response = await fetch('/api/validate', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ key: key })
                    });
                    
                    const data = await response.json();
                    
                    if (data.valid) {
                        resultDiv.innerHTML = `
                            <div style="background: #d4edda; padding: 15px; border-radius: 5px; color: #155724;">
                                <strong>✓ Key Valid!</strong><br>
                                Script: ${data.script_name}<br>
                                Type: ${data.script_type}<br>
                                Expires: ${data.expires_at}<br>
                                Status: ${data.status}
                            </div>
                        `;
                    } else {
                        resultDiv.innerHTML = `
                            <div style="background: #f8d7da; padding: 15px; border-radius: 5px; color: #721c24;">
                                <strong>✗ Key Invalid!</strong><br>
                                ${data.message}
                            </div>
                        `;
                    }
                } catch (error) {
                    resultDiv.innerHTML = `<p style="color: red;">Error: ${error.message}</p>`;
                }
            }
        </script>
    </body>
    </html>
    """

# ========== RUN ==========
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
