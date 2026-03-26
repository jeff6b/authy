import os
import secrets
import uuid
import json
from datetime import datetime, timedelta
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import JWTError, jwt
import asyncpg
from dotenv import load_dotenv
import uvicorn
import bcrypt

load_dotenv()

# ========== CONFIGURATION ==========
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
DATABASE_URL = os.getenv("DATABASE_URL")
MASTER_API_KEY = "123"

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
    except:
        return False

# ========== DATABASE ==========
class Database:
    def __init__(self):
        self.pool = None

    async def connect(self):
        if not DATABASE_URL:
            print("❌ DATABASE_URL not set!")
            return
        
        try:
            self.pool = await asyncpg.create_pool(DATABASE_URL, min_size=5, max_size=20)
            await self.init_db()
            print("✅ Database connected")
            return True
        except Exception as e:
            print(f"❌ Database error: {e}")
            return False

    async def disconnect(self):
        if self.pool:
            await self.pool.close()

    async def init_db(self):
        async with self.pool.acquire() as conn:
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
            
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS scripts (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    script_type TEXT DEFAULT 'standard',
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    config JSONB DEFAULT '{}'
                )
            ''')
            
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
            
            await conn.execute('CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key)')
            print("✅ Tables ready")

db = Database()

# ========== FASTAPI APP ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.connect()
    yield
    await db.disconnect()

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(days=7)
    data.update({"exp": expire.timestamp()})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except:
        return None

async def get_current_user(auth: HTTPAuthorizationCredentials = Depends(security)):
    if not auth:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = verify_token(auth.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    async with db.pool.acquire() as conn:
        user = await conn.fetchrow("SELECT id, username, email, is_admin FROM users WHERE username = $1", payload["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return dict(user)

def generate_key():
    parts = [uuid.uuid4().hex[:4].upper() for _ in range(3)]
    return f"AUTHY-{'-'.join(parts)}"

# ========== MODELS ==========
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

class KeyCreate(BaseModel):
    script_id: int
    nickname: Optional[str] = None
    duration_days: int = 30

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

# ========== API ENDPOINTS ==========
@app.post("/api/auth/register", response_model=TokenResponse)
async def register(user: UserCreate):
    if user.api_key != MASTER_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    async with db.pool.acquire() as conn:
        existing = await conn.fetchval("SELECT id FROM users WHERE username = $1", user.username)
        if existing:
            raise HTTPException(status_code=400, detail="Username taken")
        
        hashed = hash_password(user.password)
        user_id = await conn.fetchval(
            "INSERT INTO users (username, password_hash, email) VALUES ($1, $2, $3) RETURNING id",
            user.username, hashed, f"{user.username}@midnight.local"
        )
        
        token = create_access_token({"sub": user.username, "id": user_id})
        return {"access_token": token, "token_type": "bearer"}

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(user: UserLogin):
    async with db.pool.acquire() as conn:
        db_user = await conn.fetchrow("SELECT * FROM users WHERE username = $1", user.username)
        if not db_user or not verify_password(user.password, db_user['password_hash']):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        token = create_access_token({"sub": user.username, "id": db_user['id']})
        return {"access_token": token, "token_type": "bearer"}

@app.post("/api/scripts/create")
async def create_script(script_data: ScriptCreate, current_user: dict = Depends(get_current_user)):
    async with db.pool.acquire() as conn:
        existing = await conn.fetchval("SELECT id FROM scripts WHERE name = $1 AND user_id = $2", script_data.name, current_user['id'])
        if existing:
            raise HTTPException(status_code=400, detail="Script name exists")
        
        script_id = await conn.fetchval(
            "INSERT INTO scripts (name, script_type, user_id) VALUES ($1, $2, $3) RETURNING id",
            script_data.name, script_data.script_type, current_user['id']
        )
        return {"id": script_id, "name": script_data.name, "script_type": script_data.script_type}

@app.get("/api/scripts")
async def get_scripts(current_user: dict = Depends(get_current_user)):
    async with db.pool.acquire() as conn:
        scripts = await conn.fetch("SELECT id, name, script_type, created_at FROM scripts WHERE user_id = $1", current_user['id'])
        return [dict(s) for s in scripts]

@app.post("/api/keys/create")
async def create_key(key_data: KeyCreate, current_user: dict = Depends(get_current_user)):
    async with db.pool.acquire() as conn:
        script = await conn.fetchval("SELECT id FROM scripts WHERE id = $1 AND user_id = $2", key_data.script_id, current_user['id'])
        if not script:
            raise HTTPException(status_code=404, detail="Script not found")
        
        key = generate_key()
        while await conn.fetchval("SELECT id FROM keys WHERE key = $1", key):
            key = generate_key()
        
        expires_at = datetime.now() + timedelta(days=key_data.duration_days) if key_data.duration_days > 0 else datetime.now() + timedelta(days=3650)
        
        await conn.execute(
            "INSERT INTO keys (key, script_id, nickname, expires_at) VALUES ($1, $2, $3, $4)",
            key, key_data.script_id, key_data.nickname, expires_at
        )
        
        return {"key": key, "nickname": key_data.nickname, "expires_at": expires_at.isoformat(), "status": "active"}

@app.get("/api/keys")
async def get_keys(current_user: dict = Depends(get_current_user)):
    async with db.pool.acquire() as conn:
        keys = await conn.fetch("""
            SELECT k.*, s.name as script_name FROM keys k
            JOIN scripts s ON k.script_id = s.id
            WHERE s.user_id = $1 ORDER BY k.created_at DESC
        """, current_user['id'])
        return [dict(k) for k in keys]

@app.post("/api/validate", response_model=ValidateResponse)
async def validate_key(request: ValidateRequest):
    async with db.pool.acquire() as conn:
        key_info = await conn.fetchrow("""
            SELECT k.*, s.name as script_name, s.script_type
            FROM keys k JOIN scripts s ON k.script_id = s.id
            WHERE k.key = $1
        """, request.key)
        
        if not key_info:
            return ValidateResponse(valid=False, status="invalid", message="Key not found")
        
        if key_info['kicked']:
            return ValidateResponse(valid=False, status="kicked", message="Key kicked", kicked=True)
        
        if key_info['expires_at'] < datetime.now():
            return ValidateResponse(valid=False, status="expired", message="Key expired")
        
        if key_info['status'] != 'active':
            return ValidateResponse(valid=False, status=key_info['status'], message=f"Key {key_info['status']}")
        
        await conn.execute("UPDATE keys SET last_heartbeat = CURRENT_TIMESTAMP WHERE id = $1", key_info['id'])
        
        return ValidateResponse(
            valid=True, status="active", message="Valid",
            script_name=key_info['script_name'], script_type=key_info['script_type'],
            expires_at=key_info['expires_at'].isoformat(), kicked=False
        )

@app.get("/")
async def root():
    return {"message": "Midnight API is running", "status": "ok"}

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("backend:app", host="0.0.0.0", port=port, reload=True)
