import os
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
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

print("🚀 Starting Authy application...")
print(f"📊 DATABASE_URL exists: {bool(DATABASE_URL)}")
print(f"🔑 SECRET_KEY exists: {bool(SECRET_KEY)}")

# ========== PASSWORD HASHING ==========
# Use direct bcrypt to avoid passlib issues
def hash_password(password: str) -> str:
    """Hash password using bcrypt directly"""
    # Truncate to 72 bytes if needed (bcrypt limit)
    password_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password using bcrypt directly"""
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
        """Create connection pool with better error handling"""
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
            
            # Test the connection
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
        """Close connection pool"""
        if self.pool:
            await self.pool.close()
            print("✅ Database disconnected")

    async def init_db(self):
        """Initialize database tables"""
        if not self.pool:
            print("⚠️  Cannot init DB - no connection pool")
            return
            
        try:
            async with self.pool.acquire() as conn:
                print("🔄 Creating database tables...")
                
                # Users table
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_admin BOOLEAN DEFAULT FALSE,
                        api_key TEXT UNIQUE
                    )
                ''')
                print("✅ Users table ready")
                
                # Licenses table
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS licenses (
                        id SERIAL PRIMARY KEY,
                        key TEXT UNIQUE NOT NULL,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP NOT NULL,
                        last_heartbeat TIMESTAMP,
                        hwid TEXT,
                        max_hwid_resets INTEGER DEFAULT 3,
                        hwid_resets_used INTEGER DEFAULT 0,
                        status TEXT DEFAULT 'active',
                        note TEXT
                    )
                ''')
                print("✅ Licenses table ready")
                
                # Heartbeat logs table
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS heartbeat_logs (
                        id SERIAL PRIMARY KEY,
                        license_id INTEGER NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        hwid TEXT NOT NULL,
                        ip_address TEXT
                    )
                ''')
                print("✅ Heartbeat logs table ready")
                
                print("✅ Database tables ready")
                
        except Exception as e:
            print(f"❌ Failed to initialize tables: {e}")

db = Database()

# ========== LIFESPAN HANDLER ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("🚀 Starting up...")
    try:
        await db.connect()
    except Exception as e:
        print(f"⚠️  Startup error: {e}")
    
    yield
    
    # Shutdown
    print("🛑 Shutting down...")
    await db.disconnect()

# ========== FASTAPI APP ==========
app = FastAPI(
    title="Authy - Lua Auth System",
    description="Complete authentication system for Lua scripts",
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
    except JWTError:
        return None

async def get_current_user(auth: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from token"""
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

def generate_license_key():
    """Generate a unique license key format: LUA-XXXX-XXXX-XXXX"""
    parts = []
    for _ in range(3):
        parts.append(uuid.uuid4().hex[:4].upper())
    return f"LUA-{'-'.join(parts)}"

# ========== PYDANTIC MODELS ==========
class UserCreate(BaseModel):
    username: str
    password: str
    email: str

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class LicenseCreate(BaseModel):
    duration_days: int = 30
    note: Optional[str] = None

class LicenseResponse(BaseModel):
    key: str
    expires_at: str
    status: str

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

# ========== DEBUG ENDPOINTS ==========
@app.get("/api/debug")
async def debug_db():
    """Debug endpoint to check database connection"""
    try:
        if not db.pool:
            return {
                "status": "error", 
                "message": "Database pool not initialized",
                "database_url_exists": bool(DATABASE_URL)
            }
        
        async with db.pool.acquire() as conn:
            result = await conn.fetchval("SELECT 1")
            # Check if tables exist
            tables = await conn.fetch("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
            """)
            table_list = [t['table_name'] for t in tables]
            
            return {
                "status": "ok", 
                "message": "Database connected",
                "test_query": result,
                "pool_size": db.pool.get_size(),
                "tables": table_list
            }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "type": type(e).__name__,
            "database_url_exists": bool(DATABASE_URL)
        }

@app.get("/api/test-bcrypt")
async def test_bcrypt():
    """Test bcrypt directly"""
    try:
        password = "test123"
        hashed = hash_password(password)
        verified = verify_password(password, hashed)
        
        return {
            "status": "ok",
            "password": password,
            "hash_preview": hashed[:30] + "...",
            "verification": verified,
            "message": "Bcrypt is working"
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "type": type(e).__name__
        }

# ========== PUBLIC API ENDPOINTS (for Lua clients) ==========
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
        # Get license
        license = await conn.fetchrow(
            "SELECT * FROM licenses WHERE key = $1",
            request.key
        )
        
        if not license:
            return HeartbeatResponse(
                valid=False, 
                status="invalid", 
                message="Key not found"
            )
        
        license = dict(license)
        expires_at = license['expires_at']
        
        # Check if expired
        if expires_at < datetime.now():
            await conn.execute(
                "UPDATE licenses SET status = 'expired' WHERE id = $1",
                license['id']
            )
            return HeartbeatResponse(
                valid=False, 
                status="expired", 
                message="Key expired"
            )
        
        # Check if suspended
        if license['status'] != 'active':
            return HeartbeatResponse(
                valid=False, 
                status=license['status'], 
                message=f"Key {license['status']}"
            )
        
        # First time this HWID? If no HWID set, bind it
        client_ip = req.client.host if req.client else "unknown"
        
        if not license['hwid']:
            await conn.execute(
                "UPDATE licenses SET hwid = $1, last_heartbeat = CURRENT_TIMESTAMP WHERE id = $2",
                request.hwid, license['id']
            )
        elif license['hwid'] != request.hwid:
            # Wrong HWID
            return HeartbeatResponse(
                valid=False, 
                status="hwid_mismatch", 
                message="Invalid HWID"
            )
        else:
            # Update heartbeat
            await conn.execute(
                "UPDATE licenses SET last_heartbeat = CURRENT_TIMESTAMP WHERE id = $1",
                license['id']
            )
        
        # Log the heartbeat
        await conn.execute(
            "INSERT INTO heartbeat_logs (license_id, hwid, ip_address) VALUES ($1, $2, $3)",
            license['id'], request.hwid, client_ip
        )
        
        # Calculate days remaining
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
        license = await conn.fetchrow(
            "SELECT * FROM licenses WHERE key = $1",
            request.key
        )
        
        if not license:
            return {"valid": False, "reason": "not_found"}
        
        license = dict(license)
        
        if license['expires_at'] < datetime.now():
            return {"valid": False, "reason": "expired"}
        
        if license['status'] != 'active':
            return {"valid": False, "reason": license['status']}
        
        if license['hwid'] and license['hwid'] != request.hwid:
            return {"valid": False, "reason": "hwid_mismatch"}
        
        # If no HWID bound yet, bind it now
        if not license['hwid']:
            await conn.execute(
                "UPDATE licenses SET hwid = $1 WHERE id = $2",
                request.hwid, license['id']
            )
        
        return {
            "valid": True, 
            "expires": license['expires_at'].isoformat()
        }

# ========== AUTH ENDPOINTS ==========
@app.post("/api/auth/register", response_model=TokenResponse)
async def register(user: UserCreate):
    """Register a new user"""
    print(f"📝 Register attempt: {user.username}")
    
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        async with db.pool.acquire() as conn:
            # Check if user exists
            existing = await conn.fetchval(
                "SELECT id FROM users WHERE username = $1 OR email = $2",
                user.username, user.email
            )
            
            if existing:
                raise HTTPException(status_code=400, detail="Username or email already taken")
            
            # Hash password and create user
            hashed = hash_password(user.password)
            api_key = secrets.token_urlsafe(32)
            
            user_id = await conn.fetchval(
                "INSERT INTO users (username, password_hash, email, api_key) VALUES ($1, $2, $3, $4) RETURNING id",
                user.username, hashed, user.email, api_key
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
            # Get user
            db_user = await conn.fetchrow(
                "SELECT * FROM users WHERE username = $1",
                user.username
            )
            
            if not db_user:
                print(f"❌ User not found: {user.username}")
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            # Verify password
            if not verify_password(user.password, db_user['password_hash']):
                print(f"❌ Invalid password for: {user.username}")
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            # Create token
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
    """Get current user info"""
    return current_user

# ========== LICENSE MANAGEMENT ==========
@app.post("/api/licenses/create", response_model=LicenseResponse)
async def create_license(
    license_data: LicenseCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create a new license key"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        # Generate unique key
        key = generate_license_key()
        while await conn.fetchval("SELECT id FROM licenses WHERE key = $1", key):
            key = generate_license_key()
        
        # Create license
        expires_at = datetime.now() + timedelta(days=license_data.duration_days)
        await conn.fetchval(
            """
            INSERT INTO licenses 
            (key, user_id, expires_at, note, max_hwid_resets) 
            VALUES ($1, $2, $3, $4, $5) 
            RETURNING id
            """,
            key, current_user['id'], expires_at, license_data.note, 3
        )
        
        return LicenseResponse(
            key=key,
            expires_at=expires_at.isoformat(),
            status="active"
        )

@app.get("/api/licenses")
async def get_licenses(current_user: dict = Depends(get_current_user)):
    """Get all licenses for current user"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        licenses = await conn.fetch(
            """
            SELECT * FROM licenses 
            WHERE user_id = $1 
            ORDER BY created_at DESC
            """,
            current_user['id']
        )
        
        result = []
        for lic in licenses:
            lic = dict(lic)
            # Check if online (heartbeat in last 2 minutes)
            online = False
            if lic['last_heartbeat']:
                online = (datetime.now() - lic['last_heartbeat']).seconds < 120
            
            result.append({
                "key": lic['key'],
                "created_at": lic['created_at'].isoformat() if lic['created_at'] else None,
                "expires_at": lic['expires_at'].isoformat() if lic['expires_at'] else None,
                "last_heartbeat": lic['last_heartbeat'].isoformat() if lic['last_heartbeat'] else None,
                "hwid": lic['hwid'],
                "status": lic['status'],
                "hwid_resets_used": lic['hwid_resets_used'],
                "max_hwid_resets": lic['max_hwid_resets'],
                "note": lic['note'],
                "online": online
            })
        
        return result

@app.post("/api/licenses/reset-hwid")
async def reset_hwid(
    request: HWIDResetRequest,
    current_user: dict = Depends(get_current_user)
):
    """Reset HWID for a license"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        license = await conn.fetchrow(
            "SELECT * FROM licenses WHERE key = $1 AND user_id = $2",
            request.key, current_user['id']
        )
        
        if not license:
            raise HTTPException(status_code=404, detail="License not found")
        
        license = dict(license)
        
        if license['hwid_resets_used'] >= license['max_hwid_resets']:
            raise HTTPException(status_code=400, detail="No HWID resets remaining")
        
        if not request.confirm:
            return {
                "warning": f"This will reset HWID for {request.key}. {license['max_hwid_resets'] - license['hwid_resets_used'] - 1} resets remaining.",
                "confirm_needed": True
            }
        
        # Reset HWID
        await conn.execute(
            "UPDATE licenses SET hwid = NULL, hwid_resets_used = hwid_resets_used + 1 WHERE id = $1",
            license['id']
        )
        
        return {
            "success": True,
            "message": f"HWID reset for {request.key}. {license['max_hwid_resets'] - license['hwid_resets_used'] - 1} resets remaining."
        }

@app.delete("/api/licenses/{key}")
async def delete_license(
    key: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a license"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM licenses WHERE key = $1 AND user_id = $2",
            key, current_user['id']
        )
        
        if result.split()[-1] == "0":
            raise HTTPException(status_code=404, detail="License not found")
        
        return {"success": True}

# ========== STATS ==========
@app.get("/api/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    """Get dashboard stats"""
    if not db.pool:
        raise HTTPException(status_code=503, detail="Database not available")
    
    async with db.pool.acquire() as conn:
        # Total licenses
        total = await conn.fetchval(
            "SELECT COUNT(*) FROM licenses WHERE user_id = $1",
            current_user['id']
        )
        
        # Active licenses
        active = await conn.fetchval(
            """
            SELECT COUNT(*) FROM licenses 
            WHERE user_id = $1 
            AND status = 'active' 
            AND expires_at > CURRENT_TIMESTAMP
            """,
            current_user['id']
        )
        
        # Online now
        online = await conn.fetchval(
            """
            SELECT COUNT(*) FROM licenses 
            WHERE user_id = $1 
            AND last_heartbeat IS NOT NULL
            AND EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - last_heartbeat)) < 120
            """,
            current_user['id']
        )
        
        # Expiring soon
        expiring = await conn.fetchval(
            """
            SELECT COUNT(*) FROM licenses 
            WHERE user_id = $1 
            AND status = 'active'
            AND expires_at > CURRENT_TIMESTAMP
            AND expires_at < CURRENT_TIMESTAMP + INTERVAL '7 days'
            """,
            current_user['id']
        )
        
        return {
            "total_licenses": total or 0,
            "active_licenses": active or 0,
            "online_now": online or 0,
            "expiring_soon": expiring or 0
        }

# ========== FRONTEND ==========
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Authy - Protect Your Lua Scripts</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
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
    
    /* Dashboard Styles */
    .dashboard {
      padding: 100px 20px 40px;
      max-width: 1200px;
      margin: 0 auto;
    }
    
    .dashboard.hidden {
      display: none;
    }
    
    .welcome-card {
      background: rgba(21, 23, 30, 0.8);
      backdrop-filter: blur(16px);
      border: 1px solid #2a2f3a;
      border-radius: 24px;
      padding: 30px;
      margin-bottom: 30px;
    }
    
    .welcome-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 20px;
      flex-wrap: wrap;
      gap: 20px;
    }
    
    .welcome-title {
      font-size: 2rem;
      font-weight: 700;
    }
    
    .welcome-title span {
      color: #4a90e2;
    }
    
    .create-key-btn {
      background: #4a90e2;
      color: white;
      border: none;
      padding: 12px 24px;
      border-radius: 12px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s ease;
    }
    
    .create-key-btn:hover {
      transform: translateY(-2px);
      background: #60c0ff;
      box-shadow: 0 10px 20px rgba(74, 144, 226, 0.3);
    }
    
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-top: 20px;
    }
    
    .stat-card {
      background: rgba(30, 35, 45, 0.5);
      border: 1px solid #2a2f3a;
      border-radius: 16px;
      padding: 20px;
    }
    
    .stat-label {
      color: #a0a0a0;
      font-size: 0.9rem;
      margin-bottom: 8px;
    }
    
    .stat-value {
      font-size: 2rem;
      font-weight: 700;
      color: #4a90e2;
    }
    
    .keys-table {
      background: rgba(21, 23, 30, 0.8);
      backdrop-filter: blur(16px);
      border: 1px solid #2a2f3a;
      border-radius: 24px;
      padding: 30px;
      overflow-x: auto;
    }
    
    .keys-table h2 {
      margin-bottom: 20px;
      font-size: 1.5rem;
    }
    
    table {
      width: 100%;
      border-collapse: collapse;
    }
    
    th {
      text-align: left;
      padding: 12px;
      color: #a0a0a0;
      font-weight: 500;
      border-bottom: 1px solid #2a2f3a;
    }
    
    td {
      padding: 12px;
      border-bottom: 1px solid #2a2f3a;
    }
    
    .key-cell {
      font-family: monospace;
      color: #4a90e2;
    }
    
    .status-badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 0.85rem;
      font-weight: 500;
    }
    
    .status-active {
      background: rgba(74, 144, 226, 0.2);
      color: #4a90e2;
    }
    
    .status-expired {
      background: rgba(255, 75, 75, 0.2);
      color: #ff4b4b;
    }
    
    .action-btn {
      background: transparent;
      border: 1px solid #2a2f3a;
      color: #a0a0a0;
      padding: 6px 12px;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s ease;
      margin: 0 4px;
    }
    
    .action-btn:hover {
      border-color: #4a90e2;
      color: #4a90e2;
    }
    
    .action-btn.delete:hover {
      border-color: #ff4b4b;
      color: #ff4b4b;
    }
    
    .logout-btn {
      background: transparent;
      border: 1px solid #2a2f3a;
      color: #a0a0a0;
      padding: 8px 16px;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s ease;
      margin-left: 15px;
    }
    
    .logout-btn:hover {
      border-color: #ff4b4b;
      color: #ff4b4b;
    }
    
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
    
    .create-key-modal {
      width: 400px;
    }
    
    .duration-select {
      width: 100%;
      padding: 12px;
      background: rgba(30,35,45,0.7);
      border: 1px solid #2a2f3a;
      border-radius: 12px;
      color: white;
      margin: 15px 0;
    }
    
    .note-input {
      width: 100%;
      padding: 12px;
      background: rgba(30,35,45,0.7);
      border: 1px solid #2a2f3a;
      border-radius: 12px;
      color: white;
      margin: 15px 0;
    }
    
    .hero.hidden {
      display: none;
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
      .welcome-header {
        flex-direction: column;
        align-items: flex-start;
      }
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
  <!-- Navbar -->
  <nav class="navbar">
    <div class="logo">Authy</div>
    <div class="nav-menu">
      <a href="#" class="nav-link">Docs</a>
      <a href="#" class="nav-link">Dashboard</a>
      <a href="#" class="nav-link">Features</a>
      <a href="#" class="nav-link">Pricing</a>
      <a href="#" class="nav-link">FAQ</a>
    </div>
    <div class="nav-right" id="navRight">
      <span class="sign-in" id="openLogin">Sign in</span>
      <button class="sign-up-btn" id="openRegister">Sign up</button>
    </div>
  </nav>

  <!-- Hero Section -->
  <section class="hero-section" id="heroSection">
    <div class="hero-text">
      Protect Your Lua <span class="highlight">Scripts</span>
    </div>
    <div class="hero-subtitle">
      The most secure and reliable authentication
    </div>
  </section>

  <!-- Dashboard -->
  <div class="dashboard hidden" id="dashboard">
    <div class="welcome-card">
      <div class="welcome-header">
        <h1 class="welcome-title">Welcome back, <span id="username">User</span>!</h1>
        <div>
          <button class="create-key-btn" id="createKeyBtn">+ Create New Key</button>
          <button class="logout-btn" id="logoutBtn">Logout</button>
        </div>
      </div>
      
      <div class="stats-grid" id="statsGrid">
        <div class="stat-card"><div class="stat-label">Total Keys</div><div class="stat-value" id="totalKeys">0</div></div>
        <div class="stat-card"><div class="stat-label">Active Keys</div><div class="stat-value" id="activeKeys">0</div></div>
        <div class="stat-card"><div class="stat-label">Online Now</div><div class="stat-value" id="onlineNow">0</div></div>
        <div class="stat-card"><div class="stat-label">Expiring Soon</div><div class="stat-value" id="expiringSoon">0</div></div>
      </div>
    </div>

    <div class="keys-table">
      <h2>Your License Keys</h2>
      <table id="keysTable">
        <thead><tr><th>Key</th><th>Status</th><th>HWID</th><th>Expires</th><th>Last Seen</th><th>Actions</th></tr></thead>
        <tbody id="keysBody"><tr><td colspan="6" style="text-align:center;padding:40px;color:#666;">No keys yet. Create your first one!</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- Login Modal -->
  <div class="modal-overlay" id="loginModal">
    <div class="modal">
      <span class="modal-close" id="closeLoginModal">×</span>
      <h2 class="authy-title">Welcome Back</h2>
      <div class="floating-input"><input type="text" id="loginUsername" placeholder=""><label>Username</label><div class="notch-cover"></div></div>
      <div class="floating-input"><input type="password" id="loginPassword" placeholder=""><label>Password</label><div class="notch-cover"></div></div>
      <button class="login-btn" id="loginSubmit">Log in</button>
      <div class="terms">Don't have an account? <a href="#" id="switchToRegister">Sign up</a></div>
    </div>
  </div>

  <!-- Register Modal -->
  <div class="modal-overlay" id="registerModal">
    <div class="modal">
      <span class="modal-close" id="closeRegisterModal">×</span>
      <h2 class="authy-title">Create Account</h2>
      <div class="floating-input"><input type="text" id="registerUsername" placeholder=""><label>Username</label><div class="notch-cover"></div></div>
      <div class="floating-input"><input type="email" id="registerEmail" placeholder=""><label>Email</label><div class="notch-cover"></div></div>
      <div class="floating-input"><input type="password" id="registerPassword" placeholder=""><label>Password</label><div class="notch-cover"></div></div>
      <button class="login-btn" id="registerSubmit">Sign up</button>
      <div class="terms">Already have an account? <a href="#" id="switchToLogin">Sign in</a></div>
    </div>
  </div>

  <!-- Create Key Modal -->
  <div class="modal-overlay" id="createKeyModal">
    <div class="modal create-key-modal">
      <span class="modal-close" id="closeCreateModal">×</span>
      <h2 class="authy-title">Create License Key</h2>
      <select class="duration-select" id="keyDuration"><option value="7">7 days</option><option value="30" selected>30 days</option><option value="90">90 days</option><option value="365">1 year</option></select>
      <input type="text" class="note-input" id="keyNote" placeholder="Note (optional)">
      <button class="login-btn" id="createKeySubmit">Generate Key</button>
    </div>
  </div>

  <!-- Toast -->
  <div class="toast" id="toast"><span id="toastMessage"></span></div>

  <script>
    const API_BASE_URL = window.location.origin;
    let token = localStorage.getItem('token');
    let currentUser = null;

    const heroSection = document.getElementById('heroSection');
    const dashboard = document.getElementById('dashboard');
    const usernameSpan = document.getElementById('username');
    const toast = document.getElementById('toast');
    const toastMessage = document.getElementById('toastMessage');

    function showToast(message, type = 'success') {
      toastMessage.textContent = message;
      toast.className = `toast show ${type}`;
      setTimeout(() => toast.classList.remove('show'), 3000);
    }

    async function apiCall(endpoint, method = 'GET', data = null) {
      const headers = {'Content-Type': 'application/json'};
      if (token) headers['Authorization'] = `Bearer ${token}`;
      
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        method, headers,
        body: data ? JSON.stringify(data) : null
      });
      
      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        const text = await response.text();
        throw new Error('Server error - check console');
      }
      
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail || 'API call failed');
      return result;
    }

    async function loadDashboard() {
      try {
        currentUser = await apiCall('/api/user/me');
        usernameSpan.textContent = currentUser.username;
        await Promise.all([loadStats(), loadLicenses()]);
        heroSection.classList.add('hidden');
        dashboard.classList.remove('hidden');
      } catch { logout(); }
    }

    async function loadStats() {
      const stats = await apiCall('/api/stats');
      document.getElementById('totalKeys').textContent = stats.total_licenses;
      document.getElementById('activeKeys').textContent = stats.active_licenses;
      document.getElementById('onlineNow').textContent = stats.online_now;
      document.getElementById('expiringSoon').textContent = stats.expiring_soon;
    }

    async function loadLicenses() {
      const licenses = await apiCall('/api/licenses');
      const tbody = document.getElementById('keysBody');
      if (licenses.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:40px;color:#666;">No keys yet. Click "Create New Key" to get started!</td></tr>';
        return;
      }
      tbody.innerHTML = licenses.map(lic => {
        const statusClass = lic.status === 'active' ? 'status-active' : 'status-expired';
        const statusText = lic.online ? '🟢 ONLINE' : (lic.status === 'active' ? 'ACTIVE' : 'EXPIRED');
        return `<tr><td class="key-cell">${lic.key}</td><td><span class="status-badge ${statusClass}">${statusText}</span></td><td>${lic.hwid ? lic.hwid.substring(0,8)+'...' : 'Not bound'}</td><td>${new Date(lic.expires_at).toLocaleDateString()}</td><td>${lic.last_heartbeat ? new Date(lic.last_heartbeat).toLocaleString() : 'Never'}</td><td><button class="action-btn" onclick="resetHWID('${lic.key}')">Reset HWID</button><button class="action-btn delete" onclick="deleteKey('${lic.key}')">Delete</button></td></tr>`;
      }).join('');
    }

    window.resetHWID = async (key) => {
      if (!confirm(`Reset HWID for ${key}?`)) return;
      await apiCall('/api/licenses/reset-hwid', 'POST', { key, confirm: true });
      showToast('HWID reset successfully!');
      loadLicenses();
    };

    window.deleteKey = async (key) => {
      if (!confirm(`Delete ${key}?`)) return;
      await apiCall(`/api/licenses/${key}`, 'DELETE');
      showToast('Key deleted successfully!');
      Promise.all([loadStats(), loadLicenses()]);
    };

    function logout() {
      token = null;
      localStorage.removeItem('token');
      heroSection.classList.remove('hidden');
      dashboard.classList.add('hidden');
      showToast('Logged out successfully');
    }

    // Modal handlers
    const modals = {
      login: document.getElementById('loginModal'),
      register: document.getElementById('registerModal'),
      create: document.getElementById('createKeyModal')
    };

    document.getElementById('openLogin').onclick = () => {
      modals.login.style.display = 'flex';
      setTimeout(() => modals.login.classList.add('show'), 10);
    };

    document.getElementById('openRegister').onclick = () => {
      modals.register.style.display = 'flex';
      setTimeout(() => modals.register.classList.add('show'), 10);
    };

    document.getElementById('createKeyBtn').onclick = () => {
      modals.create.style.display = 'flex';
      setTimeout(() => modals.create.classList.add('show'), 10);
    };

    // Close handlers
    document.getElementById('closeLoginModal').onclick = () => {
      modals.login.classList.remove('show');
      setTimeout(() => modals.login.style.display = 'none', 300);
    };

    document.getElementById('closeRegisterModal').onclick = () => {
      modals.register.classList.remove('show');
      setTimeout(() => modals.register.style.display = 'none', 300);
    };

    document.getElementById('closeCreateModal').onclick = () => {
      modals.create.classList.remove('show');
      setTimeout(() => modals.create.style.display = 'none', 300);
    };

    // Switch between modals
    document.getElementById('switchToRegister').onclick = (e) => {
      e.preventDefault();
      modals.login.classList.remove('show');
      setTimeout(() => {
        modals.login.style.display = 'none';
        modals.register.style.display = 'flex';
        setTimeout(() => modals.register.classList.add('show'), 10);
      }, 300);
    };

    document.getElementById('switchToLogin').onclick = (e) => {
      e.preventDefault();
      modals.register.classList.remove('show');
      setTimeout(() => {
        modals.register.style.display = 'none';
        modals.login.style.display = 'flex';
        setTimeout(() => modals.login.classList.add('show'), 10);
      }, 300);
    };

    // Login submit
    document.getElementById('loginSubmit').onclick = async () => {
      const username = document.getElementById('loginUsername').value;
      const password = document.getElementById('loginPassword').value;
      if (!username || !password) return showToast('Fill all fields', 'error');
      
      try {
        const result = await apiCall('/api/auth/login', 'POST', { username, password });
        token = result.access_token;
        localStorage.setItem('token', token);
        modals.login.classList.remove('show');
        setTimeout(() => modals.login.style.display = 'none', 300);
        await loadDashboard();
        showToast('Login successful!');
      } catch (e) { showToast(e.message, 'error'); }
    };

    // Register submit
    document.getElementById('registerSubmit').onclick = async () => {
      const username = document.getElementById('registerUsername').value;
      const email = document.getElementById('registerEmail').value;
      const password = document.getElementById('registerPassword').value;
      if (!username || !email || !password) return showToast('Fill all fields', 'error');
      
      try {
        const result = await apiCall('/api/auth/register', 'POST', { username, email, password });
        token = result.access_token;
        localStorage.setItem('token', token);
        modals.register.classList.remove('show');
        setTimeout(() => modals.register.style.display = 'none', 300);
        await loadDashboard();
        showToast('Registration successful!');
      } catch (e) { showToast(e.message, 'error'); }
    };

    // Create key submit
    document.getElementById('createKeySubmit').onclick = async () => {
      const duration = parseInt(document.getElementById('keyDuration').value);
      const note = document.getElementById('keyNote').value;
      
      try {
        await apiCall('/api/licenses/create', 'POST', { duration_days: duration, note });
        modals.create.classList.remove('show');
        setTimeout(() => modals.create.style.display = 'none', 300);
        document.getElementById('keyNote').value = '';
        await Promise.all([loadStats(), loadLicenses()]);
        showToast('License key created!');
      } catch (e) { showToast(e.message, 'error'); }
    };

    // Logout
    document.getElementById('logoutBtn').onclick = logout;

    // Check login status
    if (token) loadDashboard().catch(() => logout());

    // Auto-refresh
    setInterval(async () => {
      if (token && !dashboard.classList.contains('hidden')) {
        await Promise.all([loadStats(), loadLicenses()]);
      }
    }, 30000);
  </script>
</body>
</html>
"""

# ========== FRONTEND ROUTES ==========
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    return HTML_TEMPLATE

@app.get("/{full_path:path}", response_class=HTMLResponse)
async def catch_all(full_path: str):
    return HTML_TEMPLATE

# ========== RUN ==========
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
