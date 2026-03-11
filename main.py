import os
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
import asyncpg
from dotenv import load_dotenv
import uvicorn

# Load environment variables
load_dotenv()

# ========== CONFIGURATION ==========
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://neondb_owner:npg_S7hoDMeaw2cQ@ep-wandering-dream-ah21egpt-pooler.c-3.us-east-1.aws.neon.tech/neondb?sslmode=require")

# ========== DATABASE CONNECTION POOL ==========
class Database:
    def __init__(self):
        self.pool = None

    async def connect(self):
        """Create connection pool"""
        self.pool = await asyncpg.create_pool(DATABASE_URL, min_size=5, max_size=20)
        await self.init_db()

    async def disconnect(self):
        """Close connection pool"""
        if self.pool:
            await self.pool.close()

    async def init_db(self):
        """Initialize database tables"""
        async with self.pool.acquire() as conn:
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
            
            # Create indexes for performance
            await conn.execute('CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(key)')
            await conn.execute('CREATE INDEX IF NOT EXISTS idx_licenses_user_id ON licenses(user_id)')
            await conn.execute('CREATE INDEX IF NOT EXISTS idx_heartbeat_license_id ON heartbeat_logs(license_id)')
            await conn.execute('CREATE INDEX IF NOT EXISTS idx_heartbeat_timestamp ON heartbeat_logs(timestamp)')

db = Database()

# ========== LIFESPAN HANDLER ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db.connect()
    print("✅ Database connected")
    yield
    # Shutdown
    await db.disconnect()
    print("✅ Database disconnected")

# ========== FASTAPI APP ==========
app = FastAPI(
    title="Lua Auth System",
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
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
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
    max_hwids: int = 1
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

# ========== PUBLIC API ENDPOINTS (for Lua clients) ==========
@app.post("/api/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(request: HeartbeatRequest, req: Request):
    """Lua clients call this every 60 seconds"""
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
    async with db.pool.acquire() as conn:
        # Check if user exists
        existing = await conn.fetchval(
            "SELECT id FROM users WHERE username = $1 OR email = $2",
            user.username, user.email
        )
        
        if existing:
            raise HTTPException(status_code=400, detail="Username or email already taken")
        
        # Create user
        hashed = pwd_context.hash(user.password)
        api_key = secrets.token_urlsafe(32)
        
        user_id = await conn.fetchval(
            "INSERT INTO users (username, password_hash, email, api_key) VALUES ($1, $2, $3, $4) RETURNING id",
            user.username, hashed, user.email, api_key
        )
        
        # Create token
        token = create_access_token({"sub": user.username, "id": user_id})
        
        return {"access_token": token, "token_type": "bearer"}

@app.post("/api/auth/login", response_model=TokenResponse)
async def login(user: UserLogin):
    """Login user"""
    async with db.pool.acquire() as conn:
        db_user = await conn.fetchrow(
            "SELECT * FROM users WHERE username = $1",
            user.username
        )
        
        if not db_user or not pwd_context.verify(user.password, db_user['password_hash']):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        token = create_access_token({"sub": user.username, "id": db_user['id']})
        
        return {"access_token": token, "token_type": "bearer"}

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
    async with db.pool.acquire() as conn:
        # Generate unique key
        key = generate_license_key()
        while await conn.fetchval("SELECT id FROM licenses WHERE key = $1", key):
            key = generate_license_key()
        
        # Create license
        expires_at = datetime.now() + timedelta(days=license_data.duration_days)
        license_id = await conn.fetchval(
            """
            INSERT INTO licenses 
            (key, user_id, expires_at, note, max_hwid_resets) 
            VALUES ($1, $2, $3, $4, $5) 
            RETURNING id
            """,
            key, current_user['id'], expires_at, license_data.note, 
            license_data.max_hwids * 3
        )
        
        return LicenseResponse(
            key=key,
            expires_at=expires_at.isoformat(),
            status="active"
        )

@app.get("/api/licenses")
async def get_licenses(current_user: dict = Depends(get_current_user)):
    """Get all licenses for current user"""
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
        old_hwid = license['hwid']
        await conn.execute(
            "UPDATE licenses SET hwid = NULL, hwid_resets_used = hwid_resets_used + 1 WHERE id = $1",
            license['id']
        )
        
        return {
            "success": True,
            "message": f"HWID reset for {request.key}. {license['max_hwid_resets'] - license['hwid_resets_used'] - 1} resets remaining.",
            "old_hwid": old_hwid
        }

@app.delete("/api/licenses/{key}")
async def delete_license(
    key: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete a license"""
    async with db.pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM licenses WHERE key = $1 AND user_id = $2",
            key, current_user['id']
        )
        
        if result.split()[-1] == "0":
            raise HTTPException(status_code=404, detail="License not found")
        
        return {"success": True}

# ========== STATS & ACTIVITY ==========
@app.get("/api/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    """Get dashboard stats"""
    async with db.pool.acquire() as conn:
        # Total licenses
        total = await conn.fetchval(
            "SELECT COUNT(*) FROM licenses WHERE user_id = $1",
            current_user['id']
        )
        
        # Active licenses (not expired, status active)
        active = await conn.fetchval(
            """
            SELECT COUNT(*) FROM licenses 
            WHERE user_id = $1 
            AND status = 'active' 
            AND expires_at > CURRENT_TIMESTAMP
            """,
            current_user['id']
        )
        
        # Online now (heartbeat in last 2 minutes)
        online = await conn.fetchval(
            """
            SELECT COUNT(*) FROM licenses 
            WHERE user_id = $1 
            AND last_heartbeat IS NOT NULL
            AND EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - last_heartbeat)) < 120
            """,
            current_user['id']
        )
        
        # Expiring soon (next 7 days)
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

@app.get("/api/activity")
async def get_activity(current_user: dict = Depends(get_current_user)):
    """Get recent activity"""
    async with db.pool.acquire() as conn:
        logs = await conn.fetch(
            """
            SELECT h.*, l.key 
            FROM heartbeat_logs h
            JOIN licenses l ON h.license_id = l.id
            WHERE l.user_id = $1
            ORDER BY h.timestamp DESC
            LIMIT 50
            """,
            current_user['id']
        )
        
        result = []
        for log in logs:
            log = dict(log)
            result.append({
                "key": log['key'],
                "hwid": log['hwid'][:8] + "..." if log['hwid'] and len(log['hwid']) > 8 else log['hwid'],
                "timestamp": log['timestamp'].isoformat(),
                "ip": log['ip_address']
            })
        
        return result

# ========== FRONTEND (HTML/CSS/JS all in one) ==========
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LuaAuth · Key Management</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #111117;
            --bg-tertiary: #1a1a24;
            --accent-blue: #3b82f6;
            --accent-blue-dark: #2563eb;
            --accent-purple: #8b5cf6;
            --accent-green: #10b981;
            --accent-orange: #f59e0b;
            --accent-red: #ef4444;
            --text-primary: #ffffff;
            --text-secondary: #a0a0b0;
            --text-muted: #6b6b7c;
            --border-color: #2a2a35;
            --glass-bg: rgba(20, 20, 30, 0.7);
            --glass-border: rgba(255, 255, 255, 0.05);
            --shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
        }

        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #0a0a0f 0%, #050507 100%);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.5;
        }

        /* Navigation */
        .navbar {
            position: sticky;
            top: 0;
            width: 100%;
            z-index: 1000;
            transition: all 0.3s ease;
            background: transparent;
        }

        .navbar.scrolled {
            background: var(--glass-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--glass-border);
        }

        .nav-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 1rem 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .nav-logo {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .nav-logo i {
            font-size: 1.75rem;
        }

        .nav-links {
            display: flex;
            gap: 2rem;
        }

        .nav-links a {
            color: var(--text-secondary);
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s ease;
            position: relative;
        }

        .nav-links a:hover,
        .nav-links a.active {
            color: var(--text-primary);
        }

        .nav-links a::after {
            content: '';
            position: absolute;
            bottom: -4px;
            left: 0;
            width: 0;
            height: 2px;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple));
            transition: width 0.3s ease;
        }

        .nav-links a:hover::after,
        .nav-links a.active::after {
            width: 100%;
        }

        .nav-user {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .user-menu {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            background: var(--glass-bg);
            backdrop-filter: blur(8px);
            border: 1px solid var(--glass-border);
            border-radius: 2rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .user-menu:hover {
            background: var(--bg-tertiary);
        }

        .username {
            font-weight: 500;
            color: var(--text-primary);
        }

        .btn-logout {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            width: 40px;
            height: 40px;
            border-radius: 50%;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s ease;
        }

        .btn-logout:hover {
            background: var(--accent-red);
            border-color: var(--accent-red);
            color: white;
        }

        .mobile-menu-btn {
            display: none;
            background: transparent;
            border: none;
            color: var(--text-primary);
            font-size: 1.5rem;
            cursor: pointer;
        }

        /* Auth Container */
        .auth-container {
            min-height: calc(100vh - 80px);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }

        .auth-card {
            background: var(--glass-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--glass-border);
            border-radius: 1.5rem;
            padding: 2.5rem;
            width: 100%;
            max-width: 450px;
            box-shadow: var(--shadow);
            animation: slideUp 0.5s ease;
        }

        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .auth-header {
            text-align: center;
            margin-bottom: 2rem;
        }

        .auth-header i {
            font-size: 3rem;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 1rem;
        }

        .auth-header h2 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }

        .auth-header p {
            color: var(--text-secondary);
        }

        .auth-tabs {
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            background: var(--bg-secondary);
            padding: 0.5rem;
            border-radius: 1rem;
        }

        .tab-btn {
            flex: 1;
            padding: 0.75rem;
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-weight: 600;
            cursor: pointer;
            border-radius: 0.75rem;
            transition: all 0.3s ease;
        }

        .tab-btn.active {
            background: var(--accent-blue);
            color: white;
        }

        .auth-form {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        .auth-form.hidden {
            display: none;
        }

        .form-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .form-group label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .form-group input,
        .form-group select {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 0.75rem;
            padding: 0.75rem 1rem;
            color: var(--text-primary);
            font-size: 1rem;
            transition: all 0.3s ease;
        }

        .form-group input:focus,
        .form-group select:focus {
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 0.75rem;
            color: white;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(59, 130, 246, 0.3);
        }

        .btn-secondary {
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            padding: 0.75rem 1.5rem;
            border-radius: 0.75rem;
            color: var(--text-primary);
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .btn-secondary:hover {
            background: var(--bg-secondary);
        }

        .btn-danger {
            background: linear-gradient(135deg, #ef4444, #dc2626);
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 0.75rem;
            color: white;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .btn-danger:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(239, 68, 68, 0.3);
        }

        .btn-danger:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        /* Dashboard */
        .dashboard-container {
            max-width: 1400px;
            margin: 2rem auto;
            padding: 0 2rem;
        }

        .dashboard-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
        }

        .header-content h1 {
            font-size: 2.5rem;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }

        .header-content p {
            color: var(--text-secondary);
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: var(--glass-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--glass-border);
            border-radius: 1.5rem;
            padding: 1.5rem;
            display: flex;
            align-items: center;
            gap: 1.5rem;
            transition: transform 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-4px);
        }

        .stat-icon {
            width: 60px;
            height: 60px;
            border-radius: 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
        }

        .stat-icon.blue {
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(37, 99, 235, 0.2));
            color: var(--accent-blue);
        }

        .stat-icon.green {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.2), rgba(5, 150, 105, 0.2));
            color: var(--accent-green);
        }

        .stat-icon.purple {
            background: linear-gradient(135deg, rgba(139, 92, 246, 0.2), rgba(124, 58, 237, 0.2));
            color: var(--accent-purple);
        }

        .stat-icon.orange {
            background: linear-gradient(135deg, rgba(245, 158, 11, 0.2), rgba(217, 119, 6, 0.2));
            color: var(--accent-orange);
        }

        .stat-info {
            flex: 1;
        }

        .stat-label {
            display: block;
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-bottom: 0.25rem;
        }

        .stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--text-primary);
        }

        /* Licenses Section */
        .licenses-section,
        .activity-section {
            background: var(--glass-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--glass-border);
            border-radius: 1.5rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }

        .search-box {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 2rem;
            padding: 0.5rem 1rem;
        }

        .search-box i {
            color: var(--text-secondary);
        }

        .search-box input {
            background: transparent;
            border: none;
            color: var(--text-primary);
            outline: none;
            width: 250px;
        }

        .table-container {
            overflow-x: auto;
        }

        .licenses-table {
            width: 100%;
            border-collapse: collapse;
        }

        .licenses-table th {
            text-align: left;
            padding: 1rem;
            color: var(--text-secondary);
            font-weight: 500;
            border-bottom: 1px solid var(--border-color);
        }

        .licenses-table td {
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
        }

        .licenses-table tr:hover {
            background: var(--bg-tertiary);
        }

        .status-badge {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 2rem;
            font-size: 0.85rem;
            font-weight: 500;
        }

        .status-badge.active {
            background: rgba(16, 185, 129, 0.2);
            color: var(--accent-green);
        }

        .status-badge.expired {
            background: rgba(239, 68, 68, 0.2);
            color: var(--accent-red);
        }

        .status-badge.suspended {
            background: rgba(245, 158, 11, 0.2);
            color: var(--accent-orange);
        }

        .hwid-cell {
            font-family: monospace;
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .actions-cell {
            display: flex;
            gap: 0.5rem;
        }

        .action-btn {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            width: 32px;
            height: 32px;
            border-radius: 0.5rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .action-btn:hover {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }

        .action-btn.reset:hover {
            background: var(--accent-orange);
            border-color: var(--accent-orange);
            color: white;
        }

        .action-btn.delete:hover {
            background: var(--accent-red);
            border-color: var(--accent-red);
            color: white;
        }

        /* Activity List */
        .activity-list {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .activity-item {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 1rem;
            background: var(--bg-secondary);
            border-radius: 1rem;
            animation: fadeIn 0.5s ease;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateX(-10px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        .activity-icon {
            width: 40px;
            height: 40px;
            border-radius: 0.75rem;
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(139, 92, 246, 0.2));
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--accent-blue);
        }

        .activity-details {
            flex: 1;
        }

        .activity-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 0.25rem;
        }

        .activity-key {
            font-weight: 600;
            color: var(--accent-blue);
        }

        .activity-time {
            color: var(--text-muted);
            font-size: 0.85rem;
        }

        .activity-hwid {
            color: var(--text-secondary);
            font-size: 0.9rem;
            font-family: monospace;
        }

        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(4px);
            z-index: 2000;
            align-items: center;
            justify-content: center;
            animation: fadeIn 0.3s ease;
        }

        .modal.show {
            display: flex;
        }

        .modal-content {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 1.5rem;
            width: 100%;
            max-width: 500px;
            animation: slideUp 0.3s ease;
        }

        .modal-header {
            padding: 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-header h3 {
            font-size: 1.25rem;
            color: var(--text-primary);
        }

        .close-btn {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-size: 1.5rem;
            cursor: pointer;
            transition: color 0.3s ease;
        }

        .close-btn:hover {
            color: var(--text-primary);
        }

        .modal-body {
            padding: 1.5rem;
        }

        .warning-icon {
            text-align: center;
            margin-bottom: 1rem;
        }

        .warning-icon i {
            font-size: 3rem;
            color: var(--accent-orange);
        }

        .warning-text {
            color: var(--accent-orange);
            font-size: 0.9rem;
            margin: 0.5rem 0;
        }

        .modal-footer {
            padding: 1.5rem;
            border-top: 1px solid var(--border-color);
            display: flex;
            justify-content: flex-end;
            gap: 1rem;
        }

        /* Toast */
        .toast {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: var(--glass-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--glass-border);
            border-radius: 1rem;
            padding: 1rem 1.5rem;
            transform: translateX(400px);
            transition: transform 0.3s ease;
            z-index: 3000;
        }

        .toast.show {
            transform: translateX(0);
        }

        .toast-content {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .toast-content i {
            font-size: 1.25rem;
        }

        .toast.success i {
            color: var(--accent-green);
        }

        .toast.error i {
            color: var(--accent-red);
        }

        .toast.info i {
            color: var(--accent-blue);
        }

        /* Utility Classes */
        .hidden {
            display: none !important;
        }

        .loading-row {
            text-align: center;
            padding: 3rem !important;
            color: var(--text-secondary);
        }

        .loading-activity {
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
        }

        /* Responsive */
        @media (max-width: 768px) {
            .nav-links,
            .nav-user {
                display: none;
            }
            
            .mobile-menu-btn {
                display: block;
            }
            
            .nav-links.show {
                display: flex;
                flex-direction: column;
                position: absolute;
                top: 100%;
                left: 0;
                right: 0;
                background: var(--glass-bg);
                backdrop-filter: blur(12px);
                padding: 1rem;
                border-bottom: 1px solid var(--glass-border);
            }
            
            .dashboard-header {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }
            
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .modal-content {
                margin: 1rem;
            }
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar" id="navbar">
        <div class="nav-container">
            <div class="nav-logo">
                <i class="fas fa-key"></i>
                <span>LuaAuth</span>
            </div>
            <div class="nav-links" id="navLinks">
                <a href="#" class="active">Dashboard</a>
                <a href="#">Licenses</a>
                <a href="#">Activity</a>
                <a href="#">Docs</a>
            </div>
            <div class="nav-user" id="navUser">
                <div class="user-menu">
                    <span class="username" id="usernameDisplay">Loading...</span>
                    <i class="fas fa-chevron-down"></i>
                </div>
                <button class="btn-logout" id="logoutBtn">
                    <i class="fas fa-sign-out-alt"></i>
                </button>
            </div>
            <button class="mobile-menu-btn" id="mobileMenuBtn">
                <i class="fas fa-bars"></i>
            </button>
        </div>
    </nav>

    <!-- Auth Container -->
    <div class="auth-container" id="authContainer">
        <div class="auth-card">
            <div class="auth-header">
                <i class="fas fa-key"></i>
                <h2>Welcome to LuaAuth</h2>
                <p>Secure key management for your Lua scripts</p>
            </div>
            <div class="auth-tabs">
                <button class="tab-btn active" id="loginTab">Login</button>
                <button class="tab-btn" id="registerTab">Register</button>
            </div>
            <div class="auth-form" id="loginForm">
                <div class="form-group">
                    <label><i class="fas fa-user"></i> Username</label>
                    <input type="text" id="loginUsername" placeholder="Enter username">
                </div>
                <div class="form-group">
                    <label><i class="fas fa-lock"></i> Password</label>
                    <input type="password" id="loginPassword" placeholder="Enter password">
                </div>
                <button class="btn-primary" id="loginBtn">
                    <i class="fas fa-sign-in-alt"></i> Login
                </button>
            </div>
            <div class="auth-form hidden" id="registerForm">
                <div class="form-group">
                    <label><i class="fas fa-user"></i> Username</label>
                    <input type="text" id="registerUsername" placeholder="Choose username">
                </div>
                <div class="form-group">
                    <label><i class="fas fa-envelope"></i> Email</label>
                    <input type="email" id="registerEmail" placeholder="Enter email">
                </div>
                <div class="form-group">
                    <label><i class="fas fa-lock"></i> Password</label>
                    <input type="password" id="registerPassword" placeholder="Choose password">
                </div>
                <button class="btn-primary" id="registerBtn">
                    <i class="fas fa-user-plus"></i> Register
                </button>
            </div>
        </div>
    </div>

    <!-- Dashboard Container -->
    <div class="dashboard-container hidden" id="dashboardContainer">
        <div class="dashboard-header">
            <div class="header-content">
                <h1>Dashboard</h1>
                <p>Manage your license keys and monitor activity</p>
            </div>
            <button class="btn-primary" id="createLicenseBtn">
                <i class="fas fa-plus"></i> New License
            </button>
        </div>

        <!-- Stats Grid -->
        <div class="stats-grid" id="statsGrid">
            <div class="stat-card">
                <div class="stat-icon blue">
                    <i class="fas fa-key"></i>
                </div>
                <div class="stat-info">
                    <span class="stat-label">Total Licenses</span>
                    <span class="stat-value" id="totalLicenses">0</span>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon green">
                    <i class="fas fa-check-circle"></i>
                </div>
                <div class="stat-info">
                    <span class="stat-label">Active</span>
                    <span class="stat-value" id="activeLicenses">0</span>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon purple">
                    <i class="fas fa-wifi"></i>
                </div>
                <div class="stat-info">
                    <span class="stat-label">Online Now</span>
                    <span class="stat-value" id="onlineNow">0</span>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon orange">
                    <i class="fas fa-clock"></i>
                </div>
                <div class="stat-info">
                    <span class="stat-label">Expiring Soon</span>
                    <span class="stat-value" id="expiringSoon">0</span>
                </div>
            </div>
        </div>

        <!-- Licenses Table -->
        <div class="licenses-section">
            <div class="section-header">
                <h2>Your Licenses</h2>
                <div class="search-box">
                    <i class="fas fa-search"></i>
                    <input type="text" placeholder="Search keys..." id="searchLicenses">
                </div>
            </div>
            <div class="table-container">
                <table class="licenses-table" id="licensesTable">
                    <thead>
                        <tr>
                            <th>Key</th>
                            <th>Status</th>
                            <th>HWID</th>
                            <th>Expires</th>
                            <th>Last Seen</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="licensesBody">
                        <tr>
                            <td colspan="6" class="loading-row">
                                <i class="fas fa-spinner fa-spin"></i> Loading licenses...
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Recent Activity -->
        <div class="activity-section">
            <h2>Recent Activity</h2>
            <div class="activity-list" id="activityList">
                <div class="loading-activity">
                    <i class="fas fa-spinner fa-spin"></i> Loading activity...
                </div>
            </div>
        </div>
    </div>

    <!-- Create License Modal -->
    <div class="modal" id="createLicenseModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Create New License</h3>
                <button class="close-btn" id="closeModalBtn">&times;</button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label>Duration (days)</label>
                    <select id="licenseDuration">
                        <option value="7">7 days</option>
                        <option value="30" selected>30 days</option>
                        <option value="90">90 days</option>
                        <option value="365">1 year</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Max HWID Resets</label>
                    <select id="licenseResets">
                        <option value="1">1 reset</option>
                        <option value="3" selected>3 resets</option>
                        <option value="5">5 resets</option>
                        <option value="10">10 resets</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Note (optional)</label>
                    <input type="text" id="licenseNote" placeholder="e.g., VIP customer">
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn-secondary" id="cancelModalBtn">Cancel</button>
                <button class="btn-primary" id="confirmCreateBtn">
                    <i class="fas fa-plus"></i> Create License
                </button>
            </div>
        </div>
    </div>

    <!-- Reset HWID Modal -->
    <div class="modal" id="resetHWIDModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Reset HWID</h3>
                <button class="close-btn" id="closeResetModalBtn">&times;</button>
            </div>
            <div class="modal-body">
                <div class="warning-icon">
                    <i class="fas fa-exclamation-triangle"></i>
                </div>
                <p>Are you sure you want to reset the HWID for <strong id="resetKeyDisplay"></strong>?</p>
                <p class="warning-text">This will unbind the current hardware ID. The user will need to authenticate again.</p>
                <div class="form-group">
                    <label>
                        <input type="checkbox" id="confirmReset">
                        I understand this action cannot be undone
                    </label>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn-secondary" id="cancelResetBtn">Cancel</button>
                <button class="btn-danger" id="confirmResetBtn" disabled>
                    <i class="fas fa-undo-alt"></i> Reset HWID
                </button>
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
        // API Configuration
        const API_BASE_URL = window.location.origin;

        // State
        let token = localStorage.getItem('token');
        let currentUser = null;

        // DOM Elements
        const navbar = document.getElementById('navbar');
        const authContainer = document.getElementById('authContainer');
        const dashboardContainer = document.getElementById('dashboardContainer');
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        const loginTab = document.getElementById('loginTab');
        const registerTab = document.getElementById('registerTab');
        const loginBtn = document.getElementById('loginBtn');
        const registerBtn = document.getElementById('registerBtn');
        const logoutBtn = document.getElementById('logoutBtn');
        const usernameDisplay = document.getElementById('usernameDisplay');
        const createLicenseBtn = document.getElementById('createLicenseBtn');
        const createLicenseModal = document.getElementById('createLicenseModal');
        const resetHWIDModal = document.getElementById('resetHWIDModal');
        const toast = document.getElementById('toast');
        const toastMessage = document.getElementById('toastMessage');
        const toastIcon = document.getElementById('toastIcon');

        // Scroll effect
        window.addEventListener('scroll', () => {
            if (window.scrollY > 50) {
                navbar.classList.add('scrolled');
            } else {
                navbar.classList.remove('scrolled');
            }
        });

        // Mobile menu
        document.getElementById('mobileMenuBtn').addEventListener('click', () => {
            document.getElementById('navLinks').classList.toggle('show');
        });

        // Tab switching
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

        // Toast
        function showToast(message, type = 'success') {
            toastMessage.textContent = message;
            toast.className = `toast show ${type}`;
            
            switch(type) {
                case 'success':
                    toastIcon.className = 'fas fa-check-circle';
                    break;
                case 'error':
                    toastIcon.className = 'fas fa-exclamation-circle';
                    break;
                case 'info':
                    toastIcon.className = 'fas fa-info-circle';
                    break;
            }
            
            setTimeout(() => {
                toast.classList.remove('show');
            }, 3000);
        }

        // API call
        async function apiCall(endpoint, method = 'GET', data = null) {
            const headers = {
                'Content-Type': 'application/json'
            };
            
            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }
            
            const options = {
                method,
                headers
            };
            
            if (data) {
                options.body = JSON.stringify(data);
            }
            
            try {
                const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
                const result = await response.json();
                
                if (!response.ok) {
                    throw new Error(result.detail || 'API call failed');
                }
                
                return result;
            } catch (error) {
                showToast(error.message, 'error');
                throw error;
            }
        }

        // Login
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
                
                await loadUserData();
                showToast('Login successful!');
                
                authContainer.classList.add('hidden');
                dashboardContainer.classList.remove('hidden');
            } catch (error) {}
        });

        // Register
        registerBtn.addEventListener('click', async () => {
            const username = document.getElementById('registerUsername').value;
            const email = document.getElementById('registerEmail').value;
            const password = document.getElementById('registerPassword').value;
            
            if (!username || !email || !password) {
                showToast('Please fill in all fields', 'error');
                return;
            }
            
            try {
                const result = await apiCall('/api/auth/register', 'POST', { username, email, password });
                token = result.access_token;
                localStorage.setItem('token', token);
                
                await loadUserData();
                showToast('Registration successful!');
                
                authContainer.classList.add('hidden');
                dashboardContainer.classList.remove('hidden');
            } catch (error) {}
        });

        // Logout
        logoutBtn.addEventListener('click', () => {
            token = null;
            localStorage.removeItem('token');
            authContainer.classList.remove('hidden');
            dashboardContainer.classList.add('hidden');
            showToast('Logged out successfully');
        });

        // Load user data
        async function loadUserData() {
            try {
                currentUser = await apiCall('/api/user/me');
                usernameDisplay.textContent = currentUser.username;
                
                await Promise.all([
                    loadStats(),
                    loadLicenses(),
                    loadActivity()
                ]);
            } catch (error) {
                logoutBtn.click();
            }
        }

        // Load stats
        async function loadStats() {
            try {
                const stats = await apiCall('/api/stats');
                
                document.getElementById('totalLicenses').textContent = stats.total_licenses;
                document.getElementById('activeLicenses').textContent = stats.active_licenses;
                document.getElementById('onlineNow').textContent = stats.online_now;
                document.getElementById('expiringSoon').textContent = stats.expiring_soon;
            } catch (error) {
                console.error('Failed to load stats:', error);
            }
        }

        // Load licenses
        async function loadLicenses() {
            try {
                const licenses = await apiCall('/api/licenses');
                
                const tbody = document.getElementById('licensesBody');
                
                if (licenses.length === 0) {
                    tbody.innerHTML = `
                        <tr>
                            <td colspan="6" style="text-align: center; padding: 3rem; color: var(--text-secondary);">
                                <i class="fas fa-key" style="font-size: 2rem; margin-bottom: 1rem; opacity: 0.5;"></i>
                                <p>No licenses yet. Create your first one!</p>
                            </td>
                        </tr>
                    `;
                    return;
                }
                
                tbody.innerHTML = licenses.map(license => {
                    const statusClass = license.online ? 'active' : license.status;
                    const statusText = license.online ? 'ONLINE' : (license.status.toUpperCase() || 'OFFLINE');
                    
                    return `
                        <tr>
                            <td><code style="color: var(--accent-blue);">${license.key}</code></td>
                            <td>
                                <span class="status-badge ${statusClass}">
                                    ${license.online ? '🟢' : '⚫'} ${statusText}
                                </span>
                            </td>
                            <td class="hwid-cell">
                                ${license.hwid ? license.hwid.substring(0, 8) + '...' : 'Not bound'}
                            </td>
                            <td>${new Date(license.expires_at).toLocaleDateString()}</td>
                            <td>${license.last_heartbeat ? new Date(license.last_heartbeat).toLocaleString() : 'Never'}</td>
                            <td class="actions-cell">
                                <button class="action-btn reset" onclick="openResetModal('${license.key}')" title="Reset HWID">
                                    <i class="fas fa-undo-alt"></i>
                                </button>
                                <button class="action-btn delete" onclick="deleteLicense('${license.key}')" title="Delete License">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </td>
                        </tr>
                    `;
                }).join('');
            } catch (error) {
                console.error('Failed to load licenses:', error);
            }
        }

        // Load activity
        async function loadActivity() {
            try {
                const activity = await apiCall('/api/activity');
                
                const activityList = document.getElementById('activityList');
                
                if (activity.length === 0) {
                    activityList.innerHTML = `
                        <div style="text-align: center; padding: 2rem; color: var(--text-secondary);">
                            <i class="fas fa-history" style="font-size: 2rem; margin-bottom: 1rem; opacity: 0.5;"></i>
                            <p>No activity yet</p>
                        </div>
                    `;
                    return;
                }
                
                activityList.innerHTML = activity.map(item => `
                    <div class="activity-item">
                        <div class="activity-icon">
                            <i class="fas fa-heartbeat"></i>
                        </div>
                        <div class="activity-details">
                            <div class="activity-header">
                                <span class="activity-key">${item.key}</span>
                                <span class="activity-time">${new Date(item.timestamp).toLocaleString()}</span>
                            </div>
                            <div class="activity-hwid">
                                <i class="fas fa-microchip"></i> ${item.hwid}
                                <span style="margin-left: 1rem;"><i class="fas fa-ip"></i> ${item.ip}</span>
                            </div>
                        </div>
                    </div>
                `).join('');
            } catch (error) {
                console.error('Failed to load activity:', error);
            }
        }

        // Create license modal
        createLicenseBtn.addEventListener('click', () => {
            createLicenseModal.classList.add('show');
        });

        document.getElementById('closeModalBtn').addEventListener('click', () => {
            createLicenseModal.classList.remove('show');
        });

        document.getElementById('cancelModalBtn').addEventListener('click', () => {
            createLicenseModal.classList.remove('show');
        });

        document.getElementById('confirmCreateBtn').addEventListener('click', async () => {
            const duration = parseInt(document.getElementById('licenseDuration').value);
            const resets = parseInt(document.getElementById('licenseResets').value);
            const note = document.getElementById('licenseNote').value;
            
            try {
                await apiCall('/api/licenses/create', 'POST', {
                    duration_days: duration,
                    max_hwids: resets,
                    note: note || null
                });
                
                createLicenseModal.classList.remove('show');
                showToast('License created successfully!');
                
                document.getElementById('licenseNote').value = '';
                
                await Promise.all([
                    loadStats(),
                    loadLicenses()
                ]);
            } catch (error) {}
        });

        // Reset HWID modal
        window.openResetModal = (key) => {
            currentResetKey = key;
            document.getElementById('resetKeyDisplay').textContent = key;
            document.getElementById('confirmReset').checked = false;
            document.getElementById('confirmResetBtn').disabled = true;
            resetHWIDModal.classList.add('show');
        };

        document.getElementById('closeResetModalBtn').addEventListener('click', () => {
            resetHWIDModal.classList.remove('show');
        });

        document.getElementById('cancelResetBtn').addEventListener('click', () => {
            resetHWIDModal.classList.remove('show');
        });

        document.getElementById('confirmReset').addEventListener('change', (e) => {
            document.getElementById('confirmResetBtn').disabled = !e.target.checked;
        });

        document.getElementById('confirmResetBtn').addEventListener('click', async () => {
            try {
                await apiCall('/api/licenses/reset-hwid', 'POST', {
                    key: currentResetKey,
                    confirm: true
                });
                
                resetHWIDModal.classList.remove('show');
                showToast('HWID reset successfully!');
                
                await loadLicenses();
            } catch (error) {}
        });

        // Delete license
        window.deleteLicense = async (key) => {
            if (!confirm(`Are you sure you want to delete license ${key}? This cannot be undone.`)) {
                return;
            }
            
            try {
                await apiCall(`/api/licenses/${key}`, 'DELETE');
                showToast('License deleted successfully!');
                
                await Promise.all([
                    loadStats(),
                    loadLicenses()
                ]);
            } catch (error) {}
        };

        // Search
        document.getElementById('searchLicenses').addEventListener('input', (e) => {
            const searchTerm = e.target.value.toLowerCase();
            const rows = document.querySelectorAll('#licensesBody tr');
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchTerm) ? '' : 'none';
            });
        });

        // Auto-refresh every 30 seconds
        setInterval(async () => {
            if (token) {
                await Promise.all([
                    loadStats(),
                    loadLicenses(),
                    loadActivity()
                ]);
            }
        }, 30000);

        // Check if logged in
        if (token) {
            loadUserData().then(() => {
                authContainer.classList.add('hidden');
                dashboardContainer.classList.remove('hidden');
            }).catch(() => {
                logoutBtn.click();
            });
        }

        // Close modals on outside click
        window.addEventListener('click', (e) => {
            if (e.target === createLicenseModal) {
                createLicenseModal.classList.remove('show');
            }
            if (e.target === resetHWIDModal) {
                resetHWIDModal.classList.remove('show');
            }
        });
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve the frontend HTML"""
    return HTML_TEMPLATE

@app.get("/{full_path:path}", response_class=HTMLResponse)
async def catch_all(full_path: str):
    """Catch all routes to serve frontend for client-side routing"""
    return HTML_TEMPLATE

# ========== RUN ==========
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
