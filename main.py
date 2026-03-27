from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
import psycopg2
import os
import random
import string
from datetime import datetime, timedelta

app = FastAPI()
DATABASE_URL = os.getenv("DATABASE_URL")

# ===== UTILS =====
def db():
    return psycopg2.connect(DATABASE_URL, sslmode="require")

def generate_key(length=20):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# ===== INIT TABLE (adds columns if missing) =====
def init():
    conn = db()
    cur = conn.cursor()

    cur.execute("""
    ALTER TABLE keys
    ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP,
    ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active';
    """)

    conn.commit()
    cur.close()
    conn.close()

init()

# ===== CREATE KEY =====
@app.get("/gen")
def gen():
    conn = db()
    cur = conn.cursor()

    key = generate_key()
    expires = datetime.utcnow() + timedelta(days=7)

    cur.execute("""
    INSERT INTO keys (key, script_id, expires_at, status)
    VALUES (%s, %s, %s, %s)
    """, (key, 1, expires, "active"))

    conn.commit()
    cur.close()
    conn.close()

    return PlainTextResponse(key)

# ===== AUTH =====
@app.get("/auth")
def auth(key: str, hwid: str):
    conn = db()
    cur = conn.cursor()

    cur.execute("""
    SELECT hwid, expires_at, status FROM keys WHERE key=%s
    """, (key,))
    row = cur.fetchone()

    if not row:
        return {"success": False}

    stored_hwid, expires, status = row

    if status != "active":
        return {"success": False}

    if datetime.utcnow() > expires:
        return {"success": False}

    if stored_hwid and stored_hwid != hwid:
        return {"success": False}

    if not stored_hwid:
        cur.execute("UPDATE keys SET hwid=%s WHERE key=%s", (hwid, key))

    conn.commit()
    cur.close()
    conn.close()

    return {"success": True}

# ===== HEARTBEAT =====
@app.get("/heartbeat")
def heartbeat(key: str):
    conn = db()
    cur = conn.cursor()

    cur.execute("""
    UPDATE keys SET last_seen=%s WHERE key=%s
    """, (datetime.utcnow(), key))

    conn.commit()

    # return status
    cur.execute("SELECT status FROM keys WHERE key=%s", (key,))
    status = cur.fetchone()

    cur.close()
    conn.close()

    return {"status": status[0] if status else "invalid"}

# ===== KICK (REVOKE) =====
@app.get("/kick")
def kick(key: str):
    conn = db()
    cur = conn.cursor()

    cur.execute("UPDATE keys SET status='revoked' WHERE key=%s", (key,))
    conn.commit()

    cur.close()
    conn.close()

    return {"ok": True}

# ===== DASHBOARD =====
@app.get("/", response_class=HTMLResponse)
def dashboard():
    conn = db()
    cur = conn.cursor()

    cur.execute("""
    SELECT key, hwid, status, last_seen FROM keys ORDER BY last_seen DESC NULLS LAST
    """)
    rows = cur.fetchall()

    cur.close()
    conn.close()

    html = """
    <html><body style="background:#0f0f0f;color:white;font-family:sans-serif">
    <h1>Dashboard</h1>
    <button onclick="gen()">Generate Key</button>
    <table border="1" style="width:100%;color:white">
    <tr><th>Key</th><th>HWID</th><th>Status</th><th>Last Seen</th><th>Action</th></tr>
    """

    for k, hwid, status, last_seen in rows:
        html += f"""
        <tr>
        <td>{k}</td>
        <td>{hwid}</td>
        <td>{status}</td>
        <td>{last_seen}</td>
        <td><button onclick="kick('{k}')">Kick</button></td>
        </tr>
        """

    html += """
    </table>

    <script>
    function gen() {
        fetch('/gen').then(r=>r.text()).then(alert)
    }

    function kick(k) {
        fetch('/kick?key='+k).then(()=>location.reload())
    }
    </script>

    </body></html>
    """

    return html
