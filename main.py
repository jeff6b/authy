from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse
import psycopg2, os, random, string, time, hmac, hashlib, secrets
from datetime import datetime, timedelta

app = FastAPI()
DATABASE_URL = os.getenv("DATABASE_URL")

SECRET = "CHANGE_THIS_TO_LONG_RANDOM_SECRET"

# ===== DB =====
def db():
    return psycopg2.connect(DATABASE_URL, sslmode="require")

# ===== INIT =====
def init():
    conn = db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS keys (
        key TEXT PRIMARY KEY,
        hwid TEXT,
        expires_at TIMESTAMP,
        status TEXT DEFAULT 'active'
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        key TEXT,
        hwid TEXT,
        created_at TIMESTAMP,
        last_seen TIMESTAMP,
        active BOOLEAN
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        id INT PRIMARY KEY DEFAULT 1,
        killswitch BOOLEAN DEFAULT FALSE
    );
    """)

    cur.execute("INSERT INTO settings (id) VALUES (1) ON CONFLICT DO NOTHING;")

    conn.commit()
    cur.close()
    conn.close()

init()

# ===== UTILS =====
def gen_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=20))

def verify_sig(token, hwid, ts, sig):
    msg = f"{token}:{hwid}:{ts}"
    expected = hmac.new(SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)

# ===== GEN KEY =====
@app.get("/gen")
def gen():
    conn = db()
    cur = conn.cursor()

    key = gen_key()
    exp = datetime.utcnow() + timedelta(days=7)

    cur.execute("INSERT INTO keys (key, expires_at, status) VALUES (%s, %s, %s)",
                (key, exp, "active"))

    conn.commit()
    cur.close()
    conn.close()

    return PlainTextResponse(key)

# ===== AUTH =====
@app.get("/auth")
def auth(key: str, hwid: str):
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT killswitch FROM settings WHERE id=1")
    if cur.fetchone()[0]:
        return {"success": False, "reason": "killswitch"}

    cur.execute("SELECT hwid, expires_at, status FROM keys WHERE key=%s", (key,))
    row = cur.fetchone()

    if not row:
        return {"success": False}

    shwid, exp, status = row

    if status != "active" or datetime.utcnow() > exp:
        return {"success": False}

    if shwid and shwid != hwid:
        return {"success": False}

    if not shwid:
        cur.execute("UPDATE keys SET hwid=%s WHERE key=%s", (hwid, key))

    token = secrets.token_hex(16)

    cur.execute("""
    INSERT INTO sessions (token, key, hwid, created_at, last_seen, active)
    VALUES (%s, %s, %s, %s, %s, %s)
    """, (token, key, hwid, datetime.utcnow(), datetime.utcnow(), True))

    conn.commit()
    cur.close()
    conn.close()

    return {"success": True, "token": token}

# ===== HEARTBEAT =====
@app.get("/heartbeat")
def heartbeat(token: str, hwid: str, ts: int, sig: str):
    if abs(time.time() - ts) > 10:
        return {"status": "invalid"}

    if not verify_sig(token, hwid, ts, sig):
        return {"status": "invalid"}

    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT active FROM sessions WHERE token=%s", (token,))
    row = cur.fetchone()

    if not row or not row[0]:
        return {"status": "revoked"}

    cur.execute("SELECT killswitch FROM settings WHERE id=1")
    if cur.fetchone()[0]:
        return {"status": "killswitch"}

    cur.execute("UPDATE sessions SET last_seen=%s WHERE token=%s",
                (datetime.utcnow(), token))

    conn.commit()
    cur.close()
    conn.close()

    return {"status": "active"}

# ===== KICK =====
@app.get("/kick")
def kick(key: str):
    conn = db()
    cur = conn.cursor()

    cur.execute("UPDATE sessions SET active=false WHERE key=%s", (key,))
    cur.execute("UPDATE keys SET status='revoked' WHERE key=%s", (key,))

    conn.commit()
    cur.close()
    conn.close()

    return {"ok": True}

# ===== KILLSWITCH =====
@app.get("/killswitch")
def ks():
    conn = db()
    cur = conn.cursor()

    cur.execute("UPDATE settings SET killswitch = NOT killswitch WHERE id=1")

    conn.commit()
    cur.close()
    conn.close()

    return {"ok": True}

# ===== DASHBOARD =====
@app.get("/", response_class=HTMLResponse)
def dash():
    conn = db()
    cur = conn.cursor()

    cur.execute("SELECT key, hwid, status FROM keys")
    rows = cur.fetchall()

    cur.execute("SELECT killswitch FROM settings WHERE id=1")
    ks = cur.fetchone()[0]

    cur.close()
    conn.close()

    # ✅ FIXED: build rows separately
    table_rows = ""
    for k, h, s in rows:
        table_rows += f"""
        <tr>
            <td>{k}</td>
            <td>{h}</td>
            <td>{s}</td>
            <td><button onclick="kickKey('{k}')">Kick</button></td>
        </tr>
        """

    return f"""
<html>
<head>
<style>
body {{background:#0b0b0b;color:white;font-family:Segoe UI}}
.tab {{padding:10px;cursor:pointer;display:inline-block}}
table {{width:100%;margin-top:10px}}
button {{background:#333;color:white;border:none;padding:6px}}
textarea {{background:#111;color:white}}
</style>
</head>

<body>

<h2>Auth Dashboard</h2>

<button onclick="gen()">Generate Key</button>

<table border=1>
<tr><th>Key</th><th>HWID</th><th>Status</th><th>Action</th></tr>
{table_rows}
</table>

<br>
<button onclick="toggle()">KillSwitch: {"ON" if ks else "OFF"}</button>

<script>
function gen() {{
    fetch('/gen').then(r=>r.text()).then(alert)
}}

function kickKey(k) {{
    fetch('/kick?key='+k).then(()=>location.reload())
}}

function toggle() {{
    fetch('/killswitch').then(()=>location.reload())
}}
</script>

</body>
</html>
"""
