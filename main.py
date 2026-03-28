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

    # Build rows separately
    table_rows = ""
    for k, h, s in rows:
        # Handle None values for HWID
        hwid_display = h if h else "Not bound"
        table_rows += f"""
        <tr>
            <td>{k}</td>
            <td>{hwid_display}</td>
            <td>{s}</td>
            <td><button onclick="kickKey('{k}')">Kick</button></td>
        </tr>
        """

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auth Dashboard</title>
    <style>
        body {{
            background: #0b0b0b;
            color: white;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h2 {{
            color: #4CAF50;
            margin-bottom: 20px;
        }}
        .btn {{
            background: #333;
            color: white;
            border: none;
            padding: 10px 20px;
            cursor: pointer;
            border-radius: 4px;
            margin: 5px;
            transition: background 0.3s;
        }}
        .btn:hover {{
            background: #555;
        }}
        .btn-danger {{
            background: #dc3545;
        }}
        .btn-danger:hover {{
            background: #c82333;
        }}
        .btn-success {{
            background: #28a745;
        }}
        .btn-success:hover {{
            background: #218838;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: #1a1a1a;
        }}
        th, td {{
            border: 1px solid #333;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background: #2c2c2c;
            color: #4CAF50;
        }}
        tr:hover {{
            background: #252525;
        }}
        .killswitch {{
            margin-top: 20px;
            padding: 15px;
            background: #1a1a1a;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 Authentication Dashboard</h2>
        
        <div>
            <button class="btn btn-success" onclick="generateKey()">✨ Generate New Key</button>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>License Key</th>
                    <th>HWID</th>
                    <th>Status</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
        
        <div class="killswitch">
            <button class="btn {'btn-danger' if ks else 'btn'}" onclick="toggleKillswitch()">
                🛡️ KillSwitch: {'🔴 ACTIVE' if ks else '🟢 INACTIVE'}
            </button>
        </div>
    </div>

    <script>
        async function generateKey() {{
            try {{
                const response = await fetch('/gen');
                const key = await response.text();
                alert('New license key generated:\\n\\n' + key + '\\n\\nThis key expires in 7 days.');
                location.reload();
            }} catch (error) {{
                alert('Error generating key: ' + error.message);
            }}
        }}

        async function kickKey(key) {{
            if (confirm('Are you sure you want to revoke this key? This action cannot be undone.')) {{
                try {{
                    const response = await fetch('/kick?key=' + encodeURIComponent(key));
                    const result = await response.json();
                    if (result.ok) {{
                        alert('Key revoked successfully');
                        location.reload();
                    }} else {{
                        alert('Failed to revoke key');
                    }}
                }} catch (error) {{
                    alert('Error revoking key: ' + error.message);
                }}
            }}
        }}

        async function toggleKillswitch() {{
            try {{
                const response = await fetch('/killswitch');
                const result = await response.json();
                if (result.ok) {{
                    alert('KillSwitch toggled successfully');
                    location.reload();
                }} else {{
                    alert('Failed to toggle KillSwitch');
                }}
            }} catch (error) {{
                alert('Error toggling KillSwitch: ' + error.message);
            }}
        }}
    </script>
</body>
</html>
    """

    return HTMLResponse(content=html_content)
