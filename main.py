from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse
import psycopg2
import os
import random
import string
from datetime import datetime, timedelta

app = FastAPI()

DATABASE_URL = os.getenv("DATABASE_URL")

# ===== GENERATE KEY =====
def generate_key(length=20):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# ===== ENSURE TABLE EXISTS =====
def init_db():
    conn = psycopg2.connect(DATABASE_URL, sslmode="require")
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS keys (
        key TEXT PRIMARY KEY,
        hwid TEXT,
        expires_at TIMESTAMP
    )
    """)

    conn.commit()
    cur.close()
    conn.close()

init_db()

# ===== GENERATE KEY =====
@app.get("/gen")
def gen():
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode="require")
        cur = conn.cursor()

        key = generate_key()
        expires = datetime.utcnow() + timedelta(days=7)

        cur.execute(
            "INSERT INTO keys (key, expires_at) VALUES (%s, %s)",
            (key, expires)
        )
        conn.commit()

        cur.close()
        conn.close()

        return PlainTextResponse(key)

    except Exception as e:
        print("ERROR:", e)
        return PlainTextResponse(str(e), status_code=500)

# ===== AUTH =====
@app.get("/auth")
def auth(key: str, hwid: str):
    try:
        conn = psycopg2.connect(DATABASE_URL, sslmode="require")
        cur = conn.cursor()

        cur.execute("SELECT hwid, expires_at FROM keys WHERE key=%s", (key,))
        result = cur.fetchone()

        if not result:
            return {"success": False}

        stored_hwid, expires_at = result

        # Expired
        if datetime.utcnow() > expires_at:
            return {"success": False}

        # HWID mismatch
        if stored_hwid and stored_hwid != hwid:
            return {"success": False}

        # Bind HWID first time
        if not stored_hwid:
            cur.execute("UPDATE keys SET hwid=%s WHERE key=%s", (hwid, key))
            conn.commit()

        cur.close()
        conn.close()

        return {"success": True}

    except Exception as e:
        print("ERROR:", e)
        return {"success": False}

# ===== PANEL =====
@app.get("/", response_class=HTMLResponse)
def panel():
    return """
    <html>
    <body style="background:#0f0f0f;color:white;text-align:center;font-family:sans-serif">
        <h1>Key System</h1>

        <button onclick="gen()">Generate Key</button>
        <p id="key"></p>

        <button onclick="copyLoader()">Copy Loader</button>

        <script>
        let currentKey = "";

        function gen() {
            fetch('/gen')
            .then(res => res.text())
            .then(k => {
                currentKey = k;
                document.getElementById('key').innerText = k;
            });
        }

        function copyLoader() {
            if (!currentKey) return alert("Generate a key first");

            const loader = `
local script_key = "` + currentKey + `"

-- try executor HWID first
local hwid = (gethwid and gethwid()) or game:GetService("RbxAnalyticsService"):GetClientId()

local url = "https://YOUR-RENDER-URL/auth?key=" .. script_key .. "&hwid=" .. hwid
local response = game:HttpGet(url)

local data = game:GetService("HttpService"):JSONDecode(response)

if not data.success then
    game.Players.LocalPlayer:Kick("Invalid Key")
    return
end
`

            navigator.clipboard.writeText(loader);
            alert("Loader copied!");
        }
        </script>
    </body>
    </html>
    """
