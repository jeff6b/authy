package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"
)

var db *sql.DB

// ===== INIT DB =====
func initDB() {
	connStr := os.Getenv("DATABASE_URL")

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("DB connection failed:", err)
	}

	fmt.Println("Connected to DB")
}

// ===== GENERATE RANDOM KEY =====
func generateKey() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 20)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// ===== CREATE KEY IN DB =====
func createKey() string {
	key := generateKey()

	_, err := db.Exec(
		"INSERT INTO keys(key, expires_at) VALUES($1, NOW() + INTERVAL '7 days')",
		key,
	)

	if err != nil {
		log.Println("Insert error:", err)
	}

	return key
}

// ===== AUTH HANDLER =====
func authHandler(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	hwid := r.URL.Query().Get("hwid")

	var storedHWID sql.NullString
	var expiresAt time.Time

	err := db.QueryRow(
		"SELECT hwid, expires_at FROM keys WHERE key=$1",
		key,
	).Scan(&storedHWID, &expiresAt)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":false}`))
		return
	}

	// Expiration check
	if time.Now().After(expiresAt) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":false}`))
		return
	}

	// HWID mismatch
	if storedHWID.Valid && storedHWID.String != hwid {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":false}`))
		return
	}

	// Bind HWID if empty
	if !storedHWID.Valid {
		_, err := db.Exec("UPDATE keys SET hwid=$1 WHERE key=$2", hwid, key)
		if err != nil {
			log.Println(err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"success":true}`))
}

// ===== PANEL PAGE =====
func panelHandler(w http.ResponseWriter, r *http.Request) {
	html := `
	<html>
	<head>
	<title>Key System</title>
	</head>
	<body style="background:#0f0f0f;color:white;font-family:sans-serif;text-align:center">
		<h1>Key Generator</h1>
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
local hwid = game:GetService("RbxAnalyticsService"):GetClientId()

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
	`
	fmt.Fprint(w, html)
}

// ===== GENERATE KEY ENDPOINT =====
func genHandler(w http.ResponseWriter, r *http.Request) {
	key := createKey()
	fmt.Fprint(w, key)
}

// ===== MAIN =====
func main() {
	rand.Seed(time.Now().UnixNano())

	initDB()

	http.HandleFunc("/", panelHandler)
	http.HandleFunc("/gen", genHandler)
	http.HandleFunc("/auth", authHandler)

	log.Println("Server running on :10000")
	http.ListenAndServe(":10000", nil)
}
