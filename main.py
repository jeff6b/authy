from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import mss
import io
import os
import subprocess
import webbrowser
import platform
import psutil
import asyncio
from PIL import Image
from datetime import datetime
import base64
import uvicorn
from typing import Optional, List
import json

app = FastAPI(title="Advanced Remote PC Recovery Tool")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store command history
command_history = []

class CommandRequest(BaseModel):
    command: str
    args: Optional[dict] = {}

class FileRequest(BaseModel):
    path: str

# ============ DASHBOARD HTML (embedded) ============
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Remote PC Recovery Tool - Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 25px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            color: #333;
            font-size: 2em;
            margin-bottom: 10px;
        }
        
        .header p {
            color: #666;
            margin-top: 5px;
        }
        
        .status-badge {
            display: inline-block;
            padding: 5px 15px;
            background: #10b981;
            color: white;
            border-radius: 20px;
            font-size: 0.9em;
            margin-top: 10px;
        }
        
        .screenshot-section {
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        
        .screenshot-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 15px;
        }
        
        .screenshot-header h2 {
            color: #333;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5a67d8;
            transform: translateY(-2px);
        }
        
        .btn-danger {
            background: #ef4444;
            color: white;
        }
        
        .btn-danger:hover {
            background: #dc2626;
        }
        
        .btn-success {
            background: #10b981;
            color: white;
        }
        
        .btn-success:hover {
            background: #059669;
        }
        
        .screenshot-display {
            background: #f3f4f6;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            min-height: 400px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .screenshot-display img {
            max-width: 100%;
            border-radius: 8px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.2);
        }
        
        .controls-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 25px;
            margin-bottom: 25px;
        }
        
        .card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
        }
        
        .card h3 {
            color: #333;
            margin-bottom: 20px;
            font-size: 1.3em;
            border-left: 4px solid #667eea;
            padding-left: 12px;
        }
        
        .input-group {
            margin-bottom: 15px;
        }
        
        .input-group label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
        }
        
        input, select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        
        input:focus, select:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .output {
            background: #1f2937;
            color: #10b981;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            margin-top: 15px;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        
        .info-item {
            background: #f3f4f6;
            padding: 15px;
            border-radius: 8px;
        }
        
        .info-label {
            font-size: 12px;
            color: #6b7280;
            text-transform: uppercase;
            font-weight: 600;
        }
        
        .info-value {
            font-size: 20px;
            font-weight: bold;
            color: #333;
            margin-top: 5px;
        }
        
        .file-list {
            max-height: 300px;
            overflow-y: auto;
        }
        
        .file-item {
            padding: 10px;
            border-bottom: 1px solid #e5e7eb;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .file-item:hover {
            background: #f3f4f6;
        }
        
        .file-name {
            font-weight: 500;
        }
        
        .file-size {
            font-size: 12px;
            color: #6b7280;
            margin-left: 10px;
        }
        
        .history-item {
            padding: 10px;
            border-bottom: 1px solid #e5e7eb;
            font-size: 13px;
        }
        
        .history-command {
            font-family: monospace;
            color: #667eea;
            font-weight: 600;
        }
        
        .history-time {
            font-size: 11px;
            color: #9ca3af;
        }
        
        @media (max-width: 768px) {
            .controls-grid {
                grid-template-columns: 1fr;
            }
            .header h1 {
                font-size: 1.5em;
            }
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #9ca3af;
        }
        
        .error {
            color: #ef4444;
            padding: 10px;
            background: #fee;
            border-radius: 8px;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🖥️ Remote PC Recovery Tool</h1>
            <p>Professional remote assistance for broken monitors</p>
            <span class="status-badge" id="statusBadge">● Connected to Server</span>
        </div>
        
        <div class="screenshot-section">
            <div class="screenshot-header">
                <h2>📸 Live Screen Capture</h2>
                <div>
                    <button class="btn btn-primary" onclick="captureScreenshot()">Capture Now</button>
                    <button class="btn btn-success" onclick="startAutoRefresh()">Auto (5s)</button>
                    <button class="btn btn-danger" onclick="stopAutoRefresh()">Stop</button>
                </div>
            </div>
            <div class="screenshot-display" id="screenshotDisplay">
                <div class="loading">Click "Capture Now" to view screen</div>
            </div>
        </div>
        
        <div class="controls-grid">
            <!-- Browser Control -->
            <div class="card">
                <h3>🌐 Browser Control</h3>
                <div class="input-group">
                    <label>URL to open:</label>
                    <input type="text" id="urlInput" placeholder="https://example.com">
                </div>
                <button class="btn btn-primary" onclick="openURL()" style="width: 100%;">Open in Browser</button>
            </div>
            
            <!-- System Commands -->
            <div class="card">
                <h3>💻 System Commands</h3>
                <div class="input-group">
                    <label>Command:</label>
                    <input type="text" id="commandInput" placeholder="ls, dir, whoami, systeminfo">
                </div>
                <button class="btn btn-primary" onclick="runCommand()" style="width: 100%;">Execute Command</button>
                <div class="output" id="commandOutput">Command output will appear here...</div>
            </div>
            
            <!-- System Info -->
            <div class="card">
                <h3>📊 System Information</h3>
                <button class="btn btn-primary" onclick="getSystemInfo()" style="width: 100%; margin-bottom: 15px;">Refresh System Info</button>
                <div class="info-grid" id="systemInfoGrid">
                    <div class="info-item">
                        <div class="info-label">OS</div>
                        <div class="info-value" id="osInfo">-</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">CPU Usage</div>
                        <div class="info-value" id="cpuInfo">-</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Memory Usage</div>
                        <div class="info-value" id="memoryInfo">-</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Hostname</div>
                        <div class="info-value" id="hostnameInfo">-</div>
                    </div>
                </div>
            </div>
            
            <!-- File Browser -->
            <div class="card">
                <h3>📁 File Browser</h3>
                <div class="input-group">
                    <label>Path:</label>
                    <input type="text" id="filePath" value="C:\\" placeholder="C:\\ or /home/">
                </div>
                <button class="btn btn-primary" onclick="listFiles()" style="width: 100%; margin-bottom: 15px;">Browse Files</button>
                <div class="file-list" id="fileList">Click browse to view files...</div>
            </div>
            
            <!-- Command History -->
            <div class="card">
                <h3>📜 Command History</h3>
                <button class="btn btn-primary" onclick="getHistory()" style="width: 100%; margin-bottom: 15px;">Refresh History</button>
                <div class="file-list" id="historyList">No commands executed yet...</div>
            </div>
            
            <!-- Process List -->
            <div class="card">
                <h3>⚙️ Running Processes</h3>
                <button class="btn btn-primary" onclick="getProcesses()" style="width: 100%; margin-bottom: 15px;">Refresh Processes</button>
                <div class="file-list" id="processList">Click refresh to view processes...</div>
            </div>
        </div>
    </div>
    
    <script>
        let autoRefreshInterval = null;
        const API_URL = '';
        
        async function captureScreenshot() {
            const display = document.getElementById('screenshotDisplay');
            display.innerHTML = '<div class="loading">📸 Capturing screenshot...</div>';
            
            try {
                const response = await fetch('/screenshot/base64');
                const data = await response.json();
                
                if (data.image) {
                    display.innerHTML = `<img src="data:image/jpeg;base64,${data.image}" alt="Screenshot">`;
                } else if (data.error) {
                    display.innerHTML = `<div class="error">Error: ${data.error}</div>`;
                }
            } catch (error) {
                display.innerHTML = `<div class="error">Failed to capture screenshot: ${error.message}</div>`;
            }
        }
        
        function startAutoRefresh() {
            if (autoRefreshInterval) clearInterval(autoRefreshInterval);
            autoRefreshInterval = setInterval(captureScreenshot, 5000);
            alert('Auto-refresh enabled (every 5 seconds)');
        }
        
        function stopAutoRefresh() {
            if (autoRefreshInterval) {
                clearInterval(autoRefreshInterval);
                autoRefreshInterval = null;
                alert('Auto-refresh stopped');
            }
        }
        
        async function openURL() {
            const url = document.getElementById('urlInput').value;
            if (!url) {
                alert('Please enter a URL');
                return;
            }
            
            try {
                const response = await fetch('/browser/open', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url})
                });
                const result = await response.json();
                if (result.status === 'success') {
                    alert(`✅ Opened: ${url}`);
                } else {
                    alert(`❌ Error: ${result.error}`);
                }
            } catch (error) {
                alert(`Failed: ${error.message}`);
            }
        }
        
        async function runCommand() {
            const command = document.getElementById('commandInput').value;
            if (!command) {
                alert('Please enter a command');
                return;
            }
            
            const outputDiv = document.getElementById('commandOutput');
            outputDiv.innerHTML = '⏳ Executing command...';
            
            try {
                const response = await fetch('/command/execute', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({command: command})
                });
                const result = await response.json();
                
                if (result.stdout) {
                    outputDiv.innerHTML = `<strong>✅ Output:</strong><br>${escapeHtml(result.stdout)}`;
                } else if (result.stderr) {
                    outputDiv.innerHTML = `<strong>⚠️ Error:</strong><br>${escapeHtml(result.stderr)}`;
                } else if (result.error) {
                    outputDiv.innerHTML = `<strong>❌ Failed:</strong><br>${escapeHtml(result.error)}`;
                }
                
                // Refresh history after command
                getHistory();
            } catch (error) {
                outputDiv.innerHTML = `<strong>❌ Error:</strong><br>${error.message}`;
            }
        }
        
        async function getSystemInfo() {
            try {
                const response = await fetch('/system/info');
                const info = await response.json();
                
                document.getElementById('osInfo').innerHTML = info.os || '-';
                document.getElementById('cpuInfo').innerHTML = info.cpu_percent ? `${info.cpu_percent}%` : '-';
                document.getElementById('memoryInfo').innerHTML = info.memory_percent ? `${info.memory_percent}%` : '-';
                document.getElementById('hostnameInfo').innerHTML = info.hostname || '-';
            } catch (error) {
                console.error('Failed to get system info:', error);
            }
        }
        
        async function listFiles() {
            const path = document.getElementById('filePath').value;
            const fileListDiv = document.getElementById('fileList');
            fileListDiv.innerHTML = '<div class="loading">Loading files...</div>';
            
            try {
                const response = await fetch('/file/list', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({path: path})
                });
                const data = await response.json();
                
                if (data.files) {
                    fileListDiv.innerHTML = data.files.map(file => `
                        <div class="file-item" onclick="document.getElementById('filePath').value = '${path}/${file.name}'; listFiles();">
                            <span class="file-name">${file.type === 'directory' ? '📁' : '📄'} ${escapeHtml(file.name)}</span>
                            <span class="file-size">${formatFileSize(file.size)}</span>
                        </div>
                    `).join('');
                } else if (data.error) {
                    fileListDiv.innerHTML = `<div class="error">Error: ${data.error}</div>`;
                }
            } catch (error) {
                fileListDiv.innerHTML = `<div class="error">Failed to list files: ${error.message}</div>`;
            }
        }
        
        async function getHistory() {
            const historyDiv = document.getElementById('historyList');
            historyDiv.innerHTML = '<div class="loading">Loading history...</div>';
            
            try {
                const response = await fetch('/history');
                const data = await response.json();
                
                if (data.history && data.history.length > 0) {
                    historyDiv.innerHTML = data.history.map(item => `
                        <div class="history-item">
                            <div class="history-command">> ${escapeHtml(item.command)}</div>
                            <div class="history-time">${new Date(item.timestamp).toLocaleString()}</div>
                            <div style="font-size: 12px; color: #666; margin-top: 5px;">${escapeHtml(item.output.substring(0, 100))}</div>
                        </div>
                    `).join('');
                } else {
                    historyDiv.innerHTML = '<div class="loading">No command history yet</div>';
                }
            } catch (error) {
                historyDiv.innerHTML = `<div class="error">Failed to load history: ${error.message}</div>`;
            }
        }
        
        async function getProcesses() {
            const processDiv = document.getElementById('processList');
            processDiv.innerHTML = '<div class="loading">Loading processes...</div>';
            
            try {
                const response = await fetch('/processes');
                const data = await response.json();
                
                if (data.processes) {
                    processDiv.innerHTML = data.processes.map(proc => `
                        <div class="history-item">
                            <strong>${escapeHtml(proc.name || 'Unknown')}</strong>
                            <span style="float: right;">PID: ${proc.pid} | CPU: ${proc.cpu_percent || 0}% | MEM: ${(proc.memory_percent || 0).toFixed(1)}%</span>
                        </div>
                    `).join('');
                }
            } catch (error) {
                processDiv.innerHTML = `<div class="error">Failed to load processes: ${error.message}</div>`;
            }
        }
        
        function formatFileSize(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Initial load
        captureScreenshot();
        getSystemInfo();
        getHistory();
        
        // Refresh system info every 30 seconds
        setInterval(getSystemInfo, 30000);
    </script>
</body>
</html>
"""

# ============ API ENDPOINTS ============

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the main dashboard HTML"""
    return HTMLResponse(content=DASHBOARD_HTML)

@app.get("/screenshot")
async def get_screenshot():
    """Capture screenshot of primary monitor"""
    try:
        with mss.mss() as sct:
            monitor = sct.monitors[1]
            screenshot = sct.grab(monitor)
            img = Image.frombytes("RGB", screenshot.size, screenshot.rgb)
            
            # Compress for faster transfer
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='JPEG', quality=70, optimize=True)
            img_byte_arr.seek(0)
            
        return StreamingResponse(img_byte_arr, media_type="image/jpeg")
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/screenshot/base64")
async def get_screenshot_base64():
    """Capture screenshot and return as base64"""
    try:
        with mss.mss() as sct:
            monitor = sct.monitors[1]
            screenshot = sct.grab(monitor)
            img = Image.frombytes("RGB", screenshot.size, screenshot.rgb)
            
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='JPEG', quality=70)
            img_byte_arr.seek(0)
            
            b64_str = base64.b64encode(img_byte_arr.getvalue()).decode()
            
        return JSONResponse(content={"image": b64_str, "timestamp": datetime.now().isoformat()})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/command/execute")
async def execute_command(cmd: CommandRequest):
    """Execute system commands on the machine"""
    try:
        # Security: whitelist allowed commands
        allowed_prefixes = ['dir', 'ls', 'echo', 'whoami', 'systeminfo', 'tasklist', 'ps', 'pwd', 'hostname']
        cmd_lower = cmd.command.lower().strip()
        
        if not any(cmd_lower.startswith(prefix) for prefix in allowed_prefixes):
            return JSONResponse(
                status_code=403, 
                content={"error": f"Command '{cmd.command}' not allowed for security reasons"}
            )
        
        result = subprocess.run(
            cmd.command, 
            shell=True, 
            capture_output=True, 
            text=True,
            timeout=10
        )
        
        command_history.append({
            "command": cmd.command,
            "timestamp": datetime.now().isoformat(),
            "output": result.stdout[:1000]  # Limit output size
        })
        
        return JSONResponse(content={
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        })
    except subprocess.TimeoutExpired:
        return JSONResponse(status_code=408, content={"error": "Command timed out"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/browser/open")
async def open_browser(request: Request):
    """Open a URL in the default browser"""
    try:
        data = await request.json()
        url = data.get("url", "https://google.com")
        
        webbrowser.open(url)
        return JSONResponse(content={"status": "success", "url_opened": url})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/system/info")
async def get_system_info():
    """Get basic system information"""
    try:
        info = {
            "os": platform.system(),
            "os_version": platform.version(),
            "hostname": platform.node(),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "python_version": platform.python_version(),
            "timestamp": datetime.now().isoformat()
        }
        return JSONResponse(content=info)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/processes")
async def get_processes():
    """Get running processes (limited to top 50)"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            if len(processes) >= 50:
                break
        return JSONResponse(content={"processes": processes})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/file/list")
async def list_files(req: FileRequest):
    """List files in a directory"""
    try:
        path = req.path or os.path.expanduser("~")
        if not os.path.exists(path):
            return JSONResponse(status_code=404, content={"error": "Path not found"})
        
        files = []
        for item in os.listdir(path)[:100]:  # Limit to 100 items
            full_path = os.path.join(path, item)
            try:
                files.append({
                    "name": item,
                    "type": "directory" if os.path.isdir(full_path) else "file",
                    "size": os.path.getsize(full_path) if os.path.isfile(full_path) else 0
                })
            except (OSError, PermissionError):
                files.append({
                    "name": item,
                    "type": "unknown",
                    "size": 0
                })
        
        return JSONResponse(content={"path": path, "files": files})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/history")
async def get_history():
    """Get command execution history"""
    return JSONResponse(content={"history": command_history[-50:]})  # Last 50 commands

# ============ RUN THE SERVER ============
if __name__ == "__main__":
    print("=" * 50)
    print("🖥️  Remote PC Recovery Tool - Server Starting...")
    print("=" * 50)
    print(f"📊 Dashboard URL: http://localhost:8000")
    print(f"📸 Screenshot API: http://localhost:8000/screenshot")
    print(f"💻 System Info API: http://localhost:8000/system/info")
    print("=" * 50)
    print("⚠️  This tool is for authorized use only!")
    print("=" * 50)
    uvicorn.run(app, host="0.0.0.0", port=8000)
