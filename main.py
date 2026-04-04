from fastapi import FastAPI
from fastapi.responses import StreamingResponse, HTMLResponse
import mss
import io
from PIL import Image
import uvicorn

app = FastAPI(title="Broken Monitor Screenshot Tool")

@app.get("/screenshot")
async def get_screenshot():
    try:
        with mss.mss() as sct:
            # Capture primary monitor (change [1] if you have multiple monitors)
            monitor = sct.monitors[1]
            screenshot = sct.grab(monitor)

            img = Image.frombytes("RGB", screenshot.size, screenshot.rgb)
            
            # Convert to PNG bytes
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='PNG', optimize=True)
            img_byte_arr.seek(0)

        return StreamingResponse(img_byte_arr, media_type="image/png")
    
    except Exception as e:
        return {"error": str(e)}

@app.get("/", response_class=HTMLResponse)
async def home():
    return """
    <html>
        <head><title>Broken Monitor Server</title></head>
        <body style="background:#111; color:#0f0; font-family:Consolas; text-align:center; padding:50px;">
            <h1>✅ Screenshot Server Running</h1>
            <p>Access screenshot at: <code>http://YOUR_IP:8000/screenshot</code></p>
            <p><strong>Leave this window open.</strong></p>
        </body>
    </html>
    """

if __name__ == "__main__":
    print("Starting Broken Monitor Screenshot Server on http://0.0.0.0:8000")
    print("Find your IP address with: ipconfig")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
