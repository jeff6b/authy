from fastapi import FastAPI
from fastapi.responses import StreamingResponse, JSONResponse
import mss
import io
from PIL import Image
import uvicorn

app = FastAPI(title="Broken Monitor Screenshot Tool")

@app.get("/screenshot")
async def get_screenshot():
    try:
        with mss.mss() as sct:
            # Capture the primary monitor
            monitor = sct.monitors[1]
            screenshot = sct.grab(monitor)

            img = Image.frombytes("RGB", screenshot.size, screenshot.rgb)
            
            # Convert to PNG bytes
            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format='PNG', optimize=True)
            img_byte_arr.seek(0)

        return StreamingResponse(img_byte_arr, media_type="image/png")

    except Exception as e:
        # Return clear error so the viewer can show it
        return JSONResponse(
            status_code=500,
            content={"error": f"Screenshot capture failed: {str(e)}"}
        )

@app.get("/")
async def home():
    return {
        "status": "ok", 
        "message": "Broken Monitor Screenshot Server is running",
        "usage": "/screenshot"
    }

# For Render deployment
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
