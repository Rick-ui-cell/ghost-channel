import io
from fastapi import FastAPI, HTTPException, UploadFile, File, Body
from typing import Dict, List
import uvicorn
from PIL import Image

app = FastAPI(title="Blind Secure Routing Node")

SERVER_DATABASE: Dict[str, Dict] = {}

print("⚙️ Generating Constant-Size Chaff Payload (1200x1200)...")
dummy_img = Image.new("RGB", (1200, 1200), color=(40, 44, 52))
buf = io.BytesIO()
dummy_img.save(buf, format="PNG")
CHAFF_PAYLOAD_HEX = buf.getvalue().hex()

@app.post("/register/{delivery_token}")
async def register_mailbox(delivery_token: str, public_key_hex: str = Body(embed=True)):
    if len(delivery_token) != 32:
        raise HTTPException(status_code=400, detail="Malformed delivery token.")
        
    if delivery_token in SERVER_DATABASE:
        raise HTTPException(status_code=400, detail="Token mailbox already registered.")
        
    SERVER_DATABASE[delivery_token] = {
        "public_key": public_key_hex,
        "messages": []
    }
    print(f"[Server] 🔑 Registered Token {delivery_token[:8]}...")
    return {"status": "success", "message": "Mailbox registered successfully."}

@app.get("/public_key/{delivery_token}")
async def get_public_key(delivery_token: str):
    if delivery_token not in SERVER_DATABASE:
        raise HTTPException(status_code=404, detail="Recipient mailbox token not found.")
    return {"public_key": SERVER_DATABASE[delivery_token]["public_key"]}

@app.post("/deposit/{delivery_token}")
async def deposit_message(delivery_token: str, file: UploadFile = File(...)):
    if delivery_token not in SERVER_DATABASE:
        raise HTTPException(status_code=404, detail="Target token mailbox does not exist.")
        
    file_bytes = await file.read()
    SERVER_DATABASE[delivery_token]["messages"].append(file_bytes)
    print(f"[Server] 📥 Message dropped off at mailbox token: {delivery_token[:8]}...")
    return {"status": "success"}

@app.get("/poll/{delivery_token}")
async def poll_messages(delivery_token: str):
    if delivery_token not in SERVER_DATABASE or not SERVER_DATABASE[delivery_token]["messages"]:
        return {"payloads": [CHAFF_PAYLOAD_HEX]}
        
    payloads = SERVER_DATABASE[delivery_token]["messages"]
    SERVER_DATABASE[delivery_token]["messages"] = []
    return {"payloads": [p.hex() for p in payloads]}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")