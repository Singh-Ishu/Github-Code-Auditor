import os
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Header
import hashlib
import hmac

load_dotenv()

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")
app = FastAPI()

def verify_signature(payload_body, secret_token, signature_header):
    if not signature_header:
        raise HTTPException(status_code = 403, detail = "x-hub-signature-256 is missing")
    hash_object = hmac.new(secret_token.encode('utf-8'), msg = payload_body, digestmod='sha256')
    expected_signature = "sha256=" + hash_object.hexdigest()

    if not hmac.compare_digest(expected_signature, signature_header):
        raise HTTPException(status_code = 403, detail = "Request signature didn't match")

@app.post("/")
async def receive_trigger(request: Request, x_hub_signature_256: str = Header(None)):
    payload_body =  await request.body()
    verify_signature(payload_body,WEBHOOK_SECRET, x_hub_signature_256)

    payload = await request.json()
    action = payload.get("action")
    allowed_actions = ("opened","synchronized")

    if action not in allowed_actions:
        return {
            "status": "ignored", 
            "message": f"Action '{action}' ignored. Only processing {allowed_actions}"
        }

    
    return {"status": "success", "message": "Starting processing of the PR"}