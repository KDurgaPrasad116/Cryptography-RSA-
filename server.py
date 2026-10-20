import os
import time
import base64
import uuid
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
import crypto_utils

app = FastAPI(title="Encrypted TCP Chat - RSA + AES Interactive Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RECEIVED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "received_files")
os.makedirs(RECEIVED_DIR, exist_ok=True)

# State Management
class AliceState:
    def __init__(self, rsa_bits: int = 1024, host: str = "127.0.0.1", tcp_port: int = 65432):
        self.rsa_bits = rsa_bits
        self.host = host
        self.tcp_port = tcp_port
        self.history = []
        self.generate_keys(bits=self.rsa_bits)

    def generate_keys(self, bits: Optional[int] = None):
        if bits:
            self.rsa_bits = bits
        self.private_key, self.public_key = crypto_utils.generate_rsa_keypair(bits=self.rsa_bits)
        self.public_key_pem = self.public_key.export_key().decode("utf-8")
        self.private_key_pem = self.private_key.export_key().decode("utf-8")
        self.key_created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

DEFAULT_HOST = os.environ.get("TCP_HOST", "127.0.0.1")
DEFAULT_TCP_PORT = int(os.environ.get("TCP_PORT", "65432"))
DEFAULT_RSA_BITS = int(os.environ.get("RSA_BITS", "1024"))

alice_state = AliceState(rsa_bits=DEFAULT_RSA_BITS, host=DEFAULT_HOST, tcp_port=DEFAULT_TCP_PORT)

class MessageRequest(BaseModel):
    message: str
    tamper_ciphertext: bool = False
    tamper_tag: bool = False

class KeyRegenRequest(BaseModel):
    bits: int = Field(default=1024, ge=1024, le=4096)

class ConfigUpdateRequest(BaseModel):
    host: Optional[str] = None
    tcp_port: Optional[int] = None
    rsa_bits: Optional[int] = None

@app.get("/api/health")
def health_check():
    return {"status": "ok"}

@app.get("/api/status")
def get_status():
    file_count = len([f for f in os.listdir(RECEIVED_DIR) if os.path.isfile(os.path.join(RECEIVED_DIR, f))])
    return {
        "alice": {
            "name": "Alice (Receiver / Key Authority)",
            "host": alice_state.host,
            "port": alice_state.tcp_port,
            "rsa_bits": alice_state.rsa_bits,
            "algorithm": f"RSA-{alice_state.rsa_bits} (PKCS#1 OAEP) + AES-256 (GCM Mode)",
            "public_key_pem": alice_state.public_key_pem,
            "private_key_pem": alice_state.private_key_pem,
            "created_at": alice_state.key_created_at,
            "files_received_count": file_count,
        },
        "bob": {
            "name": "Bob (Sender / Client)",
            "cipher": "AES-256-GCM",
            "key_exchange": f"RSA-{alice_state.rsa_bits} OAEP",
            "connected_to": f"Alice ({alice_state.host}:{alice_state.tcp_port})",
        },
        "message_count": len(alice_state.history),
    }

@app.post("/api/configure")
def configure_parameters(req: ConfigUpdateRequest):
    if req.host is not None:
        alice_state.host = req.host.strip()
    if req.tcp_port is not None:
        alice_state.tcp_port = req.tcp_port
    if req.rsa_bits is not None and req.rsa_bits in [1024, 2048, 3072, 4096]:
        alice_state.generate_keys(bits=req.rsa_bits)
    return {"success": True, "status": get_status()}

@app.post("/api/regenerate-keys")
def regenerate_keys(req: Optional[KeyRegenRequest] = None):
    bits = req.bits if req else alice_state.rsa_bits
    if bits not in [1024, 2048, 3072, 4096]:
        bits = 1024
    alice_state.generate_keys(bits=bits)
    return {
        "success": True,
        "message": f"Alice generated a brand new RSA-{bits} keypair.",
        "rsa_bits": bits,
        "public_key_pem": alice_state.public_key_pem,
        "created_at": alice_state.key_created_at,
    }

@app.post("/api/send-message")
def send_message(req: MessageRequest):
    plaintext = req.message.strip()
    if not plaintext:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")

    start_time = time.perf_counter()

    # Step 1: Bob generates fresh random 32-byte (256-bit) AES session key
    aes_key = crypto_utils.generate_aes_key()
    aes_key_hex = aes_key.hex()

    # Step 2: Bob encrypts message using AES-GCM
    # Format returned: [16 bytes IV/Nonce] + [16 bytes TAG] + [Ciphertext]
    encrypted_data = crypto_utils.aes_encrypt(aes_key, plaintext.encode("utf-8"))
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    tamper_note = None
    # Simulate MITM attack / tampering if requested
    if req.tamper_ciphertext:
        mutable_ct = bytearray(ciphertext)
        if len(mutable_ct) > 0:
            mutable_ct[0] ^= 0xFF
            ciphertext = bytes(mutable_ct)
            encrypted_data = nonce + tag + ciphertext
            tamper_note = "Attacker altered ciphertext payload in transit (byte 0 inverted)!"
    elif req.tamper_tag:
        mutable_tag = bytearray(tag)
        mutable_tag[0] ^= 0xAA
        tag = bytes(mutable_tag)
        encrypted_data = nonce + tag + ciphertext
        tamper_note = "Attacker modified GCM Authentication Tag in transit!"

    # Step 3: Bob encrypts AES key with Alice's dynamic RSA Public Key
    encrypted_aes_key = crypto_utils.rsa_encrypt(alice_state.public_key, aes_key)

    # Step 4: Bob packages wire payload
    payload = encrypted_data + b"---FILE---"
    wire_packet = encrypted_aes_key + b"---SPLIT---" + payload

    # Step 5: Alice receives and unpacks wire payload
    split_parts = wire_packet.split(b"---SPLIT---", 1)
    recv_encrypted_aes_key = split_parts[0]
    recv_payload = split_parts[1]
    recv_payload_parts = recv_payload.split(b"---FILE---", 1)
    recv_msg_data = recv_payload_parts[0]

    # Step 6: Alice decrypts AES key with RSA Private Key
    rsa_error = None
    try:
        decrypted_aes_key = crypto_utils.rsa_decrypt(alice_state.private_key, recv_encrypted_aes_key)
        rsa_decryption_ok = True
    except Exception as e:
        decrypted_aes_key = None
        rsa_decryption_ok = False
        rsa_error = str(e)

    # Step 7: Alice decrypts message with AES Key and verifies GCM Tag
    decrypted_text = None
    gcm_verified = False
    gcm_error = None

    if rsa_decryption_ok and decrypted_aes_key:
        try:
            decrypted_bytes = crypto_utils.aes_decrypt(decrypted_aes_key, recv_msg_data)
            decrypted_text = decrypted_bytes.decode("utf-8")
            gcm_verified = True
        except Exception as e:
            gcm_verified = False
            gcm_error = f"AES-GCM Authentication Failed: {str(e)} (Message tampered or corrupted!)"
    else:
        gcm_error = f"RSA Key Decryption Failed: {rsa_error}"

    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    item = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "type": "text",
        "sender": "Bob",
        "recipient": "Alice",
        "plaintext": plaintext,
        "decrypted_text": decrypted_text,
        "is_tampered": bool(req.tamper_ciphertext or req.tamper_tag),
        "tamper_note": tamper_note,
        "gcm_verified": gcm_verified,
        "gcm_error": gcm_error,
        "rsa_decryption_ok": rsa_decryption_ok,
        "duration_ms": duration_ms,
        "crypto_breakdown": {
            "rsa_bits": alice_state.rsa_bits,
            "aes_key_hex": aes_key_hex,
            "aes_key_bits": 256,
            "encrypted_aes_key_hex": encrypted_aes_key.hex(),
            "encrypted_aes_key_len": len(encrypted_aes_key),
            "nonce_hex": nonce.hex(),
            "tag_hex": tag.hex(),
            "ciphertext_hex": ciphertext.hex(),
            "wire_total_bytes": len(wire_packet),
            "wire_packet_preview_b64": base64.b64encode(wire_packet[:128]).decode("utf-8") + "...",
        }
    }

    alice_state.history.append(item)
    return item

@app.post("/api/send-file")
async def send_file(
    file: UploadFile = File(...),
    tamper_ciphertext: bool = Form(False),
    tamper_tag: bool = Form(False)
):
    # Sanitize filename (prevent directory traversal)
    raw_filename = os.path.basename(file.filename or "uploaded_file.bin")
    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    start_time = time.perf_counter()

    # Step 1: Bob generates random AES key
    aes_key = crypto_utils.generate_aes_key()

    # Step 2: Bob encrypts file bytes with AES-GCM
    encrypted_file_data = crypto_utils.aes_encrypt(aes_key, file_bytes)
    nonce = encrypted_file_data[:16]
    tag = encrypted_file_data[16:32]
    ciphertext = encrypted_file_data[32:]

    tamper_note = None
    if tamper_ciphertext:
        mutable_ct = bytearray(ciphertext)
        if len(mutable_ct) > 0:
            mutable_ct[0] ^= 0xFF
            ciphertext = bytes(mutable_ct)
            encrypted_file_data = nonce + tag + ciphertext
            tamper_note = "File ciphertext corrupted in transit!"
    elif tamper_tag:
        mutable_tag = bytearray(tag)
        mutable_tag[0] ^= 0xAA
        tag = bytes(mutable_tag)
        encrypted_file_data = nonce + tag + ciphertext
        tamper_note = "File GCM authentication tag corrupted in transit!"

    # Step 3: Bob encrypts AES key with Alice's RSA Public Key
    encrypted_aes_key = crypto_utils.rsa_encrypt(alice_state.public_key, aes_key)

    # Step 4: Bob packages wire payload
    payload = b"---FILE---" + encrypted_file_data
    wire_packet = encrypted_aes_key + b"---SPLIT---" + payload

    # Step 5: Alice receives and decrypts
    split_parts = wire_packet.split(b"---SPLIT---", 1)
    rsa_ok = True
    gcm_ok = False
    gcm_err = None
    saved_filename = None

    try:
        recv_aes_key = crypto_utils.rsa_decrypt(alice_state.private_key, split_parts[0])
    except Exception as e:
        rsa_ok = False
        recv_aes_key = None
        gcm_err = f"RSA decryption failed: {e}"

    if rsa_ok and recv_aes_key:
        try:
            recv_payload_parts = split_parts[1].split(b"---FILE---", 1)
            decrypted_file_bytes = crypto_utils.aes_decrypt(recv_aes_key, recv_payload_parts[1])
            gcm_ok = True

            # Save Alice's copy safely
            safe_basename = "".join(c for c in raw_filename if c.isalnum() or c in "._- ")
            saved_filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{safe_basename}"
            saved_path = os.path.join(RECEIVED_DIR, saved_filename)
            with open(saved_path, "wb") as f:
                f.write(decrypted_file_bytes)
        except Exception as e:
            gcm_ok = False
            gcm_err = f"AES-GCM Authentication Failed: {e}"

    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    item = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "type": "file",
        "sender": "Bob",
        "recipient": "Alice",
        "filename": raw_filename,
        "saved_filename": saved_filename,
        "file_size": len(file_bytes),
        "download_url": f"/api/download-file/{saved_filename}" if saved_filename else None,
        "is_tampered": bool(tamper_ciphertext or tamper_tag),
        "tamper_note": tamper_note,
        "gcm_verified": gcm_ok,
        "gcm_error": gcm_err,
        "rsa_decryption_ok": rsa_ok,
        "duration_ms": duration_ms,
        "crypto_breakdown": {
            "rsa_bits": alice_state.rsa_bits,
            "aes_key_hex": aes_key.hex(),
            "aes_key_bits": 256,
            "encrypted_aes_key_hex": encrypted_aes_key.hex()[:64] + "...",
            "encrypted_aes_key_len": len(encrypted_aes_key),
            "nonce_hex": nonce.hex(),
            "tag_hex": tag.hex(),
            "ciphertext_len": len(ciphertext),
            "wire_total_bytes": len(wire_packet),
        }
    }

    alice_state.history.append(item)
    return item

@app.get("/api/download-file/{filename}")
def download_file(filename: str):
    # Guard against directory traversal attacks
    safe_name = os.path.basename(filename)
    file_path = os.path.join(RECEIVED_DIR, safe_name)
    real_path = os.path.realpath(file_path)
    real_dir = os.path.realpath(RECEIVED_DIR)

    if not real_path.startswith(real_dir) or not os.path.isfile(real_path):
        raise HTTPException(status_code=404, detail="File not found.")
    return FileResponse(real_path, filename=safe_name)

@app.get("/api/history")
def get_history():
    return alice_state.history

@app.post("/api/clear")
def clear_history():
    alice_state.history.clear()
    return {"success": True}

# Mount static frontend files
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="web")

if __name__ == "__main__":
    import uvicorn
    import sys
    import socket

    port = 8000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    else:
        for candidate in [8000, 8080, 8001, 8081, 8888, 5000]:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('127.0.0.1', candidate)) != 0:
                    port = candidate
                    break

    print(f"Starting Encrypted TCP Chat Web Server on http://127.0.0.1:{port} ...")
    uvicorn.run(app, host="127.0.0.1", port=port)
