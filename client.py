import os
import base64
import hashlib
import secrets
import requests
from PIL import Image
from reedsolo import RSCodec

# Cryptography Primitives
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

SERVER_URL = "http://127.0.0.1:8000"
DELIMITER = b"##END_PAYLOAD##"
CONSTANT_DIMENSION = (1200, 1200)

# Initialize Reed-Solomon Error Correction (Adds 100 bytes of redundancy)
rs = RSCodec(100)

# =====================================================================
# 🔐 CRYPTO & MITM PROTECTION
# =====================================================================
def derive_aes_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"steg-session-key")
    return base64.urlsafe_b64encode(hkdf.derive(shared_secret))

def generate_safety_number(public_key_bytes: bytes) -> str:
    """🛡️ PATCH 1: Defeats MitM attacks by generating a human-readable hash."""
    key_hash = hashlib.sha256(public_key_bytes).hexdigest()
    numeric_hash = str(int(key_hash[:16], 16))[:20]
    return " ".join([numeric_hash[i:i+5] for i in range(0, 20, 5)])

# =====================================================================
# 🎨 RESILIENT STEGANOGRAPHY
# =====================================================================
def generate_random_pixel_path(width: int, height: int, token: str) -> list:
    seed = int(hashlib.sha256(token.encode()).hexdigest(), 16)
    rng = secrets.SystemRandom(seed)
    all_pixels = [(x, y) for y in range(height) for x in range(width)]
    rng.shuffle(all_pixels)
    return all_pixels

def robust_embed(input_path: str, payload: bytes, output_path: str, token: str):
    """Resizes to constant dimensions, applies Error Correction, and embeds payload."""
    # 🛡️ PATCH 3: Enforce constant payload size (1200x1200)
    img = Image.open(input_path).convert('RGB')
    img = img.resize(CONSTANT_DIMENSION, Image.Resampling.LANCZOS)
    encoded_img = img.copy()
    
    # 🛡️ PATCH 2: Apply Reed-Solomon Forward Error Correction
    protected_payload = rs.encode(payload) + DELIMITER
    
    binary_stream = ''.join(format(b, '08b') for b in protected_payload)
    data_len = len(binary_stream)
    pixel_path = generate_random_pixel_path(CONSTANT_DIMENSION[0], CONSTANT_DIMENSION[1], token)
    
    bit_idx = 0
    for x, y in pixel_path:
        if bit_idx >= data_len: break
        r, g, b = img.getpixel((x, y))
        if bit_idx < data_len: r = (r & ~1) | int(binary_stream[bit_idx]); bit_idx += 1
        if bit_idx < data_len: g = (g & ~1) | int(binary_stream[bit_idx]); bit_idx += 1
        if bit_idx < data_len: b = (b & ~1) | int(binary_stream[bit_idx]); bit_idx += 1
        encoded_img.putpixel((x, y), (r, g, b))
        
    encoded_img.save(output_path, "PNG")

def robust_extract(image_path: str, token: str) -> bytes:
    """Extracts the LSB path and automatically repairs corrupted bits."""
    img = Image.open(image_path).convert('RGB')
    width, height = img.size
    pixel_path = generate_random_pixel_path(width, height, token)
    
    bit_accumulator = ""
    extracted_bytes = bytearray()
    
    for x, y in pixel_path:
        r, g, b = img.getpixel((x, y))
        for channel in (r, g, b):
            bit_accumulator += str(channel & 1)
            if len(bit_accumulator) == 8:
                extracted_bytes.append(int(bit_accumulator, 2))
                bit_accumulator = ""
                
                if extracted_bytes.endswith(DELIMITER):
                    raw_protected = bytes(extracted_bytes[:-len(DELIMITER)])
                    # 🛡️ PATCH 2: Repair any bit corruption before returning
                    repaired_payload, _, _ = rs.decode(raw_protected)
                    return bytes(repaired_payload)
                    
    raise ValueError("No delimiter found.")

# =====================================================================
# 🕹️ INTERACTIVE CLIENT
# =====================================================================
def main():
    print("🌟 Production-Grade Steganography Node 🌟")
    choice = input("Select Mode:\n[1] Alice (Send)\n[2] Bob (Receive)\nChoice: ").strip()

    cover_file = "cover_base.png"
    if not os.path.exists(cover_file):
        Image.new("RGB", (800, 800), color=(70, 130, 180)).save(cover_file)

    if choice == "1":
        print("\n--- 🛠️ Sender Pipeline ---")
        token = input("Enter Bob's 32-character Delivery Token: ").strip()
        
        try:
            # 1. Fetch Key from Server
            response = requests.get(f"{SERVER_URL}/public_key/{token}").json()
            bob_public_key = mlkem.MLKEMPublicKey.from_public_bytes(bytes.fromhex(response["public_key"]))
            
            # 2. MitM Safety Check
            print(f"🔒 SAFETY NUMBER: {generate_safety_number(bob_public_key.public_bytes())}")
            input("Verify this matches Bob's screen. Press Enter to proceed...")
            
            message = input("Enter the secret message: ")
            
            # 3. Post-Quantum Crypto
            ciphertext_key_blob, alice_secret = bob_public_key.encapsulate()
            aes_key = derive_aes_key(alice_secret)
            fernet_engine = Fernet(aes_key)
            encrypted_msg = fernet_engine.encrypt(message.encode())
            complete_payload = ciphertext_key_blob + encrypted_msg
            
            # 4. Resilient Embedding & Upload
            out_carrier = "alice_outbound.png"
            robust_embed(cover_file, complete_payload, out_carrier, token)
            
            with open(out_carrier, "rb") as f:
                requests.post(f"{SERVER_URL}/deposit/{token}", files={"file": f})
            print("🚀 Secure payload transmitted and blinded to constant size.")
            os.remove(out_carrier)
            
        except Exception as e:
            print(f"❌ Transmission Error: {e}")

    elif choice == "2":
        print("\n--- 🛠️ Receiver Pipeline ---")
        priv_key_path, pub_key_path, token_path = "bob.priv", "bob.pub", "bob.token"
        
        # 1. Initialization & Registration
        if not os.path.exists(priv_key_path):
            print("🔑 Generating Post-Quantum ML-KEM-768 Keys...")
            bob_priv = mlkem.MLKEMPrivateKey.generate(mlkem.MLKEMParameterSet.ML_KEM_768)
            bob_pub = bob_priv.public_key()
            token = secrets.token_hex(16)
            
            with open(priv_key_path, "wb") as f: f.write(bob_priv.private_bytes())
            with open(pub_key_path, "wb") as f: f.write(bob_pub.public_bytes())
            with open(token_path, "w") as f: f.write(token)
            
            requests.post(f"{SERVER_URL}/register/{token}", json={"public_key_hex": bob_pub.public_bytes().hex()})
        else:
            with open(priv_key_path, "rb") as f: bob_priv = mlkem.MLKEMPrivateKey.from_private_bytes(f.read())
            with open(pub_key_path, "rb") as f: bob_pub = mlkem.MLKEMPublicKey.from_public_bytes(f.read())
            with open(token_path, "r") as f: token = f.read()

        print(f"\n📲 Your Delivery Token: {token}")
        print(f"🔒 Your Safety Number: {generate_safety_number(bob_pub.public_bytes())}")
        
        # 2. Polling Loop
        print("\n📬 Polling mailbox (filtering network chaff)...")
        try:
            hex_packages = requests.get(f"{SERVER_URL}/poll/{token}").json().get("payloads", [])
            for idx, hex_data in enumerate(hex_packages):
                temp_in = f"received_{idx}.png"
                with open(temp_in, "wb") as f: f.write(bytes.fromhex(hex_data))
                
                try:
                    # Attempt robust extraction. Will fail silently if the image is Server Chaff.
                    extracted_bytes = robust_extract(temp_in, token)
                    ciphertext_key_blob = extracted_bytes[:1088]
                    encrypted_msg = extracted_bytes[1088:]
                    
                    bob_secret = bob_priv.decapsulate(ciphertext_key_blob)
                    aes_key = derive_aes_key(bob_secret)
                    decrypted_message = Fernet(aes_key).decrypt(encrypted_msg).decode()
                    
                    print(f"\n🔓 [Valid Message Decrypted]: {decrypted_message}")
                except ValueError:
                    # Ignore expected errors from dummy chaff images
                    pass
                finally:
                    if os.path.exists(temp_in): os.remove(temp_in)
                    
        except Exception as e:
            print(f"❌ Routing Error: {e}")

if __name__ == "__main__":
    main()