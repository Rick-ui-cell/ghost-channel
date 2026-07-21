import os
import io
import base64
import hashlib
import secrets
import requests
import random
import streamlit as st
from PIL import Image
from reedsolo import RSCodec

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# =====================================================================
# ⚙️ CONFIGURATION
# =====================================================================
SERVER_URL = "https://ghost-channel-tteh.onrender.com"
APP_URL      = "http://localhost:8501"
DELIMITER    = b"##END_PAYLOAD##"
CONSTANT_DIM = (1200, 1200)
rs           = RSCodec(100)

st.set_page_config(page_title="Ghost Channel", page_icon="👻", layout="centered")

# Cleanup legacy ML-KEM keys
for old_file in ["bob.priv", "bob.pub"]:
    if os.path.exists(old_file):
        try:
            if os.path.getsize(old_file) > 200:
                os.remove(old_file)
        except Exception:
            pass

# =====================================================================
# 🔐 CRYPTO ENGINE
# =====================================================================
def derive_aes_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"steg-session-key")
    return base64.urlsafe_b64encode(hkdf.derive(shared_secret))

def generate_safety_number(public_key_bytes: bytes) -> str:
    key_hash = hashlib.sha256(public_key_bytes).hexdigest()
    numeric  = str(int(key_hash[:16], 16))[:20]
    return " ".join([numeric[i:i+5] for i in range(0, 20, 5)])

# =====================================================================
# 🎨 STEGANOGRAPHY ENGINE
# =====================================================================
def _pixel_path(width: int, height: int, token: str) -> list:
    seed   = int(hashlib.sha256(token.encode()).hexdigest(), 16)
    rng    = random.Random(seed)
    pixels = [(x, y) for y in range(height) for x in range(width)]
    rng.shuffle(pixels)
    return pixels

def robust_embed(img_obj: Image.Image, payload: bytes, token: str) -> io.BytesIO:
    img    = img_obj.convert("RGB").resize(CONSTANT_DIM, Image.Resampling.LANCZOS)
    canvas = img.copy()
    blob   = rs.encode(payload) + DELIMITER
    bits   = "".join(format(b, "08b") for b in blob)
    total  = len(bits)
    path   = _pixel_path(*CONSTANT_DIM, token)
    idx    = 0
    for x, y in path:
        if idx >= total:
            break
        r, g, b = img.getpixel((x, y))
        if idx < total: r = (r & ~1) | int(bits[idx]); idx += 1
        if idx < total: g = (g & ~1) | int(bits[idx]); idx += 1
        if idx < total: b = (b & ~1) | int(bits[idx]); idx += 1
        canvas.putpixel((x, y), (r, g, b))
    buf = io.BytesIO()
    canvas.save(buf, format="PNG")
    buf.seek(0)
    return buf

def robust_extract(img_bytes: bytes, token: str) -> bytes:
    img  = Image.open(io.BytesIO(img_bytes)).convert("RGB")
    w, h = img.size
    path = _pixel_path(w, h, token)
    bits = ""
    raw  = bytearray()
    for x, y in path:
        r, g, b = img.getpixel((x, y))
        for ch in (r, g, b):
            bits += str(ch & 1)
            if len(bits) == 8:
                raw.append(int(bits, 2))
                bits = ""
                if raw.endswith(DELIMITER):
                    protected = bytes(raw[:-len(DELIMITER)])
                    repaired, _, _ = rs.decode(protected)
                    return bytes(repaired)
    raise ValueError("Chaff or corrupt image — no payload found.")

# =====================================================================
# 📱 QR GENERATOR (MINIMALIST DARK THEMING)
# =====================================================================
def _qr_svg(data: str, px: int = 5) -> str:
    try:
        GF_EXP = [0] * 512
        GF_LOG = [0] * 256
        x = 1
        for i in range(255):
            GF_EXP[i] = x; GF_LOG[x] = i
            x <<= 1
            if x & 0x100: x ^= 0x11D
        for i in range(255, 512):
            GF_EXP[i] = GF_EXP[i - 255]

        def gf_mul(a, b):
            return 0 if (a == 0 or b == 0) else GF_EXP[GF_LOG[a] + GF_LOG[b]]

        def gf_poly_mul(p, q):
            r = [0] * (len(p) + len(q) - 1)
            for i, a in enumerate(p):
                for j, b in enumerate(q):
                    r[i+j] ^= gf_mul(a, b)
            return r

        def rs_poly(n):
            g = [1]
            for i in range(n): g = gf_poly_mul(g, [1, GF_EXP[i]])
            return g

        def rs_encode(data_bytes, n_ec):
            gen = rs_poly(n_ec)
            msg = list(data_bytes) + [0] * n_ec
            for i in range(len(data_bytes)):
                coef = msg[i]
                if coef:
                    for j in range(1, len(gen)):
                        msg[i+j] ^= gf_mul(gen[j], coef)
            return msg[len(data_bytes):]

        data_enc = data.encode("utf-8")
        n        = len(data_enc)
        versions = [(1,17,7,21),(2,32,10,25),(3,53,15,29),(4,78,20,33)]
        ver, cap, n_ec, size = next((v,c,e,s) for v,c,e,s in versions if c >= n)

        bits = "0100" + format(n, "08b") + "".join(format(b, "08b") for b in data_enc) + "0000"
        while len(bits) % 8: bits += "0"
        codewords = [int(bits[i:i+8], 2) for i in range(0, len(bits), 8)]
        pad_bytes = [0xEC, 0x11]
        i = 0
        while len(codewords) < cap:
            codewords.append(pad_bytes[i % 2])
            i += 1
        ec = rs_encode(codewords, n_ec)
        all_cw = codewords + ec

        mat = [[None]*size for _ in range(size)]

        def add_finder(r, c):
            for dr in range(7):
                for dc in range(7):
                    edge = (dr in (0,6) or dc in (0,6) or (2<=dr<=4 and 2<=dc<=4))
                    mat[r+dr][c+dc] = 1 if edge else 0

        add_finder(0,0); add_finder(0,size-7); add_finder(size-7,0)

        for i in range(8):
            for pos in [(7,i),(i,7),(7,size-1-i),(i,size-8),(size-8,i),(size-1-i,7)]:
                r2,c2=pos
                if 0<=r2<size and 0<=c2<size and mat[r2][c2] is None: mat[r2][c2]=0

        for i in range(8, size-8):
            if mat[6][i] is None: mat[6][i] = i%2==0
            if mat[i][6] is None: mat[i][6] = i%2==0

        mat[size-8][8] = 1
        fmt = 0b101010000010010
        fmt_bits = [(fmt>>i)&1 for i in range(14,-1,-1)]
        fmt_pos = [(8,i) for i in range(6)] + [(8,7),(8,8),(7,8)] + [(i,8) for i in range(5,-1,-1)]
        for (r2,c2),b in zip(fmt_pos, fmt_bits[:9]):
            if mat[r2][c2] is None: mat[r2][c2]=b
        fmt_pos2 = [(size-1-i,8) for i in range(7)] + [(8,size-8),(8,size-7)]
        for (r2,c2),b in zip(fmt_pos2, fmt_bits[7:]):
            if mat[r2][c2] is None: mat[r2][c2]=b

        bit_str = "".join(format(c,"08b") for c in all_cw)
        bi, right, col = 0, True, size - 1
        while col >= 0:
            if col == 6: col -= 1
            rows = range(size-1,-1,-1) if right else range(size)
            for row in rows:
                for dc2 in (0,1):
                    c2 = col - dc2
                    if mat[row][c2] is None:
                        bit = int(bit_str[bi]) if bi < len(bit_str) else 0
                        mat[row][c2] = bit
                        if (row + c2) % 2 == 0: mat[row][c2] ^= 1
                        bi += 1
            right = not right; col -= 2

        for r2 in range(size):
            for c2 in range(size):
                if mat[r2][c2] is None: mat[r2][c2] = 0

        margin = 3
        total_px = (size + 2*margin) * px
        rects = []
        for r2 in range(size):
            for c2 in range(size):
                if mat[r2][c2]:
                    x2 = (c2 + margin) * px
                    y2 = (r2 + margin) * px
                    rects.append(f'<rect x="{x2}" y="{y2}" width="{px}" height="{px}" fill="#A855F7" rx="1"/>')

        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_px}" height="{total_px}" '
            f'style="background:#121218;border:1px solid #22222E;border-radius:12px;">'
            + "".join(rects) + f'</svg>'
        )

    except Exception:
        return (
            f'<div style="background:#121218;border:1px solid #22222E;border-radius:12px;padding:20px;text-align:center;'
            f'font-family:monospace;font-size:11px;color:#A855F7;">{data[:16]}...</div>'
        )

def qr_for_token(token: str, app_url: str) -> str:
    invite = f"{app_url}/?add={token}"
    data   = token if len(invite) > 78 else invite
    return _qr_svg(data, px=5)

# =====================================================================
# 🔑 LOCAL CREDENTIAL MANAGEMENT
# =====================================================================
priv_path, pub_path, token_path = "bob.priv", "bob.pub", "bob.token"

if not os.path.exists(priv_path):
    priv = x25519.X25519PrivateKey.generate()
    pub  = priv.public_key()
    tok  = secrets.token_hex(16)

    priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes  = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    open(priv_path,  "wb").write(priv_bytes)
    open(pub_path,   "wb").write(pub_bytes)
    open(token_path, "w" ).write(tok)

    try:
        requests.post(
            f"{SERVER_URL}/register/{tok}",
            json={"public_key_hex": pub_bytes.hex()},
            timeout=3,
        )
    except Exception:
        pass
else:
    priv_bytes = open(priv_path,  "rb").read()
    pub_bytes  = open(pub_path,   "rb").read()
    tok        = open(token_path, "r" ).read().strip()

    priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
    pub  = x25519.X25519PublicKey.from_public_bytes(pub_bytes)

# Always force token registration on backend load
# Always force token registration on backend load
try:
    requests.post(
        f"{SERVER_URL}/register/{tok}",
        json={"public_key_hex": pub_bytes.hex()},
        timeout=3,
    )
except Exception:
    pass

my_safety = generate_safety_number(pub_bytes)

# =====================================================================
# 🌐 INVITE LINK AUTO-FILL (?add=<token>)
# =====================================================================
params          = st.query_params
prefilled_token = params.get("add", "")

# =====================================================================
# 🎨 HIGH-CONTRAST PROFESSIONAL MINIMALIST STYLING
# =====================================================================
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');
  
  html, body, [data-testid="stAppViewContainer"] {
    background-color: #08080A !important;
    font-family: 'Inter', sans-serif !important;
    color: #E4E4E7 !important;
  }
  
  [data-testid="stHeader"] {
    background: transparent !important;
  }
  
  .block-container {
    padding-top: 2rem !important;
    max-width: 720px !important;
  }

  h1, h2, h3, h4 {
    font-weight: 700 !important;
    letter-spacing: -0.025em !important;
    color: #FFFFFF !important;
  }

  .stTabs [data-baseweb="tab-list"] {
    gap: 8px !important;
    background-color: #121218 !important;
    padding: 6px !important;
    border-radius: 14px !important;
    border: 1px solid #22222E !important;
  }

  .stTabs [data-baseweb="tab"] {
    height: 40px !important;
    border-radius: 10px !important;
    color: #8E8E93 !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important;
    font-size: 13px !important;
    border: none !important;
    padding: 0 18px !important;
    transition: all 0.2s ease !important;
  }

  .stTabs [aria-selected="true"] {
    background-color: #1E1E2A !important;
    color: #A855F7 !important;
    font-weight: 600 !important;
  }

  .stTabs [data-baseweb="tab-highlight"] {
    display: none !important;
  }

  .stTextInput > div > div, .stTextArea > div > div {
    background-color: #121218 !important;
    border: 1px solid #22222E !important;
    border-radius: 12px !important;
    color: #FFFFFF !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 13px !important;
  }

  .stTextInput > div > div:focus-within, .stTextArea > div > div:focus-within {
    border-color: #A855F7 !important;
    box-shadow: 0 0 0 1px #A855F7 !important;
  }

  .stButton > button {
    border-radius: 12px !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 600 !important;
    font-size: 13px !important;
    padding: 10px 20px !important;
    transition: all 0.2s ease !important;
  }

  .stButton > button[kind="primary"] {
    background-color: #A855F7 !important;
    color: #FFFFFF !important;
    border: none !important;
  }

  .stButton > button[kind="primary"]:hover {
    background-color: #9333EA !important;
    box-shadow: 0 4px 20px rgba(168, 85, 247, 0.3) !important;
  }

  .stButton > button[kind="secondary"] {
    background-color: #121218 !important;
    color: #E4E4E7 !important;
    border: 1px solid #22222E !important;
  }

  .stButton > button[kind="secondary"]:hover {
    border-color: #A855F7 !important;
    color: #A855F7 !important;
  }

  code {
    background: #121218 !important;
    border: 1px solid #22222E !important;
    color: #A855F7 !important;
    border-radius: 10px !important;
    padding: 8px 12px !important;
    font-family: 'JetBrains Mono', monospace !important;
  }

  .surface-card {
    background: #121218;
    border: 1px solid #22222E;
    border-radius: 16px;
    padding: 20px;
    margin-bottom: 16px;
  }

  .step-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    font-weight: 700;
    color: #A855F7;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 8px;
  }
</style>
""", unsafe_allow_html=True)

# =====================================================================
# 👻 PIXELATED GHOST HEADER
# =====================================================================
GHOST_SVG = """
<svg xmlns="http://www.w3.org/2000/svg" width="54" height="54" viewBox="0 0 20 20" shape-rendering="crispEdges">
  <rect x="6" y="2" width="8" height="1" fill="#F3E8FF"/>
  <rect x="4" y="3" width="12" height="1" fill="#F3E8FF"/>
  <rect x="3" y="4" width="14" height="2" fill="#F3E8FF"/>
  <rect x="2" y="6" width="16" height="8" fill="#F3E8FF"/>
  
  <rect x="2" y="14" width="3" height="2" fill="#F3E8FF"/>
  <rect x="6" y="14" width="3" height="2" fill="#F3E8FF"/>
  <rect x="11" y="14" width="3" height="2" fill="#F3E8FF"/>
  <rect x="15" y="14" width="3" height="2" fill="#F3E8FF"/>
  
  <rect x="2" y="16" width="2" height="1" fill="#F3E8FF"/>
  <rect x="7" y="16" width="2" height="1" fill="#F3E8FF"/>
  <rect x="12" y="16" width="2" height="1" fill="#F3E8FF"/>
  <rect x="16" y="16" width="2" height="1" fill="#F3E8FF"/>

  <rect x="5" y="7" width="2" height="3" fill="#1E1B4B"/>
  <rect x="13" y="7" width="2" height="3" fill="#1E1B4B"/>
  <rect x="5" y="7" width="1" height="1" fill="#FFFFFF"/>
  <rect x="13" y="7" width="1" height="1" fill="#FFFFFF"/>

  <rect x="4" y="10" width="2" height="1" fill="#F472B6"/>
  <rect x="14" y="10" width="2" height="1" fill="#F472B6"/>

  <rect x="1" y="3" width="1" height="1" fill="#A855F7"/>
  <rect x="0" y="4" width="3" height="1" fill="#A855F7"/>
  <rect x="1" y="5" width="1" height="1" fill="#A855F7"/>

  <rect x="18" y="10" width="1" height="1" fill="#C084FC"/>
  <rect x="17" y="11" width="3" height="1" fill="#C084FC"/>
  <rect x="18" y="12" width="1" height="1" fill="#C084FC"/>
</svg>
"""

st.markdown(f"""
<div style="display: flex; align-items: center; gap: 16px; margin-bottom: 24px;">
  <div>{GHOST_SVG}</div>
  <div>
    <h2 style="margin: 0; padding: 0; font-size: 22px; font-weight: 800; letter-spacing: -0.02em;">GHOST CHANNEL</h2>
    <p style="color:#71717A; font-family:'JetBrains Mono', monospace; font-size:12px; margin: 4px 0 0 0;">
      Zero-knowledge steganographic messenger
    </p>
  </div>
</div>
""", unsafe_allow_html=True)
# Application Header
st.markdown("<h2 style='margin-bottom:0px;'>GHOST CHANNEL</h2>", unsafe_allow_html=True)
st.markdown("<p style='color:#71717A;font-family:\"JetBrains Mono\",monospace;font-size:12px;margin-bottom:24px;'>Zero-knowledge steganographic messenger</p>", unsafe_allow_html=True)

tab_send, tab_recv, tab_id = st.tabs(["SEND", "RECEIVE", "IDENTITY"])

# ─────────────────────────────────────────────
# TAB: SEND
# ─────────────────────────────────────────────
with tab_send:
    st.markdown("<div class='step-label'>01 // RECIPIENT</div>", unsafe_allow_html=True)

    if prefilled_token:
        st.toast("Invite token detected & auto-filled", icon="🔗")

    target = st.text_input(
        "Bob's delivery token:",
        value=prefilled_token,
        placeholder="Paste 32-character token...",
        max_chars=32,
        label_visibility="collapsed",
    )

    if target and len(target) == 32:
        try:
            res            = requests.get(f"{SERVER_URL}/public_key/{target}", timeout=3).json()
            rcpt_pub_bytes = bytes.fromhex(res["public_key"])
            rcpt_pub_key   = x25519.X25519PublicKey.from_public_bytes(rcpt_pub_bytes)
            rcpt_safety    = generate_safety_number(rcpt_pub_bytes)

            st.markdown("<div class='step-label' style='margin-top:20px;'>02 // SAFETY VERIFICATION</div>", unsafe_allow_html=True)

            digits = rcpt_safety.split()
            cols   = st.columns(len(digits))
            for col, chunk in zip(cols, digits):
                col.markdown(
                    f"<div style='background:#121218;border:1px solid #22222E;border-radius:10px;"
                    f"padding:10px 0;text-align:center;font-family:\"JetBrains Mono\",monospace;"
                    f"font-size:16px;font-weight:700;color:#A855F7;'>{chunk}</div>",
                    unsafe_allow_html=True,
                )

            st.markdown(
                f"<p style='font-size:12px;color:#71717A;font-family:monospace;margin:12px 0 8px;text-align:center;'>"
                f"Verify with recipient out-of-band to prevent key swapping attacks."
                f"</p>",
                unsafe_allow_html=True,
            )

            verified = st.checkbox(
                "I verified this matches the recipient's safety number",
                key="safety_confirmed",
            )

            if verified:
                st.markdown("<div class='step-label' style='margin-top:20px;'>03 // COMPOSE PAYLOAD</div>", unsafe_allow_html=True)

                cover_file = st.file_uploader(
                    "Select cover asset (photo/wallpaper):",
                    type=["png", "jpg", "jpeg"],
                )
                secret_message = st.text_area(
                    "Secret payload:",
                    placeholder="Type confidential message here...",
                )

                if cover_file:
                    st.image(cover_file, caption="Cover asset preview", use_container_width=True)

                send_ready = cover_file and secret_message and secret_message.strip()

                if st.button(
                    "Hide Message & Transmit",
                    type="primary",
                    disabled=not send_ready,
                    use_container_width=True,
                ):
                    with st.spinner("Encrypting & hiding payload..."):
                        eph_priv      = x25519.X25519PrivateKey.generate()
                        eph_pub       = eph_priv.public_key()
                        eph_pub_bytes = eph_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

                        shared        = eph_priv.exchange(rcpt_pub_key)
                        aes_key       = derive_aes_key(shared)
                        enc_msg       = Fernet(aes_key).encrypt(secret_message.encode())
                        payload       = eph_pub_bytes + enc_msg

                        stego_buf     = robust_embed(Image.open(cover_file), payload, target)
                        requests.post(
                            f"{SERVER_URL}/deposit/{target}",
                            files={"file": ("payload.png", stego_buf, "image/png")},
                            timeout=10,
                        )

                    st.success("Payload successfully transmitted into blind token mailbox.")

        except Exception as e:
            st.error(f"Recipient routing error: {e}")

# ─────────────────────────────────────────────
# TAB: RECEIVE
# ─────────────────────────────────────────────
with tab_recv:
    if "inbox" not in st.session_state:
        st.session_state.inbox = []

    if st.button("Poll Mailbox", type="secondary", use_container_width=True):
        with st.spinner("Querying node & filtering network chaff..."):
            try:
                packages = requests.get(
                    f"{SERVER_URL}/poll/{tok}", timeout=10
                ).json().get("payloads", [])

                found = 0
                for hex_data in packages:
                    raw = bytes.fromhex(hex_data)
                    try:
                        extracted = robust_extract(raw, tok)
                        st.session_state.inbox.append({
                            "raw_img"  : raw,
                            "extracted": extracted,
                            "cleartext": None,
                            "destroyed": False,
                        })
                        found += 1
                    except ValueError:
                        pass

                if found == 0:
                    st.toast("Poll complete. Zero valid payloads (Chaff filtered).", icon="📭")
                else:
                    st.toast(f"Retrieved {found} new encrypted payload(s)!", icon="📩")

            except Exception as e:
                st.error(f"Network error: {e}")

    if st.session_state.inbox:
        st.markdown("<div style='margin-top:20px;'></div>", unsafe_allow_html=True)
        for i, item in enumerate(st.session_state.inbox):
            st.markdown(
                f"<div class='surface-card'>"
                f"<div class='step-label'>INCOMING PAYLOAD #{i+1}</div>",
                unsafe_allow_html=True,
            )
            st.image(item["raw_img"], use_container_width=True)

            if item["cleartext"] is None and not item["destroyed"]:
                if st.button("Decrypt & Reveal", key=f"dec_{i}", type="primary"):
                    try:
                        extracted     = item["extracted"]
                        eph_pub_bytes = extracted[:32]
                        enc_msg       = extracted[32:]
                        eph_pub       = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
                        shared        = priv.exchange(eph_pub)
                        aes_key       = derive_aes_key(shared)
                        cleartext     = Fernet(aes_key).decrypt(enc_msg).decode()
                        st.session_state.inbox[i]["cleartext"] = cleartext
                        st.rerun()
                    except Exception:
                        st.session_state.inbox[i]["destroyed"] = True
                        st.rerun()

            elif item["destroyed"]:
                st.markdown(
                    "<div style='background:rgba(239,68,68,0.1);border:1px solid #EF4444;border-radius:10px;padding:12px;"
                    "font-family:monospace;font-size:12px;color:#FCA5A5;margin-top:10px;'>"
                    "💥 Decryption Failed — Key Mismatch / Payload Destroyed."
                    "</div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"<div style='background:rgba(168,85,247,0.1);border:1px solid #A855F7;border-radius:10px;padding:14px;"
                    f"font-family:\"JetBrains Mono\",monospace;font-size:14px;color:#FFFFFF;margin-top:10px;'>"
                    f"<span style='color:#A855F7;font-weight:700;'>PLAINTEXT:</span><br><br>{item['cleartext']}"
                    f"</div>",
                    unsafe_allow_html=True,
                )

            st.markdown("</div>", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# TAB: IDENTITY
# ─────────────────────────────────────────────
with tab_id:
    col_qr, col_info = st.columns([1, 1.4])

    with col_qr:
        st.markdown("<div class='step-label'>QR DISCOVERY</div>", unsafe_allow_html=True)
        st.markdown(qr_for_token(tok, APP_URL), unsafe_allow_html=True)

    with col_info:
        st.markdown("<div class='step-label'>YOUR DELIVERY TOKEN</div>", unsafe_allow_html=True)
        st.code(tok, language=None)

        invite_link = f"{APP_URL}/?add={tok}"
        st.markdown("<div class='step-label' style='margin-top:10px;'>DEEP INVITE LINK</div>", unsafe_allow_html=True)
        st.code(invite_link, language=None)

    st.markdown("<div class='step-label' style='margin-top:20px;'>ACTIVE SAFETY NUMBER</div>", unsafe_allow_html=True)
    st.markdown(
        f"<div style='background:#121218;border:1px solid #22222E;border-radius:12px;padding:14px;text-align:center;"
        f"font-family:\"JetBrains Mono\",monospace;font-size:18px;font-weight:700;color:#A855F7;letter-spacing:2px;'>"
        f"{my_safety}"
        f"</div>",
        unsafe_allow_html=True,
    )