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
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# =====================================================================
# ⚙️  CONFIG
# =====================================================================
SERVER_URL   = "https://ghost-channel-tteh.onrender.com"
APP_URL      = "https://ghost-channel.streamlit.app"
DELIMITER    = b"##END_PAYLOAD##"
CONSTANT_DIM = (1200, 1200)
rs           = RSCodec(100)

st.set_page_config(page_title="Ghost Channel", page_icon="👻", layout="centered")

# =====================================================================
# 🔑  SESSION-ISOLATED IDENTITY & STATE
# =====================================================================
if "private_key" not in st.session_state or "token" not in st.session_state:
    priv_key  = x25519.X25519PrivateKey.generate()
    pub_key   = priv_key.public_key()
    pub_bytes = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    token     = secrets.token_hex(16)
    try:
        requests.post(f"{SERVER_URL}/register/{token}",
                      json={"public_key_hex": pub_bytes.hex()}, timeout=3)
    except Exception:
        pass
    st.session_state["private_key"] = priv_key
    st.session_state["pub_bytes"]   = pub_bytes
    st.session_state["token"]       = token

user_token    = st.session_state["token"]
user_priv_key = st.session_state["private_key"]
user_pub_bytes= st.session_state["pub_bytes"]

if "form_key" not in st.session_state:
    st.session_state["form_key"] = 0

# =====================================================================
# 🔐  CRYPTO
# =====================================================================
def derive_aes_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"steg-session-key")
    return base64.urlsafe_b64encode(hkdf.derive(shared_secret))

def generate_safety_number(public_key_bytes: bytes) -> str:
    key_hash = hashlib.sha256(public_key_bytes).hexdigest()
    numeric  = str(int(key_hash[:16], 16))[:20]
    return " ".join([numeric[i:i+5] for i in range(0, 20, 5)])

# =====================================================================
# 🎨  STEGANOGRAPHY
# =====================================================================
def _pixel_path(width, height, token):
    seed   = int(hashlib.sha256(token.encode()).hexdigest(), 16)
    rng    = random.Random(seed)
    pixels = [(x, y) for y in range(height) for x in range(width)]
    rng.shuffle(pixels)
    return pixels

def robust_embed(img_obj, payload, token):
    img    = img_obj.convert("RGB").resize(CONSTANT_DIM, Image.Resampling.LANCZOS)
    canvas = img.copy()
    blob   = rs.encode(payload) + DELIMITER
    bits   = "".join(format(b, "08b") for b in blob)
    total  = len(bits)
    path   = _pixel_path(*CONSTANT_DIM, token)
    idx    = 0
    for x, y in path:
        if idx >= total: break
        r, g, b = img.getpixel((x, y))
        if idx < total: r = (r & ~1) | int(bits[idx]); idx += 1
        if idx < total: g = (g & ~1) | int(bits[idx]); idx += 1
        if idx < total: b = (b & ~1) | int(bits[idx]); idx += 1
        canvas.putpixel((x, y), (r, g, b))
    buf = io.BytesIO()
    canvas.save(buf, format="PNG")
    buf.seek(0)
    return buf

def robust_extract(img_bytes, token):
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
                    protected      = bytes(raw[:-len(DELIMITER)])
                    repaired, _, _ = rs.decode(protected)
                    return bytes(repaired)
    raise ValueError("Chaff or corrupt image.")

# =====================================================================
# 📱  QR CODE  (pure Python)
# =====================================================================
def _qr_svg(data: str, px: int = 5) -> str:
    try:
        GF_EXP = [0]*512; GF_LOG = [0]*256; x = 1
        for i in range(255):
            GF_EXP[i] = x; GF_LOG[x] = i; x <<= 1
            if x & 0x100: x ^= 0x11D
        for i in range(255, 512): GF_EXP[i] = GF_EXP[i-255]

        def gf_mul(a, b):
            return 0 if (a==0 or b==0) else GF_EXP[GF_LOG[a]+GF_LOG[b]]
        def gf_poly_mul(p, q):
            r = [0]*(len(p)+len(q)-1)
            for i,a in enumerate(p):
                for j,b in enumerate(q): r[i+j] ^= gf_mul(a,b)
            return r
        def rs_poly(n):
            g = [1]
            for i in range(n): g = gf_poly_mul(g,[1,GF_EXP[i]])
            return g
        def rs_encode(data_bytes, n_ec):
            gen = rs_poly(n_ec); msg = list(data_bytes)+[0]*n_ec
            for i in range(len(data_bytes)):
                coef = msg[i]
                if coef:
                    for j in range(1,len(gen)): msg[i+j] ^= gf_mul(gen[j],coef)
            return msg[len(data_bytes):]

        data_enc = data.encode("utf-8"); n = len(data_enc)
        versions = [(1,17,7,21),(2,32,10,25),(3,53,15,29),(4,78,20,33)]
        ver,cap,n_ec,size = next((v,c,e,s) for v,c,e,s in versions if c>=n)

        bits = "0100"+format(n,"08b")+"".join(format(b,"08b") for b in data_enc)+"0000"
        while len(bits)%8: bits+="0"
        codewords=[int(bits[i:i+8],2) for i in range(0,len(bits),8)]
        pad=[0xEC,0x11]; pi=0
        while len(codewords)<cap: codewords.append(pad[pi%2]); pi+=1
        all_cw = codewords+rs_encode(codewords,n_ec)

        mat=[[None]*size for _ in range(size)]
        def add_finder(r,c):
            for dr in range(7):
                for dc in range(7):
                    mat[r+dr][c+dc] = 1 if (dr in(0,6) or dc in(0,6) or (2<=dr<=4 and 2<=dc<=4)) else 0
        add_finder(0,0); add_finder(0,size-7); add_finder(size-7,0)
        for i in range(8):
            for pos in [(7,i),(i,7),(7,size-1-i),(i,size-8),(size-8,i),(size-1-i,7)]:
                r2,c2=pos
                if 0<=r2<size and 0<=c2<size and mat[r2][c2] is None: mat[r2][c2]=0
        for i in range(8,size-8):
            if mat[6][i] is None: mat[6][i]=i%2==0
            if mat[i][6] is None: mat[i][6]=i%2==0
        mat[size-8][8]=1
        fmt=0b101010000010010; fmt_bits=[(fmt>>i)&1 for i in range(14,-1,-1)]
        fmt_pos=[(8,i) for i in range(6)]+[(8,7),(8,8),(7,8)]+[(i,8) for i in range(5,-1,-1)]
        for (r2,c2),b in zip(fmt_pos,fmt_bits[:9]):
            if mat[r2][c2] is None: mat[r2][c2]=b
        fmt_pos2=[(size-1-i,8) for i in range(7)]+[(8,size-8),(8,size-7)]
        for (r2,c2),b in zip(fmt_pos2,fmt_bits[7:]):
            if mat[r2][c2] is None: mat[r2][c2]=b
        bit_str="".join(format(c,"08b") for c in all_cw)
        bi,right,col=0,True,size-1
        while col>=0:
            if col==6: col-=1
            rows=range(size-1,-1,-1) if right else range(size)
            for row in rows:
                for dc2 in(0,1):
                    c2=col-dc2
                    if mat[row][c2] is None:
                        bit=int(bit_str[bi]) if bi<len(bit_str) else 0
                        mat[row][c2]=bit
                        if (row+c2)%2==0: mat[row][c2]^=1
                        bi+=1
            right=not right; col-=2
        for r2 in range(size):
            for c2 in range(size):
                if mat[r2][c2] is None: mat[r2][c2]=0

        margin=3; total_px=(size+2*margin)*px
        rects=[]
        for r2 in range(size):
            for c2 in range(size):
                if mat[r2][c2]:
                    rects.append(f'<rect x="{(c2+margin)*px}" y="{(r2+margin)*px}" width="{px}" height="{px}" fill="#A855F7" rx="1"/>')
        return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_px}" height="{total_px}" '
                f'style="background:#0E0E16;border:1px solid #2A1F3D;border-radius:16px;">'
                +"".join(rects)+'</svg>')
    except Exception:
        return f'<div style="background:#0E0E16;border:1px solid #2A1F3D;border-radius:16px;padding:20px;text-align:center;font-family:monospace;font-size:11px;color:#A855F7;">{data[:16]}...</div>'

def qr_for_token(token, app_url):
    invite = f"{app_url}/?add={token}"
    return _qr_svg(token if len(invite)>78 else invite)

# =====================================================================
# 🌐  INVITE LINK AUTO-FILL
# =====================================================================
params          = st.query_params
prefilled_token = params.get("add","")

# =====================================================================
# 🎨  GLOBAL STYLES
# =====================================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html {
  /* Enables smooth scrolling when the ghost is clicked */
  scroll-behavior: smooth !important;
}

html, body,
[data-testid="stAppViewContainer"],
[data-testid="stApp"] {
  background: #08080F !important;
  font-family: 'Inter', sans-serif !important;
  color: #E4E4E7 !important;
}

[data-testid="stHeader"]  { background: transparent !important; border: none !important; }
[data-testid="stSidebar"] { display: none !important; }
.block-container          { max-width: 680px !important; padding: 0 1.25rem 4rem !important; }

/* ── GHOST CLICK ANIMATION ── */
.ghost-link {
  transition: transform 0.2s ease, filter 0.2s ease;
  cursor: pointer;
}
.ghost-link:hover {
  transform: translateY(-2px) scale(1.02);
  filter: drop-shadow(0 4px 12px rgba(168,85,247,0.3));
}

/* ── PIXEL SPEECH BUBBLE (FLOATING LEFT OF GHOST) ── */
.pixel-bubble-left {
  position: absolute;
  right: calc(100% + 12px); 
  top: 50%;
  transform: translateY(-50%);
  white-space: nowrap;
  background: #F3E8FF;
  color: #1E1B4B;
  padding: 6px 12px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  font-weight: 800;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  box-shadow: 
    -2px 0 0 0 #1E1B4B,
    2px 0 0 0 #1E1B4B,
    0 -2px 0 0 #1E1B4B,
    0 2px 0 0 #1E1B4B;
  z-index: 10;
}
.pixel-bubble-left::before {
  content: '';
  position: absolute;
  top: 50%;
  right: -6px; 
  transform: translateY(-50%);
  width: 4px;
  height: 4px;
  background: #F3E8FF;
  box-shadow: 
    2px 0 0 0 #1E1B4B,
    0 -2px 0 0 #1E1B4B,
    0 2px 0 0 #1E1B4B;
  z-index: 2;
}
.pixel-bubble-left::after {
  content: '';
  position: absolute;
  top: 50%;
  right: -2px; 
  transform: translateY(-50%);
  width: 2px;
  height: 4px;
  background: #F3E8FF;
  z-index: 3;
}

/* ── TABS ── */
.stTabs [data-baseweb="tab-list"] {
  background: #0E0E16 !important;
  border: 1px solid #1C1C2A !important;
  border-radius: 14px !important;
  padding: 5px !important;
  gap: 4px !important;
}
.stTabs [data-baseweb="tab"] {
  border-radius: 10px !important;
  background: transparent !important;
  color: #52525B !important;
  font-family: 'Inter', sans-serif !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  height: 38px !important;
  padding: 0 16px !important;
  border: none !important;
  transition: all .18s ease !important;
}
.stTabs [aria-selected="true"] {
  background: #1A1A2E !important;
  color: #C084FC !important;
  font-weight: 600 !important;
}
.stTabs [data-baseweb="tab-highlight"] { display: none !important; }
[data-testid="stTabPanel"]             { background: transparent !important; padding-top: 1.6rem !important; }

/* ── INPUTS ── */
.stTextInput > div > div,
.stTextArea  > div > div {
  background: #0E0E16 !important;
  border: 1px solid #1C1C2A !important;
  border-radius: 12px !important;
  color: #E4E4E7 !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 13px !important;
  transition: border-color .15s !important;
}
.stTextInput > div > div:focus-within,
.stTextArea  > div > div:focus-within {
  border-color: #A855F7 !important;
  box-shadow: 0 0 0 3px rgba(168,85,247,.15) !important;
}
.stTextInput label, .stTextArea label {
  color: #52525B !important;
  font-size: 11px !important;
  font-family: 'JetBrains Mono', monospace !important;
  letter-spacing: .08em !important;
  text-transform: uppercase !important;
}

/* ── BUTTONS ── */
.stButton > button {
  font-family: 'Inter', sans-serif !important;
  font-size: 13px !important;
  font-weight: 600 !important;
  border-radius: 10px !important;
  padding: 10px 20px !important;
  transition: all .18s ease !important;
  letter-spacing: .01em !important;
}
.stButton > button[kind="primary"] {
  background: linear-gradient(135deg, #A855F7 0%, #7C3AED 100%) !important;
  border: none !important;
  color: #fff !important;
}
.stButton > button[kind="primary"]:hover {
  background: linear-gradient(135deg, #C084FC 0%, #A855F7 100%) !important;
  box-shadow: 0 4px 24px rgba(168,85,247,.35) !important;
  transform: translateY(-1px) !important;
}
.stButton > button[kind="secondary"] {
  background: #0E0E16 !important;
  border: 1px solid #1C1C2A !important;
  color: #A1A1AA !important;
}
.stButton > button[kind="secondary"]:hover {
  border-color: #A855F7 !important;
  color: #C084FC !important;
}
.stButton > button:disabled {
  opacity: .35 !important;
  cursor: not-allowed !important;
}

/* ── FILE UPLOADER ── */
[data-testid="stFileUploader"] > div {
  background: #0E0E16 !important;
  border: 1px dashed #2A1F3D !important;
  border-radius: 12px !important;
}
[data-testid="stFileUploader"] label {
  color: #52525B !important;
  font-size: 11px !important;
  text-transform: uppercase !important;
  letter-spacing: .08em !important;
}
[data-testid="stFileUploader"] button {
  border-radius: 8px !important;
  font-size: 12px !important;
}

/* ── CHECKBOX ── */
[data-testid="stCheckbox"] label {
  color: #A1A1AA !important;
  font-size: 13px !important;
  font-family: 'Inter', sans-serif !important;
}
[data-testid="stCheckbox"] svg { color: #A855F7 !important; }

/* ── ALERTS / CARDS / COMPONENTS ── */
.gc-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 10px;
  font-weight: 600;
  color: #A855F7;
  letter-spacing: .12em;
  text-transform: uppercase;
  margin-bottom: 8px;
}
.gc-card {
  background: #0E0E16;
  border: 1px solid #1C1C2A;
  border-radius: 16px;
  padding: 20px;
  margin-bottom: 16px;
}
hr { border-color: #1C1C2A !important; margin: 1.6rem 0 !important; }

/* ── ANIMATIONS ── */
@keyframes flyAway {
  0%   { transform: translate(0,0)       scale(1);   opacity: 1; }
  20%  { transform: translate(-8px,8px)  scale(1);   opacity: 1; }
  100% { transform: translate(260px,-180px) scale(.4); opacity: 0; }
}
@keyframes fadeSlideIn {
  from { opacity: 0; transform: translateY(8px); }
  to   { opacity: 1; transform: translateY(0);   }
}
.plane-anim {
  animation: flyAway 1.4s cubic-bezier(.4,0,.2,1) forwards;
  display: flex; justify-content: center; padding: 16px 0;
}
.success-anim {
  animation: fadeSlideIn .4s ease forwards;
  background: rgba(168,85,247,.08);
  border: 1px solid #2A1F3D;
  border-radius: 14px;
  padding: 20px;
  display: flex; flex-direction: column; align-items: center; gap: 10px;
  text-align: center;
}
</style>
""", unsafe_allow_html=True)


# =====================================================================
# 👻  DYNAMIC PIXEL ART ASSETS
# =====================================================================

def get_ghost_header_assets(state="normal"):
    """
    Generates dynamic SVG face features and header text based on user state.
    """
    base_body = """<svg xmlns="http://www.w3.org/2000/svg" width="54" height="54" viewBox="0 0 20 20" shape-rendering="crispEdges">
  <rect x="6" y="2"  width="8"  height="1" fill="#F3E8FF"/>
  <rect x="4" y="3"  width="12" height="1" fill="#F3E8FF"/>
  <rect x="3" y="4"  width="14" height="2" fill="#F3E8FF"/>
  <rect x="2" y="6"  width="16" height="8" fill="#F3E8FF"/>
  <rect x="2" y="14" width="3"  height="2" fill="#F3E8FF"/>
  <rect x="6" y="14" width="3"  height="2" fill="#F3E8FF"/>
  <rect x="11" y="14" width="3" height="2" fill="#F3E8FF"/>
  <rect x="15" y="14" width="3" height="2" fill="#F3E8FF"/>
{face_elements}
</svg>"""

    if state == "imageLoaded":
        face_elements = (
            '<rect x="4" y="7" width="1" height="1" fill="#1E1B4B"/>\n'
            '<rect x="5" y="8" width="2" height="1" fill="#1E1B4B"/>\n'
            '<rect x="4" y="9" width="1" height="1" fill="#1E1B4B"/>\n'
            '<rect x="15" y="7" width="1" height="1" fill="#1E1B4B"/>\n'
            '<rect x="13" y="8" width="2" height="1" fill="#1E1B4B"/>\n'
            '<rect x="15" y="9" width="1" height="1" fill="#1E1B4B"/>\n'
            '<rect x="4" y="10" width="2" height="1" fill="#F472B6"/>\n'
            '<rect x="14" y="10" width="2" height="1" fill="#F472B6"/>'
        )
        subtext = "Image is ready for secret Text embedding"

    elif state == "typing":
        face_elements = (
            '<rect x="4" y="7" width="3" height="1" fill="#1E1B4B"/>\n'
            '<rect x="6" y="8" width="1" height="2" fill="#1E1B4B"/>\n'
            '<rect x="12" y="7" width="3" height="1" fill="#1E1B4B"/>\n'
            '<rect x="14" y="8" width="1" height="2" fill="#1E1B4B"/>\n'
            '<rect x="4" y="10" width="2" height="1" fill="#F472B6"/>\n'
            '<rect x="14" y="10" width="2" height="1" fill="#F472B6"/>'
        )
        subtext = "Im not looking at all !!"

    elif state == "decrypted":
        face_elements = (
            '<rect x="4" y="7" width="1" height="1" fill="#1E1B4B"/>\n'
            '<rect x="5" y="6" width="1" height="1" fill="#1E1B4B"/>\n'
            '<rect x="6" y="7" width="1" height="1" fill="#1E1B4B"/>\n'
            '<rect x="12" y="7" width="1" height="1" fill="#1E1B4B"/>\n'
            '<rect x="13" y="6" width="1" height="1" fill="#1E1B4B"/>\n'
            '<rect x="14" y="7" width="1" height="1" fill="#1E1B4B"/>\n'
            '<rect x="4" y="9" width="2" height="1" fill="#F472B6"/>\n'
            '<rect x="14" y="9" width="2" height="1" fill="#F472B6"/>'
        )
        subtext = "Secret message revealed!"
        
    elif state == "error":
        # New angry token error face
        face_elements = (
            '<rect x="4" y="7" width="1" height="1" fill="#4C1D95"/>\n'
            '<rect x="5" y="8" width="2" height="1" fill="#4C1D95"/>\n'
            '<rect x="4" y="9" width="1" height="1" fill="#4C1D95"/>\n'
            '<rect x="15" y="7" width="1" height="1" fill="#4C1D95"/>\n'
            '<rect x="13" y="8" width="2" height="1" fill="#4C1D95"/>\n'
            '<rect x="15" y="9" width="1" height="1" fill="#4C1D95"/>\n'
            '<rect x="4" y="10" width="2" height="1" fill="#F472B6"/>\n'
            '<rect x="14" y="10" width="2" height="1" fill="#F472B6"/>'
        )
        subtext = "Token Error!"

    else:
        # Default/Normal state 
        face_elements = (
            '<rect x="5" y="7" width="2" height="3" fill="#1E1B4B"/>\n'
            '<rect x="13" y="7" width="2" height="3" fill="#1E1B4B"/>\n'
            '<rect x="4" y="10" width="2" height="1" fill="#F472B6"/>\n'
            '<rect x="14" y="10" width="2" height="1" fill="#F472B6"/>'
        )
        subtext = "Need help ? click me!"

    svg_code = base_body.format(face_elements=face_elements)
    return svg_code, subtext

GHOST_ANGRY_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="60" height="60" viewBox="0 0 20 20" shape-rendering="crispEdges">
  <rect x="6" y="2"  width="8"  height="1" fill="#EDE9FE"/>
  <rect x="4" y="3"  width="12" height="1" fill="#EDE9FE"/>
  <rect x="3" y="4"  width="14" height="2" fill="#EDE9FE"/>
  <rect x="2" y="6"  width="16" height="8" fill="#EDE9FE"/>
  <rect x="2"  y="14" width="3"  height="2" fill="#EDE9FE"/>
  <rect x="7"  y="14" width="3"  height="2" fill="#EDE9FE"/>
  <rect x="12" y="14" width="3"  height="2" fill="#EDE9FE"/>
  <rect x="17" y="14" width="1"  height="2" fill="#EDE9FE"/>
  <rect x="4"  y="7"  width="1"  height="1" fill="#4C1D95"/>
  <rect x="5"  y="8"  width="2"  height="1" fill="#4C1D95"/>
  <rect x="4"  y="9"  width="1"  height="1" fill="#4C1D95"/>
  <rect x="13" y="7"  width="1"  height="1" fill="#4C1D95"/>
  <rect x="11" y="8"  width="2"  height="1" fill="#4C1D95"/>
  <rect x="13" y="9"  width="1"  height="1" fill="#4C1D95"/>
  <rect x="3"  y="11" width="3"  height="1" fill="#F9A8D4"/>
  <rect x="14" y="11" width="3"  height="1" fill="#F9A8D4"/>
</svg>"""

GHOST_THUMBS_UP_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 24 20" shape-rendering="crispEdges">
  <rect x="6" y="2" width="8" height="1" fill="#A855F7"/>
  <rect x="4" y="3" width="12" height="1" fill="#A855F7"/>
  <rect x="3" y="4" width="14" height="2" fill="#A855F7"/>
  <rect x="2" y="6" width="16" height="8" fill="#A855F7"/>
  <rect x="2" y="14" width="3" height="2" fill="#A855F7"/>
  <rect x="6" y="14" width="3" height="2" fill="#A855F7"/>
  <rect x="11" y="14" width="3" height="2" fill="#A855F7"/>
  <rect x="15" y="14" width="3" height="2" fill="#A855F7"/>
  <rect x="5" y="7" width="2" height="3" fill="#1E1B4B"/>
  <rect x="13" y="7" width="2" height="3" fill="#1E1B4B"/>
  <rect x="18" y="9" width="3" height="2" fill="#A855F7"/>
  <rect x="20" y="7" width="2" height="2" fill="#A855F7"/>
</svg>"""

PLANE_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="56" height="56" viewBox="0 0 20 20" shape-rendering="crispEdges">
  <rect x="2"  y="10" width="16" height="2" fill="#A855F7"/>
  <rect x="6"  y="8"  width="12" height="2" fill="#A855F7"/>
  <rect x="10" y="6"  width="8"  height="2" fill="#A855F7"/>
  <rect x="14" y="4"  width="4"  height="2" fill="#A855F7"/>
  <rect x="6"  y="12" width="6"  height="2" fill="#7C3AED"/>
  <rect x="6"  y="14" width="2"  height="2" fill="#7C3AED"/>
</svg>"""

# =====================================================================
# 🏠  HEADER PLACEHOLDER (Drawn dynamically at the bottom)
# =====================================================================
header_placeholder = st.empty()

form_key = st.session_state["form_key"]
has_cover_image = bool(st.session_state.get(f"cover_file_{form_key}"))
has_secret_text = bool(st.session_state.get(f"secret_msg_{form_key}", "").strip())

# Determine initial base state before checking for errors below
if st.session_state.get("just_decrypted"):
    ghost_state = "decrypted"
    st.session_state["just_decrypted"] = False  
elif has_secret_text:
    ghost_state = "typing"
elif has_cover_image:
    ghost_state = "imageLoaded"
else:
    ghost_state = "normal"

# =====================================================================
# 🗂️  MAIN TABS
# =====================================================================
tab_send, tab_recv, tab_id = st.tabs(["↑  SEND", "↓  RECEIVE", "◎  IDENTITY"])

# =====================================================================
# TAB — SEND
# =====================================================================
with tab_send:

    def label(text, mt="1.4rem"):
        st.markdown(
            f"<div class='gc-label' style='margin-top:{mt};'>{text}</div>",
            unsafe_allow_html=True,
        )

    if prefilled_token:
        st.markdown(
            "<div style='background:rgba(168,85,247,.08);border:1px solid #2A1F3D;"
            "border-radius:10px;padding:10px 14px;font-size:12px;color:#C084FC;"
            "font-family:\"JetBrains Mono\",monospace;margin-bottom:16px;'>"
            "🔗 invite token detected and pre-filled</div>",
            unsafe_allow_html=True,
        )

    label("01 // recipient token", mt="0")
    target = st.text_input(
        "token", value=prefilled_token,
        placeholder="paste 32-character delivery token…",
        max_chars=32, label_visibility="collapsed",
    )

    if target and len(target) != 32:
        ghost_state = "error" # Override header state
        st.markdown(
            "<div style='font-size:12px;color:#EF4444;font-family:\"JetBrains Mono\",monospace;"
            "margin-top:4px;'>⚠ token must be exactly 32 characters</div>",
            unsafe_allow_html=True,
        )

    if target and len(target) == 32:
        try:
            res            = requests.get(f"{SERVER_URL}/public_key/{target}", timeout=3).json()
            rcpt_pub_bytes = bytes.fromhex(res["public_key"])
            rcpt_pub_key   = x25519.X25519PublicKey.from_public_bytes(rcpt_pub_bytes)
            rcpt_safety    = generate_safety_number(rcpt_pub_bytes)
            digits         = rcpt_safety.split()

            label("02 // verify safety number")

            cols = st.columns(4)
            for col, chunk in zip(cols, digits):
                col.markdown(
                    f"<div style='background:#0E0E16;border:1px solid #2A1F3D;"
                    f"border-radius:12px;padding:14px 6px;text-align:center;"
                    f"font-family:\"JetBrains Mono\",monospace;font-size:20px;"
                    f"font-weight:700;color:#A855F7;letter-spacing:3px;'>{chunk}</div>",
                    unsafe_allow_html=True,
                )

            st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

            verified = st.checkbox(
                "confirmed — safety number matches (verified out-of-band)",
                key="safety_confirmed",
            )

            if not verified:
                st.markdown(
                    "<div style='background:rgba(120,53,15,.3);border:1px solid #78350F;"
                    "border-radius:10px;padding:10px 14px;font-size:12px;color:#92400E;"
                    "font-family:\"JetBrains Mono\",monospace;margin-top:8px;'>"
                    "⚠ verify the number before sending — a mismatch means the server key was tampered with"
                    "</div>",
                    unsafe_allow_html=True,
                )

            if verified:
                label("03 // compose payload")

                cover_file = st.file_uploader(
                    "cover image",
                    type=["png","jpg","jpeg"],
                    label_visibility="collapsed",
                    key=f"cover_file_{form_key}"
                )
                st.markdown(
                    "<div style='font-size:10px;color:#52525B;font-family:\"JetBrains Mono\",monospace;"
                    "letter-spacing:.1em;text-transform:uppercase;margin:.8rem 0 .35rem;'>secret message</div>",
                    unsafe_allow_html=True,
                )
                secret_message = st.text_area(
                    "msg", placeholder="only the recipient will ever read this…",
                    height=100, label_visibility="collapsed",
                    key=f"secret_msg_{form_key}"
                )

                if cover_file:
                    st.markdown("<div style='height:6px;'></div>", unsafe_allow_html=True)
                    st.image(cover_file, caption="cover image preview", use_container_width=True)

                st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

                send_ok = bool(cover_file and secret_message and secret_message.strip())
                anim_slot = st.empty()

                if st.session_state.get("payload_sent"):
                    anim_slot.markdown(
                        f"<div class='success-anim'>{GHOST_THUMBS_UP_SVG}"
                        f"<span style='font-family:\"JetBrains Mono\",monospace;"
                        f"font-size:13px;font-weight:700;color:#C084FC;'>"
                        f"PAYLOAD TRANSMITTED</span>"
                        f"<span style='font-size:12px;color:#52525B;font-family:\"Inter\",sans-serif;'>"
                        f"recipient sees only a photo — until they decrypt</span></div>",
                        unsafe_allow_html=True,
                    )
                    st.session_state["payload_sent"] = False  

                if st.button("↑ hide & transmit", type="primary",
                             use_container_width=True, disabled=not send_ok):
                    
                    anim_slot.markdown(
                        f"<div class='plane-anim'>{PLANE_SVG}</div>",
                        unsafe_allow_html=True,
                    )
                    with st.spinner("encrypting & embedding payload…"):
                        eph_priv      = x25519.X25519PrivateKey.generate()
                        eph_pub_bytes = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
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
                    
                    st.session_state["payload_sent"] = True
                    st.session_state["form_key"] += 1
                    st.rerun()

        except Exception:
            ghost_state = "error" # Override header state
            st.markdown(
                f"<div style='background:rgba(239,68,68,.06);border:1px solid #7F1D1D;"
                f"border-radius:12px;padding:16px;display:flex;align-items:center;gap:14px;'>"
                f"{GHOST_ANGRY_SVG}"
                f"<div><div style='font-size:13px;color:#EF4444;font-weight:700;"
                f"font-family:\"JetBrains Mono\",monospace;margin-bottom:4px;'>Token Expired</div>"
                f"<div style='font-size:12px;color:#7F1D1D;font-family:\"JetBrains Mono\",monospace;'>"
                f"This token is no longer valid.<br>Ask the recipient for a fresh one.</div></div>"
                f"</div>",
                unsafe_allow_html=True,
            )

# =====================================================================
# TAB — RECEIVE
# =====================================================================
with tab_recv:

    if "inbox" not in st.session_state:
        st.session_state.inbox = []

    if st.button("↓ check mailbox", type="secondary", use_container_width=True):
        with st.spinner("querying node & filtering chaff…"):
            try:
                packages = requests.get(
                    f"{SERVER_URL}/poll/{user_token}", timeout=10
                ).json().get("payloads", [])
                found = 0
                for hex_data in packages:
                    raw = bytes.fromhex(hex_data)
                    try:
                        extracted = robust_extract(raw, user_token)
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
                    st.toast("mailbox empty — chaff filtered", icon="📭")
                else:
                    st.toast(f"{found} new payload(s) arrived", icon="📩")

            except Exception as e:
                ghost_state = "error" # Override header state
                st.markdown(
                    f"<div style='background:rgba(239,68,68,.06);border:1px solid #7F1D1D;"
                    f"border-radius:12px;padding:16px;display:flex;align-items:center;gap:14px;'>"
                    f"{GHOST_ANGRY_SVG}"
                    f"<div><div style='font-size:13px;color:#EF4444;font-weight:700;"
                    f"font-family:\"JetBrains Mono\",monospace;margin-bottom:4px;'>Server Offline</div>"
                    f"<div style='font-size:12px;color:#7F1D1D;font-family:\"JetBrains Mono\",monospace;'>"
                    f"Could not reach the relay node.<br>Check your connection and try again.</div></div>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

    if st.session_state.inbox:
        st.markdown(
            f"<div class='gc-label' style='margin:1.4rem 0 1rem;'>"
            f"inbox &nbsp;·&nbsp; {len(st.session_state.inbox)} message(s)</div>",
            unsafe_allow_html=True,
        )

        for i, item in enumerate(st.session_state.inbox):

            st.markdown(
                f"<div class='gc-card'>"
                f"<div style='margin-bottom:14px;'>"
                f"<span style='font-family:\"JetBrains Mono\",monospace;font-size:10px;"
                f"color:#3F3F46;letter-spacing:.1em;text-transform:uppercase;'>"
                f"message #{i+1}</span></div>",
                unsafe_allow_html=True,
            )

            st.image(item["raw_img"], use_container_width=True)

            st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)

            if item["cleartext"] is None and not item["destroyed"]:
                col_btn, col_hint = st.columns([1, 2])
                with col_btn:
                    if st.button("🔑 decrypt", key=f"dec_{i}", type="primary"):
                        try:
                            ext       = item["extracted"]
                            eph_pub   = x25519.X25519PublicKey.from_public_bytes(ext[:32])
                            shared    = user_priv_key.exchange(eph_pub)
                            aes_key   = derive_aes_key(shared)
                            cleartext = Fernet(aes_key).decrypt(ext[32:]).decode()
                            st.session_state.inbox[i]["cleartext"] = cleartext
                            st.session_state["just_decrypted"] = True  
                            st.toast("message decrypted!", icon="🔓")
                            st.rerun()
                        except Exception:
                            st.session_state.inbox[i]["destroyed"] = True
                            st.rerun()
                with col_hint:
                    st.markdown(
                        "<div style='font-size:12px;color:#3F3F46;"
                        "font-family:\"JetBrains Mono\",monospace;"
                        "line-height:1.7;padding-top:8px;'>"
                        "a hidden message is inside<br>use your private key to reveal it</div>",
                        unsafe_allow_html=True,
                    )

            elif item["destroyed"]:
                st.markdown(
                    "<div style='background:rgba(239,68,68,.06);border:1px solid #7F1D1D;"
                    "border-radius:10px;padding:14px;"
                    "font-family:\"JetBrains Mono\",monospace;'>"
                    "<div style='font-size:13px;color:#EF4444;font-weight:700;margin-bottom:4px;'>"
                    "✗ decryption failed</div>"
                    "<div style='font-size:11px;color:#7F1D1D;'>"
                    "authentication tag mismatch — message destroyed</div></div>",
                    unsafe_allow_html=True,
                )

            else:
                st.markdown(
                    f"<div style='background:rgba(168,85,247,.06);border:1px solid #2A1F3D;"
                    f"border-radius:10px;padding:16px;"
                    f"font-family:\"JetBrains Mono\",monospace;animation:fadeSlideIn .4s ease;'>"
                    f"<div style='font-size:10px;color:#7C3AED;letter-spacing:.1em;"
                    f"text-transform:uppercase;margin-bottom:10px;'>🔓 decrypted message</div>"
                    f"<div style='font-size:14px;color:#E4E4E7;line-height:1.75;'>{item['cleartext']}</div>"
                    f"</div>",
                    unsafe_allow_html=True,
                )

            st.markdown("</div>", unsafe_allow_html=True) 

# =====================================================================
# TAB — IDENTITY
# =====================================================================
with tab_id:
    my_safety = generate_safety_number(user_pub_bytes)

    col_qr, col_info = st.columns([1, 1.5], gap="large")

    with col_qr:
        st.markdown("<div class='gc-label'>QR code</div>", unsafe_allow_html=True)
        st.markdown(qr_for_token(user_token, APP_URL), unsafe_allow_html=True)
        st.markdown(
            "<div style='font-size:10px;color:#3F3F46;font-family:\"JetBrains Mono\",monospace;"
            "margin-top:8px;text-align:center;'>let sender scan this</div>",
            unsafe_allow_html=True,
        )

    with col_info:
        st.markdown("<div class='gc-label'>delivery token</div>", unsafe_allow_html=True)
        st.code(user_token, language=None)

        invite = f"{APP_URL}/?add={user_token}"
        st.markdown(
            "<div class='gc-label' style='margin-top:14px;'>invite link</div>",
            unsafe_allow_html=True,
        )
        st.code(invite, language=None)

    st.markdown(
        "<div class='gc-label' style='margin-top:20px;'>safety number</div>",
        unsafe_allow_html=True,
    )
    sn_cols = st.columns(4)
    for col, chunk in zip(sn_cols, my_safety.split()):
        col.markdown(
            f"<div style='background:#0E0E16;border:1px solid #2A1F3D;"
            f"border-radius:12px;padding:14px 6px;text-align:center;"
            f"font-family:\"JetBrains Mono\",monospace;font-size:18px;"
            f"font-weight:700;color:#A855F7;letter-spacing:3px;'>{chunk}</div>",
            unsafe_allow_html=True,
        )
    st.markdown(
        "<div style='font-size:11px;color:#3F3F46;font-family:\"JetBrains Mono\",monospace;"
        "margin-top:10px;text-align:center;'>read this to your contact out-of-band "
        "to confirm no one swapped your keys</div>",
        unsafe_allow_html=True,
    )

    st.markdown("<hr>", unsafe_allow_html=True)

    st.markdown("<div class='gc-label'>how to share</div>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    for col, icon, title, desc in [
        (c1, "◈", "in person",    "show QR code\nsender scans it\nno typing needed"),
        (c2, "◉", "online",       "send invite link\ntoken auto-fills\nworks anywhere"),
        (c3, "↻", "rotate",       "refresh the page\nto generate a\nfresh identity"),
    ]:
        col.markdown(
            f"<div style='background:#0E0E16;border:1px solid #1C1C2A;border-radius:12px;"
            f"padding:16px 12px;text-align:center;height:100%;'>"
            f"<div style='font-size:20px;color:#7C3AED;margin-bottom:8px;'>{icon}</div>"
            f"<div style='font-size:12px;font-weight:600;color:#E4E4E7;"
            f"font-family:\"Inter\",sans-serif;margin-bottom:6px;'>{title}</div>"
            f"<div style='font-size:11px;color:#52525B;font-family:\"JetBrains Mono\",monospace;"
            f"line-height:1.8;white-space:pre-line;'>{desc}</div></div>",
            unsafe_allow_html=True,
        )

    st.markdown(
        "<div style='background:#0E0E16;border:1px solid #1C1C2A;border-radius:10px;"
        "padding:12px 16px;font-size:12px;color:#3F3F46;"
        "font-family:\"JetBrains Mono\",monospace;margin-top:14px;line-height:1.7;'>"
        "your token is a mailbox address, not your identity — "
        "anyone with it can send you messages but cannot read them "
        "or find out who you are.</div>",
        unsafe_allow_html=True,
    )


# =====================================================================
# 🏠  RENDER HEADER (Evaluated after all logic to ensure correct state)
# =====================================================================
with header_placeholder.container():
    header_ghost, header_sub = get_ghost_header_assets(ghost_state)
    st.markdown(f"""
<div style="display:flex;align-items:center;padding:2rem 0 1.6rem;">
<div style="display:flex;align-items:center;gap:14px;">
<a href="#help-section" class="ghost-link" style="position:relative;display:inline-flex;align-items:center;text-decoration:none;color:inherit;">
<div class="pixel-bubble-left">
{header_sub}
</div>
{header_ghost}
</a>
<div>
<div style="font-family:'Inter',sans-serif;font-size:20px;font-weight:900;color:#fff;letter-spacing:-.02em;">GHOST CHANNEL</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#52525B;letter-spacing:.1em;margin-top:3px;">STEGANOGRAPHIC · E2E ENCRYPTED · ZERO IDENTITY</div>
</div>
</div>
</div>
<div style="height:1px;background:linear-gradient(90deg,#2A1F3D,transparent);margin-bottom:1.6rem;"></div>
""", unsafe_allow_html=True)


# =====================================================================
# HELP & ABOUT SECTION (ANCHORED AT BOTTOM)
# =====================================================================
st.markdown("""
<div id="help-section" style="margin-top:6rem; padding-top:4rem; border-top:1px solid #1C1C2A; font-family:'Inter', sans-serif; display:flex; gap:60px; flex-wrap:wrap; padding-bottom:4rem;">
<div style="flex:1; min-width:280px;">
<div style="font-family:'JetBrains Mono', monospace; font-size:10px; font-weight:600; color:#52525B; letter-spacing:.12em; text-transform:uppercase; margin-bottom:16px;">INSTRUCTIONS & WARNINGS</div>
<div style="font-size:12px; color:#A1A1AA; line-height:1.8;">
<span style="color:#EF4444; font-weight:600;">CRITICAL: DO NOT REFRESH</span><br>
Refreshing your browser generates a brand new cryptographic identity. You will permanently lose your current delivery token, private key, and any unread messages.<br><br>
<span style="color:#E4E4E7; font-weight:600;">1. The Cover Image</span><br>
The app mathematically alters the invisible color pixels of an uploaded image to embed your secret text inside it.<br><br>
<span style="color:#E4E4E7; font-weight:600;">2. Sending</span><br>
Get the recipient's 32-character token. Paste the token, upload a photo, type your message, and transmit.<br><br>
<span style="color:#E4E4E7; font-weight:600;">3. Receiving</span><br>
Click check mailbox. If a disguised image appears, click decrypt to extract the hidden text using your private key.
</div>
</div>
<div style="flex:1; min-width:280px;">
<div style="font-family:'JetBrains Mono', monospace; font-size:10px; font-weight:600; color:#52525B; letter-spacing:.12em; text-transform:uppercase; margin-bottom:16px;">ABOUT GHOST CHANNEL</div>
<div style="font-size:12px; color:#A1A1AA; line-height:1.8;">
<span style="color:#E4E4E7; font-weight:600;">Zero Identity. Total Plausible Deniability.</span><br>
An ultra-private, E2E encrypted message drop designed for environments where even the metadata of messaging is dangerous.<br><br>
<span style="color:#E4E4E7; font-weight:600;">No Accounts</span><br>
No emails, usernames, or phone numbers. Every session uses a disposable cryptographic identity.<br><br>
<span style="color:#E4E4E7; font-weight:600;">Steganography & Chaffing</span><br>
Ciphertexts are camouflaged in image pixels. The server cannot distinguish payloads from noise.
</div>
</div>
</div>
""", unsafe_allow_html=True)