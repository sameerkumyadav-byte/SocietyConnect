"""
╔══════════════════════════════════════════════════════════╗
║       SocietyConnect — Python Flask Backend v2           ║
║  Run: pip install -r requirements.txt && python server.py║
╚══════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3
import jwt
import datetime
import hashlib
import os
import re
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps

# ─────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────
SECRET_KEY = os.environ.get("SECRET_KEY", "societyconnect_secret_key_2024")
DB_PATH    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "societyconnect.db")
PORT       = int(os.environ.get("PORT", 5000))

# ── EMAIL CONFIG (set these as Environment Variables on Render) ──
# EMAIL_USER = your Gmail address e.g. yourname@gmail.com
# EMAIL_PASS = your Gmail App Password (NOT your normal password)
#   Steps to get App Password:
#   1. Go to myaccount.google.com → Security → 2-Step Verification (enable it)
#   2. Then go to myaccount.google.com/apppasswords
#   3. Select app: Mail, device: Other → name it "SocietyConnect"
#   4. Copy the 16-char password → paste as EMAIL_PASS on Render
EMAIL_USER = os.environ.get("EMAIL_USER", "")
EMAIL_PASS = os.environ.get("EMAIL_PASS", "")

# In-memory OTP store { key: {"otp":"123456","expires":datetime} }
# Falls back to SQLite for persistence across Render restarts
otp_store = {}

def otp_set(key, otp, minutes=10):
    """Store OTP both in memory and SQLite for persistence."""
    expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=minutes)
    otp_store[key] = {"otp": otp, "expires": expires}
    try:
        db = get_db()
        db.execute("DELETE FROM otp_tokens WHERE key=?", (key,))
        db.execute("INSERT INTO otp_tokens (key, otp, expires_at) VALUES (?,?,?)",
                   (key, otp, expires.isoformat()))
        db.commit()
        db.close()
    except Exception:
        pass  # table may not exist yet on first run

def otp_get(key):
    """Get OTP from memory first, fall back to SQLite."""
    stored = otp_store.get(key)
    if stored:
        return stored
    # Try SQLite (server may have restarted)
    try:
        db = get_db()
        row = db.execute("SELECT otp, expires_at FROM otp_tokens WHERE key=?", (key,)).fetchone()
        db.close()
        if row:
            expires = datetime.datetime.fromisoformat(row["expires_at"])
            stored = {"otp": row["otp"], "expires": expires}
            otp_store[key] = stored  # cache back in memory
            return stored
    except Exception:
        pass
    return None

def otp_delete(key):
    """Remove OTP from both memory and SQLite."""
    otp_store.pop(key, None)
    try:
        db = get_db()
        db.execute("DELETE FROM otp_tokens WHERE key=?", (key,))
        db.commit()
        db.close()
    except Exception:
        pass

def send_email_otp(to_email, otp, purpose="verification"):
    """Send OTP via Gmail SMTP. Returns True on success."""
    if not EMAIL_USER or not EMAIL_PASS:
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["From"]    = EMAIL_USER
        msg["To"]      = to_email
        msg["Subject"] = f"SocietyConnect OTP: {otp}"
        html = f"""<div style="font-family:sans-serif;max-width:420px;margin:auto;padding:32px;background:#0d1117;color:#e6edf3;border-radius:16px">
          <div style="text-align:center;margin-bottom:20px"><div style="font-size:40px">&#127961;</div>
          <h2 style="color:#f59e0b;margin:8px 0 4px">SocietyConnect</h2></div>
          <p style="font-size:15px">Your OTP for <b>{purpose}</b>:</p>
          <div style="background:#161b22;border:2px solid #f59e0b;border-radius:12px;padding:20px;text-align:center;margin:20px 0">
            <span style="font-size:42px;font-weight:900;letter-spacing:14px;color:#f59e0b">{otp}</span>
          </div>
          <p style="color:#7d8590;font-size:12px;text-align:center">Expires in 10 minutes. Do not share.</p></div>"""
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP("smtp.gmail.com", 587) as srv:
            srv.starttls()
            srv.login(EMAIL_USER, EMAIL_PASS)
            srv.send_message(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=False)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


# ─────────────────────────────────────────
#  DATABASE SETUP
# ─────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            email      TEXT    UNIQUE NOT NULL,
            password   TEXT    NOT NULL,
            role       TEXT    DEFAULT 'customer',
            skill      TEXT    DEFAULT '',
            flat       TEXT    DEFAULT '',
            phone      TEXT    DEFAULT '',
            address    TEXT    DEFAULT '',
            society    TEXT    DEFAULT 'Shapoorji Complex, New Town',
            avatar     TEXT    DEFAULT '',
            joined_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS providers (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER UNIQUE NOT NULL,
            skill         TEXT    NOT NULL,
            rating        REAL    DEFAULT 5.0,
            reviews_count INTEGER DEFAULT 0,
            available     INTEGER DEFAULT 1,
            price_min     INTEGER DEFAULT 300,
            price_max     INTEGER DEFAULT 600,
            price_unit    TEXT    DEFAULT 'hr',
            experience    TEXT    DEFAULT '1 yr',
            jobs_done     INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS service_requests (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id  INTEGER NOT NULL,
            provider_id  INTEGER,
            service_type TEXT    NOT NULL,
            description  TEXT    NOT NULL,
            status       TEXT    DEFAULT 'Pending',
            emergency    INTEGER DEFAULT 0,
            cost         TEXT    DEFAULT 'TBD',
            society      TEXT    DEFAULT '',
            created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (customer_id) REFERENCES users(id),
            FOREIGN KEY (provider_id) REFERENCES users(id)
        )
    """)

    # Add society column to existing service_requests table if missing
    try:
        c.execute("ALTER TABLE service_requests ADD COLUMN society TEXT DEFAULT ''")
    except Exception:
        pass

    # Add completion_otp column for OTP-based job completion
    try:
        c.execute("ALTER TABLE service_requests ADD COLUMN completion_otp TEXT DEFAULT ''")
    except Exception:
        pass

    # Add declined_by column (comma-separated provider user IDs)
    try:
        c.execute("ALTER TABLE service_requests ADD COLUMN declined_by TEXT DEFAULT ''")
    except Exception:
        pass

    # Add image_data column for photo uploads
    try:
        c.execute("ALTER TABLE service_requests ADD COLUMN image_data TEXT DEFAULT ''")
    except Exception:
        pass

    # Ensure existing requests with status 'Declined' or missing statuses are handled
    # (no schema change needed — status is a TEXT field)

    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER,
            sender_id  INTEGER NOT NULL,
            content    TEXT    NOT NULL,
            translated TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (request_id) REFERENCES service_requests(id),
            FOREIGN KEY (sender_id)  REFERENCES users(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS reviews (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id  INTEGER NOT NULL,
            customer_id INTEGER NOT NULL,
            provider_id INTEGER NOT NULL,
            rating      INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
            comment     TEXT    DEFAULT '',
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            title      TEXT    NOT NULL,
            message    TEXT    NOT NULL,
            type       TEXT    DEFAULT 'info',
            read_flag  INTEGER DEFAULT 0,
            icon       TEXT    DEFAULT '🔔',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            society  TEXT NOT NULL DEFAULT 'Shapoorji Complex, New Town',
            category TEXT NOT NULL,
            title    TEXT NOT NULL,
            body     TEXT NOT NULL,
            icon     TEXT DEFAULT '📋'
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS support_tickets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            subject     TEXT    NOT NULL,
            message     TEXT    NOT NULL,
            status      TEXT    DEFAULT 'open',
            reply       TEXT    DEFAULT '',
            agent_id    INTEGER,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            token      TEXT    NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used       INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Persistent OTP store — survives server restarts on Render
    c.execute("""
        CREATE TABLE IF NOT EXISTS otp_tokens (
            key        TEXT PRIMARY KEY,
            otp        TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Clean up expired OTPs on startup
    c.execute("DELETE FROM otp_tokens WHERE expires_at < ?",
              (datetime.datetime.utcnow().isoformat(),))

    c.execute("SELECT COUNT(*) FROM rules")
    if c.fetchone()[0] == 0:
        _seed_rules(c)

    conn.commit()
    conn.close()
    print("✅ Database initialized.")


def _seed_rules(c):
    rules = [
        ("Shapoorji Complex, New Town","Eligibility","Income Eligibility","Spandan (LIG): Total average monthly gross family income must be within ₹30,000/month. Spriha (MIG-U): income within ₹80,000/month. Family includes spouse, dependent parents, and dependent children ONLY. In-laws are NOT considered. BSHDPL's decision is final and binding.","💰"),
        ("Shapoorji Complex, New Town","Parking","Parking Policy","One 2-wheeler parking (in-stilt) is MANDATORY for each Spandan allottee. 4-wheeler parking is optional via draw of lots. Prices: Open 4-wheeler ₹3,85,000 | In-stilt 4-wheeler ₹4,95,000 | 2-wheeler ₹70,000. Enclosing parking with walls or mesh is strictly prohibited.","🚗"),
        ("Shapoorji Complex, New Town","Possession","Possession Timeline","Spandan: Possession within 36 months from Provisional Allotment Letter. Spriha: Possession within 48 months. Delay beyond 12 months from Deemed Date of Possession = automatic cancellation.","🏠"),
        ("Shapoorji Complex, New Town","Payment","Payment & Default Policy","Allotment money must be paid within 45 days. No extension allowed. Delayed installments attract SBI MCLR + 2% interest + GST. Only Demand Draft, Pay Order, or online bank transfer accepted.","💳"),
        ("Shapoorji Complex, New Town","Maintenance","Maintenance Charges","First 12 months: Spandan ₹850/month + GST; Spriha ₹2,000/month + GST. Corpus Deposit (one-time): Spandan ₹6,400; Spriha ₹13,800. Late payment = 15% per annum interest.","🔧"),
        ("Shapoorji Complex, New Town","Modifications","No Structural Modifications","No structural or aesthetic changes permitted after possession. PROHIBITED: tampering with RCC beams, columns, slabs, lintels, external walls, waterproofing areas.","🔨"),
        ("Shapoorji Complex, New Town","Cancellation","Cancellation & Withdrawal","Before Draw of Lots — Spandan: ₹7,500 + GST; Spriha: ₹25,000 + GST. After Draw of Lots — Spandan: ₹15,000 + GST; Spriha: ₹50,000 + GST. Refund within 90 working days.","❌"),
        ("Shapoorji Complex, New Town","Legal","Jurisdiction & Arbitration","All disputes subject to exclusive jurisdiction of High Courts of Calcutta and/or Court of Barasat, West Bengal. Disputes resolved through Arbitration under the Arbitration and Conciliation Act 1996.","⚖️"),
    ]
    c.executemany("INSERT INTO rules (society,category,title,body,icon) VALUES (?,?,?,?,?)", rules)
    print(f"📋 {len(rules)} rules seeded.")


# ─────────────────────────────────────────
#  AUTH HELPERS
# ─────────────────────────────────────────
def generate_token(user_id: int, role: str) -> str:
    payload = {
        "user_id": user_id,
        "role":    role,
        "exp":     datetime.datetime.utcnow() + datetime.timedelta(days=30),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.replace("Bearer ", "").strip()
        if not token:
            return jsonify({"error": "Authorization token missing"}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_id   = data["user_id"]
            request.user_role = data["role"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if getattr(request, "user_role", None) != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────
#  HELPER
# ─────────────────────────────────────────
def push_notif(user_id, title, message, notif_type="info", icon="🔔"):
    db = get_db()
    db.execute("INSERT INTO notifications (user_id,title,message,type,icon) VALUES (?,?,?,?,?)",
               (user_id, title, message, notif_type, icon))
    db.commit()
    db.close()
    socketio.emit("notification", {"title": title, "message": message}, room=f"user_{user_id}")

def is_valid_email(email):
    return re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email.strip()) is not None

def is_valid_phone(phone):
    digits = re.sub(r'\D', '', phone)
    return len(digits) >= 10


# ═══════════════════════════════════════════
#  PING
# ═══════════════════════════════════════════
@app.route("/api/ping", methods=["GET", "OPTIONS"])
def ping():
    return jsonify({"status": "ok", "server": "SocietyConnect v2 ✅"}), 200


# ═══════════════════════════════════════════
#  AUTH ROUTES
# ═══════════════════════════════════════════
@app.route("/api/auth/signup", methods=["POST"])
def signup():
    d = request.get_json(force=True)

    name     = (d.get("name") or "").strip()
    email    = (d.get("email") or "").lower().strip()
    password = d.get("password") or ""
    phone    = (d.get("phone") or "").strip()
    role     = d.get("role", "customer")
    skill    = (d.get("skill") or "").strip()
    society  = (d.get("society") or "Shapoorji Complex, New Town").strip()

    # Validation
    if not name:
        return jsonify({"error": "Full name is required"}), 400
    if not email or not is_valid_email(email):
        return jsonify({"error": "A valid email address is required"}), 400
    if not password or len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if not phone or not is_valid_phone(phone):
        return jsonify({"error": "A valid 10-digit phone number is required"}), 400
    if role == "provider" and not skill:
        return jsonify({"error": "Skill is required for providers"}), 400

    # Normalize phone
    digits = re.sub(r'\D', '', phone)[-10:]
    phone_fmt = f"+91 {digits[:5]} {digits[5:]}"

    db = get_db()
    try:
        db.execute(
            """INSERT INTO users (name,email,password,role,skill,flat,phone,address,society,avatar)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (name, email, hash_pw(password), role, skill if role=="provider" else "",
             d.get("flat",""), phone_fmt, d.get("address",""), society, name[:2].upper())
        )
        db.commit()
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

        if role == "provider" and skill:
            primary_skill = skill.split(",")[0].strip()
            skill_prices = {
                "Plumber": (300, 500, "hr"), "Electrician": (400, 600, "hr"),
                "Cleaner": (200, 300, "hr"), "Shifting": (1000, 3000, "job"),
            }
            pmin, pmax, unit = skill_prices.get(primary_skill, (300, 500, "hr"))
            db.execute(
                "INSERT INTO providers (user_id,skill,price_min,price_max,price_unit) VALUES (?,?,?,?,?)",
                (user["id"], skill, pmin, pmax, unit)
            )
            db.commit()

        token = generate_token(user["id"], user["role"])
        return jsonify({"token": token, "user": dict(user)}), 201

    except Exception as e:
        if "UNIQUE constraint" in str(e):
            return jsonify({"error": "This email is already registered"}), 409
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


@app.route("/api/auth/login", methods=["POST"])
def login():
    """Verify credentials, send OTP (or return it if email not configured)."""
    d = request.get_json(force=True)
    email    = (d.get("email") or "").lower().strip()
    password = d.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    db = get_db()
    # Try exact match first, then case-insensitive fallback
    user = db.execute(
        "SELECT * FROM users WHERE email=? AND password=?",
        (email, hash_pw(password))
    ).fetchone()
    if not user:
        user = db.execute(
            "SELECT * FROM users WHERE LOWER(email)=? AND password=?",
            (email, hash_pw(password))
        ).fetchone()
    db.close()

    if not user:
        return jsonify({"error": "Incorrect email or password. Please check and try again."}), 401

    otp = str(random.randint(100000, 999999))
    otp_set(f"login_{user['id']}", otp)
    email_sent = send_email_otp(email, otp, "Login")
    resp = {"otp_required": True, "user_id": user["id"], "email_sent": email_sent}
    if not email_sent:
        resp["otp"] = otp
        resp["note"] = "Email not configured. Use this OTP to login."
    return jsonify(resp)


@app.route("/api/auth/login/verify-otp", methods=["POST"])
def login_verify_otp():
    """Step 2: verify OTP, return JWT token."""
    d = request.get_json(force=True)
    user_id = d.get("user_id")
    otp     = (d.get("otp") or "").strip()

    key = f"login_{user_id}"
    stored = otp_get(key)
    if not stored:
        return jsonify({"error": "OTP not found or expired. Please login again."}), 400
    if datetime.datetime.utcnow() > stored["expires"]:
        otp_delete(key)
        return jsonify({"error": "OTP expired. Please login again."}), 400
    if stored["otp"] != otp:
        return jsonify({"error": "Incorrect OTP. Try again."}), 400

    otp_delete(key)
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    db.close()
    if not user:
        return jsonify({"error": "User not found"}), 404

    token = generate_token(user["id"], user["role"])
    return jsonify({"token": token, "user": dict(user)})


@app.route("/api/auth/login/request-otp", methods=["POST"])
def login_request_otp():
    """Resend login OTP — called by frontend Resend button."""
    d = request.get_json(force=True)
    email = (d.get("email") or "").lower().strip()
    if not email:
        return jsonify({"error": "Email required"}), 400
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE LOWER(email)=?", (email,)).fetchone()
    db.close()
    if not user:
        return jsonify({"error": "No account found with that email"}), 404
    otp = str(random.randint(100000, 999999))
    otp_set(f"login_{user['id']}", otp)
    email_sent = send_email_otp(email, otp, "Login")
    resp = {"user_id": user["id"], "email_sent": email_sent}
    if not email_sent:
        resp["otp"] = otp
    return jsonify(resp)



def forgot_password():
    """Send OTP to email for password reset."""
    d = request.get_json(force=True)
    email = (d.get("email") or "").lower().strip()
    if not email:
        return jsonify({"error": "Email is required"}), 400

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    db.close()

    if not user:
        return jsonify({"message": "If that email exists, an OTP has been sent."}), 200

    otp = str(random.randint(100000, 999999))
    otp_set(f"forgot_{user['id']}", otp)
    email_sent = send_email_otp(email, otp, "Password Reset")
    resp = {"message": "OTP sent to your email.", "user_id": user["id"], "email_sent": email_sent}
    if not email_sent:
        resp["otp"] = otp
        resp["note"] = "Email not configured. Use this OTP to reset."
    return jsonify(resp)


@app.route("/api/auth/forgot-password/verify-otp", methods=["POST"])
def forgot_verify_otp():
    """Verify forgot-password OTP and set new password."""
    d = request.get_json(force=True)
    user_id      = d.get("user_id")
    otp          = (d.get("otp") or "").strip()
    new_password = d.get("new_password") or ""

    if not user_id or not otp or not new_password:
        return jsonify({"error": "user_id, otp and new_password required"}), 400
    if len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    key = f"forgot_{user_id}"
    stored = otp_get(key)
    if not stored:
        return jsonify({"error": "OTP not found or expired. Please request again."}), 400
    if datetime.datetime.utcnow() > stored["expires"]:
        otp_delete(key)
        return jsonify({"error": "OTP expired. Please request again."}), 400
    if stored["otp"] != otp:
        return jsonify({"error": "Incorrect OTP."}), 400

    otp_delete(key)
    db = get_db()
    db.execute("UPDATE users SET password=? WHERE id=?", (hash_pw(new_password), user_id))
    db.commit()
    db.close()
    return jsonify({"success": True, "message": "Password reset! Please login."})


@app.route("/api/auth/signup/send-otp", methods=["POST"])
def signup_send_otp():
    """Step 1 of signup: validate form data and send OTP to email before creating account."""
    d = request.get_json(force=True)

    name     = (d.get("name") or "").strip()
    email    = (d.get("email") or "").lower().strip()
    password = d.get("password") or ""
    phone    = (d.get("phone") or "").strip()
    role     = d.get("role", "customer")
    skill    = (d.get("skill") or "").strip()

    # Validation
    if not name:
        return jsonify({"error": "Full name is required"}), 400
    if not email or not is_valid_email(email):
        return jsonify({"error": "A valid email address is required"}), 400
    if not password or len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if not phone or not is_valid_phone(phone):
        return jsonify({"error": "A valid 10-digit phone number is required"}), 400
    if role == "provider" and not skill:
        return jsonify({"error": "Skill is required for providers"}), 400

    # Check if email already registered
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    db.close()
    if existing:
        return jsonify({"error": "This email is already registered"}), 409

    # Generate OTP and store all signup data temporarily
    otp = str(random.randint(100000, 999999))
    session_key = f"signup_{email}_{random.randint(10000, 99999)}"
    otp_set(session_key, otp)
    # Store signup data separately (keyed by session_key + _data)
    otp_store[session_key + "_data"] = d

    email_sent = send_email_otp(email, otp, "Sign Up Verification")
    resp = {"otp_required": True, "session_key": session_key, "email_sent": email_sent}
    if not email_sent:
        resp["otp"] = otp
        resp["note"] = "Email not configured. Use this OTP to complete signup."
    return jsonify(resp)


@app.route("/api/auth/signup/verify-otp", methods=["POST"])
def signup_verify_otp():
    """Step 2 of signup: verify OTP and create the account."""
    d = request.get_json(force=True)
    session_key = (d.get("session_key") or "").strip()
    otp         = (d.get("otp") or "").strip()

    if not session_key or not otp:
        return jsonify({"error": "session_key and otp are required"}), 400

    stored = otp_get(session_key)
    if not stored:
        return jsonify({"error": "Session expired or not found. Please sign up again."}), 400
    if datetime.datetime.utcnow() > stored["expires"]:
        otp_delete(session_key)
        return jsonify({"error": "OTP expired. Please sign up again."}), 400
    if stored["otp"] != otp:
        return jsonify({"error": "Incorrect OTP. Try again."}), 400

    # OTP matched — consume session and create account
    otp_delete(session_key)
    sd = otp_store.pop(session_key + "_data", None) or stored.get("signup_data") or {}

    name     = (sd.get("name") or "").strip()
    email    = (sd.get("email") or "").lower().strip()
    password = sd.get("password") or ""
    phone    = (sd.get("phone") or "").strip()
    role     = sd.get("role", "customer")
    skill    = (sd.get("skill") or "").strip()
    society  = (sd.get("society") or "Shapoorji Complex, New Town").strip()

    digits    = re.sub(r'\D', '', phone)[-10:]
    phone_fmt = f"+91 {digits[:5]} {digits[5:]}"

    db = get_db()
    try:
        db.execute(
            """INSERT INTO users (name,email,password,role,skill,flat,phone,address,society,avatar)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (name, email, hash_pw(password), role,
             skill if role == "provider" else "",
             sd.get("flat", ""), phone_fmt, sd.get("address", ""), society,
             name[:2].upper())
        )
        db.commit()
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

        if role == "provider" and skill:
            primary_skill = skill.split(",")[0].strip()
            skill_prices = {
                "Plumber": (300, 500, "hr"), "Electrician": (400, 600, "hr"),
                "Cleaner": (200, 300, "hr"), "Shifting": (1000, 3000, "job"),
            }
            pmin, pmax, unit = skill_prices.get(primary_skill, (300, 500, "hr"))
            db.execute(
                "INSERT INTO providers (user_id,skill,price_min,price_max,price_unit) VALUES (?,?,?,?,?)",
                (user["id"], skill, pmin, pmax, unit)
            )
            db.commit()

        token = generate_token(user["id"], user["role"])
        return jsonify({"token": token, "user": dict(user)}), 201

    except Exception as e:
        if "UNIQUE constraint" in str(e):
            return jsonify({"error": "This email is already registered"}), 409
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()



# ═══════════════════════════════════════════
#  USER ROUTES
# ═══════════════════════════════════════════
@app.route("/api/users/me", methods=["GET"])
@token_required
def get_me():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (request.user_id,)).fetchone()
    if not user:
        db.close()
        return jsonify({"error": "User not found"}), 404
    result = dict(user)
    # Always merge provider info if exists
    prov = db.execute("SELECT * FROM providers WHERE user_id=?", (request.user_id,)).fetchone()
    if prov:
        result.update(dict(prov))
    db.close()
    return jsonify(result)


@app.route("/api/users/me", methods=["PUT"])
@token_required
def update_me():
    d = request.get_json(force=True)
    allowed = ["name", "address", "society", "flat"]
    updates = {k: v for k, v in d.items() if k in allowed and v is not None}

    db = get_db()

    if updates:
        set_clause = ", ".join(f"{k}=?" for k in updates)
        db.execute(f"UPDATE users SET {set_clause} WHERE id=?",
                   list(updates.values()) + [request.user_id])
        db.commit()

    # Also update provider experience if provided separately
    experience = d.get("experience")
    if experience is not None:
        db.execute("UPDATE providers SET experience=? WHERE user_id=?",
                   (experience, request.user_id))
        db.commit()

    user = db.execute("SELECT * FROM users WHERE id=?", (request.user_id,)).fetchone()
    prov = db.execute("SELECT * FROM providers WHERE user_id=?", (request.user_id,)).fetchone()
    db.close()

    result = dict(user)
    if prov:
        result.update(dict(prov))
    return jsonify(result)


@app.route("/api/users/me", methods=["DELETE"])
@token_required
def delete_account():
    """Permanently delete the user account and all related data."""
    user_id = request.user_id
    db = get_db()
    try:
        # Delete in order (child tables first)
        db.execute("DELETE FROM notifications WHERE user_id=?", (user_id,))
        db.execute("DELETE FROM password_resets WHERE user_id=?", (user_id,))
        db.execute("DELETE FROM reviews WHERE customer_id=? OR provider_id=?", (user_id, user_id))
        db.execute("DELETE FROM messages WHERE sender_id=?", (user_id,))
        db.execute("DELETE FROM service_requests WHERE customer_id=? OR provider_id=?", (user_id, user_id))
        db.execute("DELETE FROM providers WHERE user_id=?", (user_id,))
        db.execute("DELETE FROM support_tickets WHERE user_id=?", (user_id,))
        db.execute("DELETE FROM users WHERE id=?", (user_id,))
        db.commit()
        db.close()
        return jsonify({"message": "Account deleted successfully"}), 200
    except Exception as e:
        db.close()
        return jsonify({"error": str(e)}), 500


@app.route("/api/users/me/switch-role", methods=["POST"])
@token_required
def switch_role():
    """Switch customer → provider or provider → customer."""
    d = request.get_json(force=True)
    new_role = d.get("role", "").strip()
    skill    = (d.get("skill") or "").strip()
    experience = (d.get("experience") or "").strip()

    if new_role not in ("customer", "provider"):
        return jsonify({"error": "Role must be 'customer' or 'provider'"}), 400
    if new_role == "provider" and not skill:
        return jsonify({"error": "Skill is required to become a provider"}), 400

    db = get_db()
    db.execute("UPDATE users SET role=?, skill=? WHERE id=?",
               (new_role, skill if new_role=="provider" else "", request.user_id))
    db.commit()

    if new_role == "provider":
        existing = db.execute("SELECT id FROM providers WHERE user_id=?", (request.user_id,)).fetchone()
        if not existing:
            # Use first skill for pricing if multiple given
            primary_skill = skill.split(",")[0].strip() if skill else skill
            skill_prices = {
                "Plumber": (300, 500, "hr"), "Electrician": (400, 600, "hr"),
                "Cleaner": (200, 300, "hr"), "Shifting": (1000, 3000, "job"),
            }
            pmin, pmax, unit = skill_prices.get(primary_skill, (300, 500, "hr"))
            db.execute(
                "INSERT INTO providers (user_id,skill,price_min,price_max,price_unit,experience) VALUES (?,?,?,?,?,?)",
                (request.user_id, skill, pmin, pmax, unit, experience or "1 yr")
            )
        else:
            db.execute("UPDATE providers SET skill=?, experience=? WHERE user_id=?",
                       (skill, experience or "1 yr", request.user_id))
        db.commit()

    user = db.execute("SELECT * FROM users WHERE id=?", (request.user_id,)).fetchone()

    # Get provider info if switched to provider
    prov = None
    if new_role == "provider":
        prov = db.execute("SELECT * FROM providers WHERE user_id=?", (request.user_id,)).fetchone()

    db.close()

    # Issue new token with updated role
    new_token = generate_token(request.user_id, new_role)
    result = dict(user)
    if prov:
        result.update(dict(prov))

    return jsonify({"token": new_token, "user": result}), 200


@app.route("/api/users/all", methods=["GET"])
@token_required
def get_all_users():
    if request.user_role != "admin":
        return jsonify({"error": "Forbidden"}), 403
    db = get_db()
    users = db.execute("SELECT id,name,email,role,flat,phone,society,joined_at FROM users").fetchall()
    db.close()
    return jsonify([dict(u) for u in users])


# ═══════════════════════════════════════════
#  PROVIDER ROUTES
# ═══════════════════════════════════════════
@app.route("/api/providers", methods=["GET"])
def get_providers():
    skill   = request.args.get("skill")
    avail   = request.args.get("available", "")
    society = request.args.get("society", "")
    db = get_db()
    base = """
        SELECT u.id, u.name, u.flat, u.avatar, u.society,
               p.skill, p.rating, p.reviews_count, p.available,
               p.price_min, p.price_max, p.price_unit, p.experience, p.jobs_done
        FROM users u
        JOIN providers p ON u.id = p.user_id
        WHERE 1=1
    """
    params = []
    if skill:
        # Support multi-skill: provider's skill field may contain comma-separated values
        base += " AND (',' || p.skill || ',') LIKE ?"; params.append(f"%,{skill},%")
    if avail == "1":
        base += " AND p.available=1"
    if society:
        base += " AND u.society=?"; params.append(society)
    base += " ORDER BY p.rating DESC, p.jobs_done DESC"
    rows = db.execute(base, params).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/providers/me", methods=["PUT"])
@token_required
def update_provider_profile():
    """Update provider-specific fields: experience, price, availability."""
    d = request.get_json(force=True)
    db = get_db()
    allowed = ["experience", "price_min", "price_max", "available"]
    updates = {k: v for k, v in d.items() if k in allowed and v is not None}
    if updates:
        set_clause = ", ".join(f"{k}=?" for k in updates)
        db.execute(f"UPDATE providers SET {set_clause} WHERE user_id=?",
                   list(updates.values()) + [request.user_id])
        db.commit()
    user = db.execute("SELECT * FROM users WHERE id=?", (request.user_id,)).fetchone()
    prov = db.execute("SELECT * FROM providers WHERE user_id=?", (request.user_id,)).fetchone()
    db.close()
    result = dict(user)
    if prov: result.update(dict(prov))
    return jsonify(result)


@app.route("/api/providers/me/availability", methods=["PUT"])
@token_required
def toggle_availability():
    d = request.get_json(force=True)
    db = get_db()
    db.execute("UPDATE providers SET available=? WHERE user_id=?",
               (1 if d.get("available") else 0, request.user_id))
    db.commit()
    db.close()
    return jsonify({"success": True})


# ═══════════════════════════════════════════
#  SERVICE REQUESTS
# ═══════════════════════════════════════════
@app.route("/api/requests", methods=["GET"])
@token_required
def get_requests():
    db = get_db()
    role = request.user_role

    if role == "customer":
        rows = db.execute("""
            SELECT r.*, u.name AS provider_name, u.avatar AS provider_avatar
            FROM service_requests r
            LEFT JOIN users u ON r.provider_id = u.id
            WHERE r.customer_id=?
            ORDER BY r.created_at DESC
        """, (request.user_id,)).fetchall()

    elif role == "provider":
        # Support multi-skill: provider's skill field may be comma-separated
        user = db.execute("SELECT society, skill FROM users WHERE id=?", (request.user_id,)).fetchone()
        user_society = user["society"] if user else ""
        user_skill_str = user["skill"] if user else ""
        skills = [s.strip() for s in user_skill_str.split(",") if s.strip()]

        # Get requests already assigned to this provider
        assigned_rows = db.execute("""
            SELECT r.*, cu.name AS customer_name, cu.flat AS flat, cu.avatar AS customer_avatar
            FROM service_requests r
            JOIN users cu ON r.customer_id = cu.id
            WHERE r.provider_id=?
            ORDER BY r.created_at DESC
        """, (request.user_id,)).fetchall()

        # Get open pending requests matching any of provider's skills, in same society
        open_rows = []
        for skill in skills:
            skill_rows = db.execute("""
                SELECT r.*, cu.name AS customer_name, cu.flat AS flat, cu.avatar AS customer_avatar
                FROM service_requests r
                JOIN users cu ON r.customer_id = cu.id
                WHERE r.status='Pending' AND r.service_type=? AND cu.society=?
                AND (r.provider_id IS NULL OR r.provider_id=0)
                ORDER BY r.created_at DESC
            """, (skill, user_society)).fetchall()
            open_rows.extend(skill_rows)

        # Filter out requests this provider has declined
        filtered_open = []
        for row in open_rows:
            declined_ids = [x for x in (row["declined_by"] or "").split(",") if x]
            if str(request.user_id) not in declined_ids:
                filtered_open.append(row)

        # Merge, deduplicate
        seen = set()
        combined = []
        for r in list(assigned_rows) + filtered_open:
            if r["id"] not in seen:
                seen.add(r["id"])
                combined.append(r)
        rows = combined

    else:  # admin
        rows = db.execute("""
            SELECT r.*, cu.name AS customer_name, pu.name AS provider_name
            FROM service_requests r
            LEFT JOIN users cu ON r.customer_id = cu.id
            LEFT JOIN users pu ON r.provider_id = pu.id
            ORDER BY r.created_at DESC
        """).fetchall()

    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/requests", methods=["POST"])
@token_required
def create_request():
    d = request.get_json(force=True)
    service_type = d.get("service_type", "")
    description  = d.get("description", "")
    emergency    = 1 if d.get("emergency") else 0
    image_data   = d.get("image_data", "")   # base64 image string
    preferred_provider_id = d.get("preferred_provider_id")

    if not service_type or not description:
        return jsonify({"error": "service_type and description are required"}), 400

    db = get_db()
    user = db.execute("SELECT society FROM users WHERE id=?", (request.user_id,)).fetchone()
    society = user["society"] if user else ""

    provider_id = None
    status      = "Pending"
    price_map   = {"Plumber":"₹300–500","Electrician":"₹400–600","Cleaner":"₹200–300","Shifting":"₹1,000–3,000"}
    cost        = price_map.get(service_type, "TBD")

    db.execute(
        """INSERT INTO service_requests
           (customer_id, provider_id, service_type, description, status, emergency, cost, society, image_data)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (request.user_id, provider_id, service_type, description, status, emergency, cost, society, image_data)
    )
    db.commit()
    req_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    push_notif(request.user_id, "Request Submitted",
               f"Your {service_type} request is live. Providers in {society} can accept it.", "info", "📋")
    # Notify all available providers in same society with matching skill
    avail_provs = db.execute(
        """SELECT p.user_id FROM providers p
           JOIN users u ON p.user_id = u.id
           WHERE (',' || p.skill || ',') LIKE ? AND p.available=1 AND u.society=?""",
        (f"%,{service_type},%", society)
    ).fetchall()
    for prov in avail_provs:
        push_notif(prov["user_id"], f"New {service_type} Request",
                   f"A new {service_type} request in {society} is waiting for acceptance.", "info", "🔔")

    req = db.execute("SELECT * FROM service_requests WHERE id=?", (req_id,)).fetchone()
    db.close()
    socketio.emit("new_request", dict(req), room=f"society_{society}")
    return jsonify(dict(req)), 201


@app.route("/api/requests/<int:req_id>", methods=["PUT"])
@token_required
def update_request(req_id):
    d = request.get_json(force=True)
    db = get_db()

    updates = {}
    if "status" in d: updates["status"] = d["status"]
    if "cost"   in d: updates["cost"]   = d["cost"]
    if "provider_id" in d: updates["provider_id"] = d["provider_id"]

    if not updates:
        return jsonify({"error": "No valid fields"}), 400

    set_clause = ", ".join(f"{k}=?" for k in updates)
    db.execute(f"UPDATE service_requests SET {set_clause} WHERE id=?",
               list(updates.values()) + [req_id])
    db.commit()

    req = db.execute("SELECT * FROM service_requests WHERE id=?", (req_id,)).fetchone()
    if "status" in updates and req:
        icons = {"On the way":"🚗","Coming":"🚶","Arrived":"🏠","Reached":"🏠","Completed":"✅","In Progress":"⚙️","Pending":"⏳","Declined":"❌","Cancelled":"❌","Accepted":"✅"}
        push_notif(req["customer_id"], f"Provider Update: {updates['status']}",
                   f"Your {req['service_type']} request: {updates['status']}", "status",
                   icons.get(updates["status"], "🔔"))

    db.close()
    socketio.emit("request_updated", dict(req), room=f"request_{req_id}")
    return jsonify(dict(req))


# ═══════════════════════════════════════════
#  MESSAGES
# ═══════════════════════════════════════════
@app.route("/api/messages/<int:request_id>", methods=["GET"])
@token_required
def get_messages(request_id):
    db = get_db()
    rows = db.execute(
        """SELECT m.*, u.name AS sender_name, u.role AS sender_role
           FROM messages m JOIN users u ON m.sender_id = u.id
           WHERE m.request_id=? ORDER BY m.created_at ASC""",
        (request_id,)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/messages", methods=["POST"])
@token_required
def send_message():
    d = request.get_json(force=True)
    content    = (d.get("content") or "").strip()
    request_id = d.get("request_id")
    if not content:
        return jsonify({"error": "Message cannot be empty"}), 400
    db = get_db()
    db.execute("INSERT INTO messages (request_id, sender_id, content) VALUES (?,?,?)",
               (request_id, request.user_id, content))
    db.commit()
    msg_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    msg = db.execute(
        """SELECT m.*, u.name AS sender_name, u.role AS sender_role
           FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.id=?""",
        (msg_id,)
    ).fetchone()
    req = db.execute("SELECT * FROM service_requests WHERE id=?", (request_id,)).fetchone() if request_id else None
    if req:
        target = req["provider_id"] if request.user_id == req["customer_id"] else req["customer_id"]
        if target:
            sender = db.execute("SELECT name FROM users WHERE id=?", (request.user_id,)).fetchone()
            push_notif(target, "New Message", f"{sender['name']}: {content[:60]}", "chat", "💬")
    db.close()
    socketio.emit("new_message", dict(msg), room=f"request_{request_id or 0}")
    return jsonify(dict(msg)), 201


@app.route("/api/requests/<int:req_id>/decline", methods=["POST"])
@token_required
def decline_request(req_id):
    """Provider declines/skips a job — it is hidden from their view."""
    if request.user_role != "provider":
        return jsonify({"error": "Only providers can decline requests"}), 403
    db = get_db()
    req = db.execute("SELECT * FROM service_requests WHERE id=?", (req_id,)).fetchone()
    if not req:
        db.close()
        return jsonify({"error": "Request not found"}), 404
    declined_ids = [x for x in (req["declined_by"] or "").split(",") if x]
    if str(request.user_id) not in declined_ids:
        declined_ids.append(str(request.user_id))
    db.execute("UPDATE service_requests SET declined_by=? WHERE id=?",
               (",".join(declined_ids), req_id))
    db.commit()
    updated = db.execute("SELECT * FROM service_requests WHERE id=?", (req_id,)).fetchone()
    db.close()
    return jsonify({"success": True, "request": dict(updated)})


@app.route("/api/requests/<int:req_id>/accept", methods=["POST"])
@token_required
def accept_request(req_id):
    """Provider accepts a pending job."""
    if request.user_role != "provider":
        return jsonify({"error": "Only providers can accept requests"}), 403
    db = get_db()
    req = db.execute("SELECT * FROM service_requests WHERE id=?", (req_id,)).fetchone()
    if not req:
        db.close()
        return jsonify({"error": "Request not found"}), 404
    if req["status"] != "Pending":
        db.close()
        return jsonify({"error": "Request is no longer pending"}), 400
    if req["provider_id"] and req["provider_id"] != request.user_id:
        db.close()
        return jsonify({"error": "Request already assigned to another provider"}), 400
    db.execute("UPDATE service_requests SET provider_id=?, status='Accepted' WHERE id=?",
               (request.user_id, req_id))
    db.commit()
    req_updated = db.execute("SELECT * FROM service_requests WHERE id=?", (req_id,)).fetchone()
    prov_name = db.execute("SELECT name FROM users WHERE id=?", (request.user_id,)).fetchone()
    push_notif(req["customer_id"], "Provider Accepted! 🎉",
               f"{prov_name['name']} accepted your {req['service_type']} request.", "assign", "👷")
    db.close()
    socketio.emit("request_updated", dict(req_updated), room=f"request_{req_id}")
    socketio.emit("request_updated", dict(req_updated), room=f"society_{req_updated['society']}")
    return jsonify(dict(req_updated))


@app.route("/api/requests/<int:req_id>/cancel", methods=["POST"])
@token_required
def cancel_request(req_id):
    """Customer or provider can cancel before work starts (In Progress)."""
    db = get_db()
    req = db.execute("SELECT * FROM service_requests WHERE id=?", (req_id,)).fetchone()
    if not req:
        db.close()
        return jsonify({"error": "Request not found"}), 404

    # Permission check
    is_customer = req["customer_id"] == request.user_id
    is_provider = req["provider_id"] == request.user_id

    if not is_customer and not is_provider:
        db.close()
        return jsonify({"error": "Not authorized to cancel this request"}), 403

    # Can only cancel before work has started
    if req["status"] in ("In Progress", "Completed"):
        db.close()
        return jsonify({"error": "Cannot cancel after work has started or completed"}), 400

    # Always mark the original request as Cancelled
    db.execute("UPDATE service_requests SET status='Cancelled', provider_id=NULL WHERE id=?", (req_id,))
    db.commit()

    # Notify the other party
    if is_customer and req["provider_id"]:
        customer = db.execute("SELECT name FROM users WHERE id=?", (request.user_id,)).fetchone()
        push_notif(req["provider_id"], "Request Cancelled",
                   f"{customer['name']} cancelled the {req['service_type']} request.", "info", "❌")
    elif is_provider:
        prov_user = db.execute("SELECT name FROM users WHERE id=?", (request.user_id,)).fetchone()
        push_notif(req["customer_id"], "Provider Cancelled",
                   f"Your provider cancelled the {req['service_type']} request. A new request has been broadcast.", "info", "❌")
        # Create a NEW pending request so other providers can pick it up (don't mutate the cancelled one)
        db.execute(
            """INSERT INTO service_requests
               (customer_id, provider_id, service_type, description, status, emergency, cost, society)
               VALUES (?,NULL,?,?,?,?,?,?)""",
            (req["customer_id"], req["service_type"], req["description"],
             "Pending", req["emergency"], req["cost"], req["society"])
        )
        db.commit()

    req_updated = db.execute("SELECT * FROM service_requests WHERE id=?", (req_id,)).fetchone()
    db.close()
    socketio.emit("request_updated", dict(req_updated), room=f"request_{req_id}")
    return jsonify(dict(req_updated))


@app.route("/api/requests/<int:req_id>/start-work", methods=["POST"])
@token_required
def start_work(req_id):
    """Both customer and provider must confirm to mark work as started (In Progress)."""
    db = get_db()
    req = db.execute("SELECT * FROM service_requests WHERE id=?", (req_id,)).fetchone()
    if not req:
        db.close()
        return jsonify({"error": "Request not found"}), 404

    is_customer = req["customer_id"] == request.user_id
    is_provider = req["provider_id"] == request.user_id

    if not is_customer and not is_provider:
        db.close()
        return jsonify({"error": "Not authorized"}), 403

    if req["status"] not in ("Accepted", "On the way", "Coming", "Reached", "Arrived"):
        db.close()
        return jsonify({"error": "Cannot start work in current state"}), 400

    db.execute("UPDATE service_requests SET status='In Progress' WHERE id=?", (req_id,))
    db.commit()

    req_updated = db.execute("SELECT * FROM service_requests WHERE id=?", (req_id,)).fetchone()

    # Notify the other party
    if is_provider:
        push_notif(req["customer_id"], "Work Started! ⚙️",
                   f"Your provider has started working on the {req['service_type']} job.", "status", "⚙️")
    else:
        if req["provider_id"]:
            push_notif(req["provider_id"], "Customer Confirmed Work Start",
                       f"Customer has confirmed work start for {req['service_type']} job.", "status", "⚙️")

    db.close()
    socketio.emit("request_updated", dict(req_updated), room=f"request_{req_id}")
    return jsonify(dict(req_updated))


@app.route("/api/requests/<int:req_id>/generate-otp", methods=["POST"])
@token_required
def generate_otp(req_id):
    """Customer generates a 6-digit OTP to verify job completion."""
    if request.user_role != "customer":
        return jsonify({"error": "Only customers can generate OTP"}), 403
    db = get_db()
    req = db.execute("SELECT * FROM service_requests WHERE id=? AND customer_id=?",
                     (req_id, request.user_id)).fetchone()
    if not req:
        db.close()
        return jsonify({"error": "Request not found"}), 404
    if req["status"] not in ("In Progress", "Arrived", "On the way", "Coming", "Reached"):
        db.close()
        return jsonify({"error": "OTP can only be generated for active jobs"}), 400
    import secrets, random
    otp = str(random.randint(100000, 999999))
    db.execute("UPDATE service_requests SET completion_otp=? WHERE id=?", (otp, req_id))
    db.commit()
    db.close()
    return jsonify({"otp": otp})


@app.route("/api/requests/<int:req_id>/complete-otp", methods=["POST"])
@token_required
def complete_with_otp(req_id):
    """Provider submits OTP to mark job as completed."""
    if request.user_role != "provider":
        return jsonify({"error": "Only providers can submit OTP"}), 403
    d = request.get_json(force=True)
    otp = (d.get("otp") or "").strip()
    db = get_db()
    req = db.execute("SELECT * FROM service_requests WHERE id=? AND provider_id=?",
                     (req_id, request.user_id)).fetchone()
    if not req:
        db.close()
        return jsonify({"error": "Request not found or not assigned to you"}), 404
    if not req["completion_otp"]:
        db.close()
        return jsonify({"error": "Customer hasn't generated an OTP yet. Ask them to generate one."}), 400
    if req["completion_otp"] != otp:
        db.close()
        return jsonify({"error": "Invalid OTP. Please check with your customer."}), 400
    # OTP matched — mark complete
    db.execute("UPDATE service_requests SET status='Completed', completion_otp='' WHERE id=?", (req_id,))
    db.execute("UPDATE providers SET jobs_done=jobs_done+1 WHERE user_id=?", (request.user_id,))
    db.commit()
    push_notif(req["customer_id"], "Job Completed! ✅",
               f"Your {req['service_type']} job has been completed. Rate your provider!", "complete", "✅")
    req_updated = db.execute("SELECT * FROM service_requests WHERE id=?", (req_id,)).fetchone()
    db.close()
    socketio.emit("request_updated", dict(req_updated), room=f"request_{req_id}")
    return jsonify(dict(req_updated))


# ═══════════════════════════════════════════
#  REVIEWS
# ═══════════════════════════════════════════
@app.route("/api/reviews", methods=["POST"])
@token_required
def create_review():
    d = request.get_json(force=True)
    rating = int(d.get("rating", 0))
    provider_id = d.get("provider_id")
    if not 1 <= rating <= 5:
        return jsonify({"error": "Rating must be 1–5"}), 400
    if not provider_id:
        return jsonify({"error": "provider_id required"}), 400
    db = get_db()
    try:
        # Prevent duplicate rating for same request
        existing = db.execute(
            "SELECT id FROM reviews WHERE request_id=? AND customer_id=?",
            (d.get("request_id"), request.user_id)
        ).fetchone()
        if existing:
            db.close()
            return jsonify({"error": "You have already rated this job"}), 409

        db.execute("INSERT INTO reviews (request_id,customer_id,provider_id,rating,comment) VALUES (?,?,?,?,?)",
                   (d.get("request_id"), request.user_id, provider_id, rating, d.get("comment","")))
        avg = db.execute("SELECT AVG(rating) AS a, COUNT(*) AS c FROM reviews WHERE provider_id=?", (provider_id,)).fetchone()
        db.execute("UPDATE providers SET rating=?, reviews_count=? WHERE user_id=?",
                   (round(avg["a"],1), avg["c"], provider_id))
        db.commit()
        push_notif(provider_id, "New Review! ⭐", f"You received a {rating}⭐ rating!", "review", "⭐")
        db.close()
        return jsonify({"success": True, "new_rating": round(avg["a"],1)}), 201
    except Exception as e:
        db.close()
        return jsonify({"error": str(e)}), 500


@app.route("/api/reviews/check/<int:req_id>", methods=["GET"])
@token_required
def check_my_rating(req_id):
    """Check if the current user has already rated a specific request."""
    db = get_db()
    row = db.execute(
        "SELECT rating, comment FROM reviews WHERE request_id=? AND customer_id=?",
        (req_id, request.user_id)
    ).fetchone()
    db.close()
    if row:
        return jsonify({"rated": True, "rating": row["rating"], "comment": row["comment"]})
    return jsonify({"rated": False, "rating": None})


@app.route("/api/reviews/provider/<int:provider_id>", methods=["GET"])
def get_provider_reviews(provider_id):
    """Get all reviews for a specific provider — public endpoint."""
    db = get_db()
    rows = db.execute(
        """SELECT r.*, u.name AS customer_name
           FROM reviews r JOIN users u ON r.customer_id = u.id
           WHERE r.provider_id=?
           ORDER BY r.created_at DESC LIMIT 20""",
        (provider_id,)
    ).fetchall()
    # Also get aggregate stats
    stats = db.execute(
        "SELECT AVG(rating) AS avg_rating, COUNT(*) AS total FROM reviews WHERE provider_id=?",
        (provider_id,)
    ).fetchone()
    db.close()
    return jsonify({
        "reviews": [dict(r) for r in rows],
        "avg_rating": round(stats["avg_rating"] or 0, 1),
        "total": stats["total"]
    })


# ═══════════════════════════════════════════
#  NOTIFICATIONS
# ═══════════════════════════════════════════
@app.route("/api/notifications", methods=["GET"])
@token_required
def get_notifications():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50",
        (request.user_id,)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/notifications/<int:notif_id>/read", methods=["PUT"])
@token_required
def mark_read(notif_id):
    db = get_db()
    db.execute("UPDATE notifications SET read_flag=1 WHERE id=? AND user_id=?", (notif_id, request.user_id))
    db.commit(); db.close()
    return jsonify({"success": True})


@app.route("/api/notifications/read-all", methods=["PUT"])
@token_required
def mark_all_read():
    db = get_db()
    db.execute("UPDATE notifications SET read_flag=1 WHERE user_id=?", (request.user_id,))
    db.commit(); db.close()
    return jsonify({"success": True})


# ═══════════════════════════════════════════
#  RULES
# ═══════════════════════════════════════════
@app.route("/api/rules", methods=["GET"])
def get_rules():
    society = request.args.get("society", "Shapoorji Complex, New Town")
    db = get_db()
    rows = db.execute("SELECT * FROM rules WHERE society=? ORDER BY id", (society,)).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


# ═══════════════════════════════════════════
#  SUPPORT / CONTACT US
# ═══════════════════════════════════════════
@app.route("/api/support", methods=["POST"])
@token_required
def create_ticket():
    d = request.get_json(force=True)
    subject = (d.get("subject") or "").strip()
    message = (d.get("message") or "").strip()
    if not subject or not message:
        return jsonify({"error": "Subject and message are required"}), 400
    db = get_db()
    db.execute("INSERT INTO support_tickets (user_id,subject,message) VALUES (?,?,?)",
               (request.user_id, subject, message))
    db.commit()
    ticket_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    ticket = db.execute("SELECT * FROM support_tickets WHERE id=?", (ticket_id,)).fetchone()
    db.close()
    push_notif(request.user_id, "Support Ticket Created",
               f"Your ticket '{subject}' has been submitted. We'll respond shortly.", "info", "🎧")
    return jsonify(dict(ticket)), 201


@app.route("/api/support", methods=["GET"])
@token_required
def get_tickets():
    db = get_db()
    if request.user_role == "admin":
        rows = db.execute(
            """SELECT t.*, u.name AS user_name, u.email AS user_email
               FROM support_tickets t JOIN users u ON t.user_id = u.id
               ORDER BY t.created_at DESC"""
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM support_tickets WHERE user_id=? ORDER BY created_at DESC",
            (request.user_id,)
        ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/support/<int:ticket_id>/reply", methods=["PUT"])
@token_required
def reply_ticket(ticket_id):
    if request.user_role != "admin":
        return jsonify({"error": "Admin only"}), 403
    d = request.get_json(force=True)
    reply = (d.get("reply") or "").strip()
    if not reply:
        return jsonify({"error": "Reply cannot be empty"}), 400
    db = get_db()
    db.execute("UPDATE support_tickets SET reply=?, status='resolved', agent_id=? WHERE id=?",
               (reply, request.user_id, ticket_id))
    db.commit()
    ticket = db.execute("SELECT * FROM support_tickets WHERE id=?", (ticket_id,)).fetchone()
    if ticket:
        push_notif(ticket["user_id"], "Support Reply Received",
                   f"Your ticket has been resolved: {reply[:60]}", "info", "🎧")
    db.close()
    return jsonify(dict(ticket))


# ═══════════════════════════════════════════
#  ADMIN
# ═══════════════════════════════════════════
@app.route("/api/admin/stats", methods=["GET"])
@token_required
@admin_required
def admin_stats():
    db = get_db()
    stats = {
        "total_users":          db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_customers":      db.execute("SELECT COUNT(*) FROM users WHERE role='customer'").fetchone()[0],
        "total_providers":      db.execute("SELECT COUNT(*) FROM providers").fetchone()[0],
        "total_requests":       db.execute("SELECT COUNT(*) FROM service_requests").fetchone()[0],
        "completed_requests":   db.execute("SELECT COUNT(*) FROM service_requests WHERE status='Completed'").fetchone()[0],
        "pending_requests":     db.execute("SELECT COUNT(*) FROM service_requests WHERE status='Pending'").fetchone()[0],
        "open_support_tickets": db.execute("SELECT COUNT(*) FROM support_tickets WHERE status='open'").fetchone()[0],
    }
    db.close()
    return jsonify(stats)


# ═══════════════════════════════════════════
#  SOCKET.IO
# ═══════════════════════════════════════════
@socketio.on("connect")
def on_connect():
    print(f"🔌 Client connected: {request.sid}")

@socketio.on("disconnect")
def on_disconnect():
    print(f"🔌 Disconnected: {request.sid}")

@socketio.on("join_room")
def on_join(data):
    room = data.get("room")
    if room:
        join_room(room)
        emit("joined", {"room": room})

@socketio.on("leave_room")
def on_leave(data):
    room = data.get("room")
    if room: leave_room(room)

@socketio.on("send_message")
def on_send_message(data):
    room = data.get("room")
    if room: emit("new_message", data, room=room, include_self=False)


# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("""
╔══════════════════════════════════════════════════════╗
║       SocietyConnect Backend v3 — Running!           ║
╠══════════════════════════════════════════════════════╣
║  http://localhost:5000                               ║
╠══════════════════════════════════════════════════════╣
║  NEW ENDPOINTS (v4):                                 ║
║    POST /api/auth/signup/send-otp   — Send signup OTP║
║    POST /api/auth/signup/verify-otp — Verify & create║
║    POST /api/requests/:id/decline   — Skip job       ║
║    POST /api/requests/:id/generate-otp — Get OTP     ║
║    POST /api/requests/:id/complete-otp — Submit OTP  ║
║  UPDATED:                                            ║
║    GET /api/providers — multi-skill support          ║
║    POST /api/requests — preferred_provider_id        ║
╚══════════════════════════════════════════════════════╝
    """)
    socketio.run(app, debug=False, host="0.0.0.0", port=PORT, use_reloader=False, allow_unsafe_werkzeug=True)
