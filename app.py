import os
import re
import random
import bcrypt
import cloudinary
import cloudinary.uploader
from datetime import datetime, timedelta
from io import BytesIO
import logging
import json
import sendgrid
from sendgrid.helpers.mail import Mail

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.datastructures import FileStorage
from dotenv import load_dotenv

# supabase client (ensure package installed in your env)
from supabase import create_client, Client

# pillow
from PIL import Image

# -----------------------------
# LOAD ENV
# -----------------------------
load_dotenv()

# ---------- logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# -----------------------------
# APP CONFIG
# -----------------------------
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024   # 20MB upload limit
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret")

# Allow all origins by default (you can restrict later)
CORS(app)

# -----------------------------
# RATE LIMITER
# -----------------------------
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10 per minute", "200 per day"]
)
limiter.init_app(app)

# -----------------------------
# SUPABASE CONFIG
# -----------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
if not SUPABASE_URL or not SUPABASE_KEY:
    logger.warning("Supabase URL or KEY missing from env (SUPABASE_URL / SUPABASE_KEY).")

# create client (may raise if env invalid) — catch exceptions
supabase: Client = None
try:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception as e:
    logger.exception("Failed to create Supabase client: %s", str(e))
    # keep supabase as None; routes will return helpful error if used

# -----------------------------
# CLOUDINARY CONFIG (optional)
# -----------------------------
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET")
)

# -----------------------------
# ALLOWED FILES
# -----------------------------
ALLOWED_EXT = {"jpg", "jpeg", "png"}
ALLOWED_MIME = {"image/png", "image/jpeg"}

def allowed_file(file: FileStorage):
    if not file or not getattr(file, "filename", None):
        return False
    ext = file.filename.rsplit(".", 1)[-1].lower()
    return ext in ALLOWED_EXT and file.mimetype in ALLOWED_MIME

# -----------------------------
# REGEX VALIDATIONS
# -----------------------------
PHONE_REGEX = re.compile(r"^\+2547\d{8}$")  # +2547XXXXXXXX
PLATE_REGEX = re.compile(r"^[A-Z]{1,3}\d{3,4}[A-Z]?$")

def normalize_plate(plate: str) -> str:
    return plate.replace(" ", "").upper()

def valid_plate(plate: str) -> bool:
    return bool(PLATE_REGEX.match(plate))

def check_password_strength(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Add at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Add at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Add at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Add at least one special character."
    return True, "Strong."

def parse_date(date_str: str):
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").date()
    except:
        return None

def hash_password(password: str) -> str:
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed.decode()

def generate_driver_id():
    return f"{random.randint(100000, 999999)}"

# -----------------------------
# IMAGE RESIZE FUNCTION USING PILLOW
# -----------------------------
def resize_image(file: FileStorage, max_size=(1024, 1024)):
    try:
        # PIL works with file-like objects
        img = Image.open(file)
        img.thumbnail(max_size)
        buffer = BytesIO()
        img.save(buffer, format="JPEG", quality=85)
        buffer.seek(0)
        return buffer
    except Exception as e:
        raise ValueError(f"Image processing failed: {str(e)}")

# -----------------------------
# Heartbeat route (quick check)
# -----------------------------
@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "message": "drivers-backend running"}), 200

# ==========================================================# ROUTE: REGISTER NAME ONLY (TABLE: dere)
# 

@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json(force=True, silent=False) or {}
    except Exception as e:
        logger.exception("Failed to parse JSON body: %s", str(e))
        return jsonify({"success": False, "error": "Invalid JSON body"}), 400

    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    confirm = data.get("confirm") or ""

    # REQUIRED FIELDS
    if not name:
        return jsonify({"success": False, "error": "Name is required"}), 400
    if not email:
        return jsonify({"success": False, "error": "Email is required"}), 400

    # EMAIL REGEX
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"success": False, "error": "Invalid email address"}), 400

    if not password:
        return jsonify({"success": False, "error": "Password is required"}), 400
    if not confirm:
        return jsonify({"success": False, "error": "Confirm password is required"}), 400

    if password != confirm:
        return jsonify({"success": False, "error": "Passwords do not match"}), 400

    # PASSWORD STRENGTH
    ok, msg = check_password_strength(password)
    if not ok:
        return jsonify({"success": False, "error": msg}), 400

    # HASH
    try:
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    except Exception as e:
        logger.exception("Password hashing failed: %s", str(e))
        return jsonify({"success": False, "error": "Server error hashing password"}), 500

    # Check supabase init
    if supabase is None:
        return jsonify({"success": False, "error": "Database client missing"}), 500

    # INSERT INTO TABLE dere
    try:
        response = supabase.table("dere").insert({
            "full_name": name,
            "email": email,
            "password": hashed
        }).execute()

        # Check for error
        resp_error = getattr(response, "error", None)

        if resp_error:
            logger.error("Supabase insert error: %s", resp_error)
            return jsonify({"success": False, "error": "Database insert failed"}), 500

        return jsonify({
            "success": True,
            "message": "Registration successful. Check your email to continue."
        }), 200

    except Exception as e:
        logger.exception("Unexpected supabase insert error: %s", str(e))
        return jsonify({"success": False, "error": "Internal server error during registration"}), 500



# ============================================================
# ROUTE: SEND CONTINUE REGISTRATION EMAIL
# ============================================================
@app.route("/continue-reg", methods=["POST"])
def continue_reg():
    if supabase is None:
        return jsonify({"success": False, "error": "Database client missing"}), 500

    try:
        data = request.get_json(force=True, silent=False) or {}
    except:
        return jsonify({"success": False, "error": "Invalid JSON body"}), 400

    email = (data.get("email") or "").strip().lower()

    if not email:
        return jsonify({"success": False, "error": "Email is required"}), 400

    # FIND USER
    try:
        lookup = supabase.table("dere").select("*").eq("email", email).single().execute()
    except Exception:
        return jsonify({"success": False, "error": "Database lookup failed"}), 500

    if not lookup.data:
        return jsonify({"success": False, "error": "Email not found"}), 404

    # CREATE TOKEN
    token = str(random.randint(10000000, 99999999))

    # UPDATE USER WITH TOKEN
    try:
        supabase.table("dere").update({
            "continue_token": token
        }).eq("email", email).execute()
    except Exception:
        return jsonify({"success": False, "error": "Database update failed"}), 500

    # EMAIL CONTENT
    continue_url = f"https://drivers-backend-4spp.onrender.com/continue-form?token={token}"

    try:
        sg = sendgrid.SendGridAPIClient(api_key=os.getenv("SENDGRID_API_KEY"))
        message = Mail(
            from_email=os.getenv("FROM_EMAIL"),
            to_emails=email,
            subject="Continue Your Registration",
            html_content=f"""
                <p>Hello,</p>
                <p>Click the button below to continue your registration:</p>
                <a href="{continue_url}" 
                style="background:#1b8f2a;color:white;padding:12px 18px;text-decoration:none;border-radius:6px;">
                Continue Registration
                </a>
            """
        )
        sg.send(message)
    except Exception as e:
        logger.exception("Email sending failed: %s", str(e))
        return jsonify({"success": False, "error": "Failed to send email"}), 500

    return jsonify({
        "success": True,
        "message": "Email sent. Check your inbox to continue registration.",
        "token": token
    }), 200

# -----------------------------
# JSON error handlers to avoid HTML pages
# -----------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found", "path": request.path}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    try:
        allowed = list(request.url_rule.methods) if request.url_rule else None
    except Exception:
        allowed = None
    return jsonify({"error": "Method not allowed", "allowed": allowed}), 405

@app.errorhandler(413)
def payload_too_large(e):
    return jsonify({"error": "Payload too large"}), 413

@app.errorhandler(500)
def internal_error(e):
    # log server error
    logger.exception("Internal server error (global handler): %s", str(e))
    return jsonify({"error": "Internal server error"}), 500

# ============================================================
# RUN APP
# ============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
