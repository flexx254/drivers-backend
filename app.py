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

# ============================================================
# ROUTE: REGISTER NAME ONLY (TABLE: dere)
# ============================================================
@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json(force=True, silent=False) or {}
    except Exception as e:
        logger.exception("Failed to parse JSON body: %s", str(e))
        return jsonify({"success": False, "error": "Invalid JSON body"}), 400

    name = (data.get("name") or "").strip()
    password = data.get("password") or ""
    confirm = data.get("confirm") or ""

    # Check empty fields
    if not name:
        return jsonify({"success": False, "error": "Name is required"}), 400
    if not password:
        return jsonify({"success": False, "error": "Password is required"}), 400
    if not confirm:
        return jsonify({"success": False, "error": "Confirm password is required"}), 400

    # Confirm password
    if password != confirm:
        return jsonify({"success": False, "error": "Passwords do not match"}), 400

    # Strong password validation (same rules as frontend + lowercase)
    ok, msg = check_password_strength(password)
    if not ok:
        return jsonify({"success": False, "error": msg}), 400

    # Hash password
    try:
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    except Exception as e:
        logger.exception("Password hashing failed: %s", str(e))
        return jsonify({"success": False, "error": "Server error hashing password"}), 500

    # Ensure supabase client exists
    if supabase is None:
        logger.error("Supabase client is not initialized.")
        return jsonify({"success": False, "error": "Server misconfiguration: database client missing"}), 500

    # Insert into Supabase (or your database) with error checks
    try:
        response = supabase.table("dere").insert({
            "full_name": name,
            "password": hashed
        }).execute()

        # response format may vary; try to detect error
        # new supabase-py returns dict-like with 'data' and 'error'
        resp_error = None
        resp_data = None
        try:
            # if response is object with .error/.data
            resp_error = getattr(response, "error", None)
            resp_data = getattr(response, "data", None)
        except Exception:
            pass
        # If it's a dict
        if isinstance(response, dict):
            resp_error = response.get("error") or resp_error
            resp_data = response.get("data") or resp_data

        # If there's an error, log and return it
        if resp_error:
            logger.error("Supabase insert error: %s", resp_error)
            # avoid leaking internal DB details to client, but pass concise message
            return jsonify({"success": False, "error": "Database insert failed"}), 500

        # Good insertion
        logger.info("Inserted into dere table for name=%s", name)
        return jsonify({"success": True, "message": "Partly registered successfully"}), 200

    except Exception as e:
        # Log full exception for Render logs
        logger.exception("Unexpected error during supabase insert: %s", str(e))
        # Helpful JSON to frontend (do not include stack traces)
        return jsonify({"success": False, "error": "Internal server error during registration"}), 500

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
