import os
import re
import random
import bcrypt
import cloudinary
import cloudinary.uploader
from datetime import datetime, timedelta
from io import BytesIO
import logging

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.datastructures import FileStorage
from dotenv import load_dotenv

# supabase client (ensure package installed in your env)
from supabase import create_client, Client

# sendgrid
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

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

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# -----------------------------
# CLOUDINARY CONFIG
# -----------------------------
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET")
)

# -----------------------------
# SENDGRID CONFIG
# -----------------------------
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
EMAIL_FROM = os.getenv("EMAIL_FROM")

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
# - Accepts both "name" and "full_name" keys
# - URL path uses dash to match current frontend: /register-name
# ============================================================


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    name = data.get("name", "").strip()
    password = data.get("password", "")
    confirm = data.get("confirm", "")

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

    # Strong password validation
    if len(password) < 8:
        return jsonify({"success": False, "error": "Password must be at least 8 characters"}), 400
    if not re.search(r"[A-Z]", password):
        return jsonify({"success": False, "error": "Password must include an uppercase letter"}), 400
    if not re.search(r"[a-z]", password):
        return jsonify({"success": False, "error": "Password must include a lowercase letter"}), 400
    if not re.search(r"[0-9]", password):
        return jsonify({"success": False, "error": "Password must include a digit"}), 400
    if not re.search(r"[!@#$%^&*()_+\-=]", password):
        return jsonify({"success": False, "error": "Password must include a special character"}), 400

    # Everything OK → Hash password
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    # Insert into Supabase (or your database)
    supabase.table("dere").insert({
        "name": name,
        "password": hashed
    }).execute()

    return jsonify({
        "success": True,
        "message": "Partly registered successfully"
    }), 200

# -----------------------------
# JSON error handlers to avoid HTML pages
# -----------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found", "path": request.path}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed", "allowed": list(request.url_rule.methods) if request.url_rule else None}), 405

@app.errorhandler(413)
def payload_too_large(e):
    return jsonify({"error": "Payload too large"}), 413

@app.errorhandler(500)
def internal_error(e):
    # log server error
    logger.exception("Internal server error")
    return jsonify({"error": "Internal server error"}), 500

# ============================================================
# RUN APP
# ============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # set debug False on production
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
