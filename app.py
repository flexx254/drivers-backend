import os
import re
import random
import bcrypt
import cloudinary
import cloudinary.uploader
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
KENYA_TZ = ZoneInfo("Africa/Nairobi")
from io import BytesIO
import logging
import json
import threading
import time


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
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)

# -----------------------------
# LOAD ENV
# -----------------------------
load_dotenv()


# ---------- logging ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from mailjet_rest import Client

mailjet = Client(
    auth=(
        os.getenv("MAILJET_API_KEY"),
        os.getenv("MAILJET_SECRET_KEY")
    ),
    version="v3.1"
)

def send_mailjet_html(to_email: str, subject: str, html: str) -> bool:
    try:
        sender_email = os.getenv("MAILJET_SENDER_EMAIL")
        sender_name = os.getenv("MAILJET_SENDER_NAME", "Strategic Drivers")

        if not sender_email:
            raise RuntimeError("Mailjet sender email missing")

        data = {
            "Messages": [
                {
                    "From": {
                        "Email": sender_email,
                        "Name": sender_name
                    },
                    "To": [
                        {
                            "Email": to_email
                        }
                    ],
                    "Subject": subject,
                    "HTMLPart": html
                }
            ]
        }

        result = mailjet.send.create(data=data)

        if result.status_code not in (200, 201):
            logger.error("Mailjet send failed: %s", result.json())
            return False

        return True

    except Exception as e:
        logger.exception("Mailjet send error: %s", str(e))
        return False


# ----------------------------
# HELPER: Validate date format
# ----------------------------
def validate_date(date_str):
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
        return True
    except (ValueError, TypeError):
        return False



def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Empty password cannot be hashed")

    hashed = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )
    return hashed.decode("utf-8")

app = Flask(__name__)
# -----------------------------
# JWT CONFIGURATION
# -----------------------------
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=12)

if not app.config["JWT_SECRET_KEY"]:
    raise RuntimeError("JWT_SECRET_KEY missing from environment variables")

jwt = JWTManager(app)

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

def normalize_phone(number: str) -> str:
    """Convert MPESA phone formats to standard 2547xxxxxxx."""
    number = number.strip().replace(" ", "").replace("+", "")
    if number.startswith("0") and len(number) == 10:
        return "254" + number[1:]
    elif number.startswith("7") and len(number) == 9:
        return "254" + number
    elif number.startswith("254") and len(number) == 12:
        return number
    return number

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

    # FIELDS
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    phone = (data.get("phone_number") or "").strip()
    sacco = (data.get("sacco") or "").strip()
    password = data.get("password") or ""
    confirm = data.get("confirm") or ""

    # REQUIRED FIELDS
    if not name:
        return jsonify({"success": False, "error": "Name is required"}), 400
    if not email:
        return jsonify({"success": False, "error": "Email is required"}), 400
    if not phone:
        return jsonify({"success": False, "error": "Phone number is required"}), 400
    if not sacco:
        return jsonify({"success": False, "error": "Sacco is required"}), 400

    # EMAIL FORMAT
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"success": False, "error": "Invalid email address"}), 400

    # PHONE NUMBER FORMAT (+254XXXXXXXXX)
    if not re.match(r"^\+254\d{9}$", phone):
        return jsonify({"success": False, "error": "Phone must be in +254XXXXXXXXX format"}), 400

    # PASSWORD VALIDATION
    if not password:
        return jsonify({"success": False, "error": "Password is required"}), 400
    if not confirm:
        return jsonify({"success": False, "error": "Confirm password is required"}), 400
    if password != confirm:
        return jsonify({"success": False, "error": "Passwords do not match"}), 400

    ok, msg = check_password_strength(password)
    if not ok:
        return jsonify({"success": False, "error": msg}), 400

    # HASH PASSWORD
    try:
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    except Exception as e:
        logger.exception("Password hashing failed: %s", str(e))
        return jsonify({"success": False, "error": "Server error hashing password"}), 500

    # DB CLIENT CHECK
    if supabase is None:
        return jsonify({"success": False, "error": "Database client missing"}), 500

    # INSERT INTO dere
    try:
        response = supabase.table("dere").insert({
            "full_name": name,
            "email": email,
            "password": hashed,
            "phone_number": phone,
            "sacco": sacco
        }).execute()

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
    except Exception:
        return jsonify({"success": False, "error": "Invalid JSON body"}), 400

    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"success": False, "error": "Email is required"}), 400

    # 1️⃣ FIND USER
    try:
        lookup = (
            supabase
            .table("dere")
            .select("email")
            .eq("email", email)
            .single()
            .execute()
        )
    except Exception:
        return jsonify({"success": False, "error": "Database lookup failed"}), 500

    if not lookup.data:
        return jsonify({"success": False, "error": "Email not found"}), 404

    # 2️⃣ CREATE TOKEN
    token = f"{random.randint(10000000, 99999999)}"

    # 3️⃣ SAVE TOKEN
    try:
        supabase.table("dere").update({
            "continue_token": token
        }).eq("email", email).execute()
    except Exception:
        return jsonify({"success": False, "error": "Database update failed"}), 500

    # 4️⃣ EMAIL CONTENT
    continue_url = (
        "https://flexx254.github.io/drivers-frontend/"
        f"continue-form.html?token={token}"
    )

    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto">
        <h2 style="color:#1b8f2a">Continue Registration</h2>
        <p>Hello,</p>
        <p>Click the button below to continue your registration:</p>

        <p style="text-align:center;margin:30px 0">
            <a href="{continue_url}"
               style="background:#1b8f2a;color:#fff;padding:14px 22px;
               text-decoration:none;border-radius:6px;display:inline-block">
               Continue Registration
            </a>
        </p>

        <p style="font-size:12px;color:#666">
            If you did not request this, please ignore this email.
        </p>
    </div>
    """

    # 5️⃣ SEND EMAIL (GMAIL SMTP)
    sent = send_mailjet_html(
        email,
        "Continue Your Registration",
        html
    )

    if not sent:
        return jsonify({"success": False, "error": "Failed to send email"}), 500

    # 6️⃣ SUCCESS
    return jsonify({
        "success": True,
        "message": "Email sent. Check your inbox to continue registration.",
        "token": token
    }), 200







@app.route("/upload-documents", methods=["POST"])
@jwt_required()  # require JWT authentication
def upload_documents():
    try:
        # -----------------------------
        # 1. Get current user from JWT
        # -----------------------------
        email = get_jwt_identity()
        if not email:
            return jsonify({"success": False, "error": "Unauthorized"}), 401

        # -----------------------------
        # 2. Get form fields
        # -----------------------------
        id_number = request.form.get("id_number")
        license_exp = request.form.get("license_expiry")
        psv_exp = request.form.get("psv_badge_expiry")
        gc_exp = request.form.get("good_conduct_expiry")

        # -----------------------------
        # 3. Get uploaded files
        # -----------------------------
        profile_file = request.files.get("profile_pic")
        license_file = request.files.get("license")
        psv_file = request.files.get("psv_badge")
        good_conduct_file = request.files.get("good_conduct")

        # -----------------------------
        # 4. Helper: upload & resize
        # -----------------------------
        def process_file(file, folder):
            if not file:
                return None
            if not allowed_file(file):
                raise ValueError(f"Invalid file format for {file.filename}. Allowed: JPG/PNG")
            resized = resize_image(file)
            uploaded = cloudinary.uploader.upload(resized, folder=folder)
            return uploaded.get("secure_url")

        # -----------------------------
        # 5. Upload files
        # -----------------------------
        profile_url = process_file(profile_file, "driver_profile") if profile_file else None
        license_url = process_file(license_file, "driver_docs") if license_file else None
        psv_url = process_file(psv_file, "driver_docs") if psv_file else None
        gc_url = process_file(good_conduct_file, "driver_docs") if good_conduct_file else None

        # -----------------------------
        # 6. Build update data
        # -----------------------------
        update_data = {}
        if id_number: update_data["id_number"] = id_number
        if license_exp: update_data["license_expiry"] = license_exp
        if psv_exp: update_data["psv_badge_expiry"] = psv_exp
        if gc_exp: update_data["good_conduct_expiry"] = gc_exp
        if profile_url: update_data["profile_pic_url"] = profile_url
        if license_url: update_data["license_url"] = license_url
        if psv_url: update_data["psv_badge_url"] = psv_url
        if gc_url: update_data["good_conduct_url"] = gc_url

        if not update_data:
            return jsonify({"success": False, "error": "No data or files to update"}), 400

        # -----------------------------
        # 7. Save to database
        # -----------------------------
        response = supabase.table("dere").update(update_data).eq("email", email).execute()
        if getattr(response, "error", None):
            return jsonify({"success": False, "error": str(response.error)}), 500

        return jsonify({
            "success": True,
            "message": "Documents uploaded successfully.",
            "updated_fields": list(update_data.keys())
        }), 200

    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400
    except Exception as e:
        logger.exception("Document upload error: %s", str(e))
        return jsonify({"success": False, "error": "Server error"}), 500


# ============================================================
# ROUTE: UPDATE ID NUMBER ONLY (JWT SECURE)
# ============================================================


@app.route("/update-id", methods=["POST"])
@jwt_required()
def update_id():
    try:
        # -----------------------------
        # 1. Get email from JWT
        # -----------------------------
        email = get_jwt_identity()
        if not email:
            return jsonify({"success": False, "error": "Unauthorized"}), 401

        # -----------------------------
        # 2. Get ID number from request
        # -----------------------------
        id_number = request.form.get("id_number", "").strip()
        if not id_number:
            return jsonify({"success": False, "error": "ID number is required"}), 400

        print("Updating ID for:", email, "New ID:", id_number)

        # -----------------------------
        # 3. Update Supabase
        # -----------------------------
        update_resp = supabase.table("dere").update({
            "id_number": id_number
        }).eq("email", email).execute()

        print("Supabase update response:", update_resp)

        if getattr(update_resp, "error", None):
            return jsonify({"success": False, "error": str(update_resp.error)}), 500

        # -----------------------------
        # 4. Success response
        # -----------------------------
        return jsonify({
            "success": True,
            "message": "ID number saved successfully."
        }), 200

    except Exception as e:
        logger.exception("ID update error: %s", str(e))
        return jsonify({"success": False, "error": str(e)}), 500

    

# ============================================================
# ROUTE: UPDATE DRIVING LICENSE (JWT SECURE)
# ============================================================
@app.route("/update-driving-license", methods=["POST"])
@jwt_required()
def update_driving_license():
    try:
        # -----------------------------
        # 1. Get email from JWT
        # -----------------------------
        email = get_jwt_identity()
        if not email:
            return jsonify({"success": False, "error": "Unauthorized"}), 401

        # -----------------------------
        # 2. Get form data
        # -----------------------------
        license_expiry = request.form.get("license_expiry", "").strip()
        file = request.files.get("license")

        if not file:
            return jsonify({"success": False, "error": "No file uploaded"}), 400

        if not allowed_file(file):
            return jsonify({"success": False, "error": "Invalid file format. Use JPG or PNG"}), 400

        # -----------------------------
        # 3. Resize & upload
        # -----------------------------
        try:
            resized_buffer = resize_image(file)
            upload_resp = cloudinary.uploader.upload(
                resized_buffer,
                folder="driver_docs"
            )
            license_url = upload_resp.get("secure_url")
        except Exception as e:
            logger.exception("Driving license upload error: %s", e)
            return jsonify({"success": False, "error": "File upload failed"}), 500

        if not license_url:
            return jsonify({"success": False, "error": "Cloudinary did not return a URL"}), 500

        # -----------------------------
        # 4. Save to Supabase
        # -----------------------------
        update_data = {
            "license_url": license_url
        }

        if license_expiry:
            update_data["license_expiry"] = license_expiry

        update_resp = supabase.table("dere")\
            .update(update_data)\
            .eq("email", email)\
            .execute()

        if getattr(update_resp, "error", None):
            return jsonify({"success": False, "error": "Database update failed"}), 500

        # -----------------------------
        # 5. SUCCESS
        # -----------------------------
        return jsonify({
            "success": True,
            "license_url": license_url,
            "message": "Driving license uploaded successfully."
        }), 200

    except Exception as e:
        logger.exception("Driving license update error: %s", str(e))
        return jsonify({"success": False, "error": "Server error"}), 500

# ============================================================
# ROUTE: UPDATE NUMBER PLATE (JWT SECURE)
# ============================================================
@app.route("/update-number-plate", methods=["POST"])
@jwt_required()
def update_number_plate():
    try:
        # -----------------------------
        # 1. Get email from JWT
        # -----------------------------
        email = get_jwt_identity()
        if not email:
            return jsonify({"success": False, "error": "Unauthorized"}), 401

        # -----------------------------
        # 2. Get number plate from request
        # -----------------------------
        plate = request.form.get("number_plate", "").strip()
        if not plate:
            return jsonify({"success": False, "error": "Number plate is required"}), 400

        # Normalize and validate
        normalized = normalize_plate(plate)
        if not valid_plate(normalized):
            return jsonify({"success": False, "error": "Invalid number plate format"}), 400

        # -----------------------------
        # 3. Check for duplicate number plate (exclude this user)
        # -----------------------------
        duplicate = supabase.table("dere")\
            .select("*")\
            .eq("number_plate", normalized)\
            .neq("email", email)\
            .execute()

        if duplicate.data:
            return jsonify({"success": False, "error": "Number plate already exists"}), 400

        # -----------------------------
        # 4. Update number plate
        # -----------------------------
        update_resp = supabase.table("dere")\
            .update({"number_plate": normalized})\
            .eq("email", email)\
            .execute()

        if getattr(update_resp, "error", None):
            return jsonify({"success": False, "error": str(update_resp.error)}), 500

        return jsonify({
            "success": True,
            "number_plate": normalized
        }), 200

    except Exception as e:
        logger.exception("Number plate update error: %s", e)
        return jsonify({"success": False, "error": "Server error"}), 500




# ============================================================
# ROUTE: UPDATE PROFILE PICTURE (JWT SECURE)
# ============================================================
@app.route("/update-profile-picture", methods=["POST"])
@jwt_required()
def update_profile_picture():
    try:
        # -----------------------------
        # 1. Get email from JWT
        # -----------------------------
        email = get_jwt_identity()
        if not email:
            return jsonify({"success": False, "error": "Unauthorized"}), 401

        # -----------------------------
        # 2. Get uploaded file
        # -----------------------------
        file = request.files.get("profile_picture")
        if not file:
            return jsonify({"success": False, "error": "No image uploaded"}), 400

        # Validate file
        if not allowed_file(file):
            return jsonify({"success": False, "error": "Invalid image format. Use JPG or PNG."}), 400

        # -----------------------------
        # 3. Resize image using Pillow
        # -----------------------------
        try:
            resized_buffer = resize_image(file)
        except Exception as e:
            return jsonify({"success": False, "error": f"Image processing failed: {str(e)}"}), 500

        # -----------------------------
        # 4. Upload to Cloudinary
        # -----------------------------
        try:
            upload_resp = cloudinary.uploader.upload(
                resized_buffer,
                folder="driver_profile"
            )
            image_url = upload_resp.get("secure_url")
        except Exception as e:
            logger.exception("Cloudinary upload error: %s", str(e))
            return jsonify({"success": False, "error": "Failed to upload image"}), 500

        if not image_url:
            return jsonify({"success": False, "error": "Cloudinary did not return a URL"}), 500

        # -----------------------------
        # 5. Save URL to Supabase
        # -----------------------------
        update_resp = supabase.table("dere")\
            .update({"profile_pic_url": image_url})\
            .eq("email", email)\
            .execute()

        if getattr(update_resp, "error", None):
            return jsonify({"success": False, "error": "Database update failed"}), 500

        # -----------------------------
        # 6. SUCCESS
        # -----------------------------
        return jsonify({
            "success": True,
            "profile_pic_url": image_url,
            "message": "Profile picture uploaded successfully."
        }), 200

    except Exception as e:
        logger.exception("Profile picture update error: %s", str(e))
        return jsonify({"success": False, "error": "Server error"}), 500




# ============================================================
# ROUTE: UPDATE PSV BADGE (JWT SECURE)
# ============================================================
@app.route("/update-psv-badge", methods=["POST"])
@jwt_required()
def update_psv_badge():
    try:
        # -----------------------------
        # 1. Get user email from JWT
        # -----------------------------
        email = get_jwt_identity()
        if not email:
            return jsonify({"success": False, "error": "Unauthorized"}), 401

        # -----------------------------
        # 2. Get file and expiry date
        # -----------------------------
        file = request.files.get("psv_badge")
        psv_expiry = request.form.get("psv_badge_expiry", "").strip()

        if not file:
            return jsonify({"success": False, "error": "No file uploaded"}), 400

        if not allowed_file(file):
            return jsonify({"success": False, "error": "Invalid file format. Use JPG or PNG"}), 400

        # -----------------------------
        # 3. Resize & upload
        # -----------------------------
        try:
            resized_buffer = resize_image(file)
            upload_resp = cloudinary.uploader.upload(resized_buffer, folder="driver_docs")
            psv_url = upload_resp.get("secure_url")
        except Exception as e:
            logger.exception("PSV badge processing/upload error: %s", e)
            return jsonify({"success": False, "error": "File upload failed"}), 500

        if not psv_url:
            return jsonify({"success": False, "error": "Cloudinary did not return a URL"}), 500

        # -----------------------------
        # 4. Save to Supabase
        # -----------------------------
        update_resp = supabase.table("dere").update({
            "psv_badge_url": psv_url,
            "psv_badge_expiry": psv_expiry
        }).eq("email", email).execute()

        if getattr(update_resp, "error", None):
            return jsonify({"success": False, "error": "Database update failed"}), 500

        # -----------------------------
        # 5. SUCCESS
        # -----------------------------
        return jsonify({
            "success": True,
            "psv_badge_url": psv_url,
            "message": "PSV badge uploaded successfully."
        }), 200

    except Exception as e:
        logger.exception("PSV badge upload error: %s", e)
        return jsonify({"success": False, "error": "Server error"}), 500




# ============================================================
# ROUTE: UPDATE GOOD CONDUCT CERTIFICATE (JWT SECURE)
# ============================================================
@app.route("/update-good-conduct", methods=["POST"])
@jwt_required()
def update_good_conduct():
    try:
        # -----------------------------
        # 1. Get user email from JWT
        # -----------------------------
        email = get_jwt_identity()
        if not email:
            return jsonify({"success": False, "error": "Unauthorized"}), 401

        # -----------------------------
        # 2. Get file and expiry date
        # -----------------------------
        file = request.files.get("good_conduct")
        gc_expiry = request.form.get("good_conduct_expiry", "").strip()

        if not file:
            return jsonify({"success": False, "error": "No file uploaded"}), 400

        if not allowed_file(file):
            return jsonify({"success": False, "error": "Invalid file format. Use JPG or PNG"}), 400

        # -----------------------------
        # 3. Resize & upload
        # -----------------------------
        try:
            resized_buffer = resize_image(file)
            upload_resp = cloudinary.uploader.upload(resized_buffer, folder="driver_docs")
            gc_url = upload_resp.get("secure_url")
        except Exception as e:
            logger.exception("Good conduct processing/upload error: %s", e)
            return jsonify({"success": False, "error": "File upload failed"}), 500

        if not gc_url:
            return jsonify({"success": False, "error": "Cloudinary did not return a URL"}), 500

        # -----------------------------
        # 4. Save to Supabase
        # -----------------------------
        update_resp = supabase.table("dere").update({
            "good_conduct_url": gc_url,
            "good_conduct_expiry": gc_expiry
        }).eq("email", email).execute()

        if getattr(update_resp, "error", None):
            return jsonify({"success": False, "error": "Database update failed"}), 500

        # -----------------------------
        # 5. SUCCESS
        # -----------------------------
        return jsonify({
            "success": True,
            "good_conduct_url": gc_url,
            "message": "Good conduct certificate uploaded successfully."
        }), 200

    except Exception as e:
        logger.exception("Good conduct upload error: %s", e)
        return jsonify({"success": False, "error": "Server error"}), 500


@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json(force=True, silent=False) or {}
    except Exception as e:
        logger.exception("Failed to parse JSON body: %s", str(e))
        return jsonify({"success": False, "error": "Invalid JSON body"}), 400

    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email:
        return jsonify({"success": False, "error": "Email is required"}), 400
    if not password:
        return jsonify({"success": False, "error": "Password is required"}), 400

    if supabase is None:
        return jsonify({"success": False, "error": "Database client missing"}), 500

    # Fetch user
    try:
        response = (
            supabase
            .table("dere")
            .select("*")
            .eq("email", email)
            .single()
            .execute()
        )
        user = response.data
    except Exception as e:
        logger.exception("Supabase lookup error: %s", str(e))
        return jsonify({"success": False, "error": "Database lookup failed"}), 500

    if not user:
        return jsonify({"success": False, "error": "Email not found"}), 404

    hashed = user.get("password")
    if not hashed:
        return jsonify({"success": False, "error": "User password not set"}), 500

    # Check password
    try:
        if not bcrypt.checkpw(password.encode(), hashed.encode()):
            return jsonify({"success": False, "error": "Incorrect password"}), 401
    except Exception as e:
        logger.exception("Password check error: %s", str(e))
        return jsonify({"success": False, "error": "Password verification failed"}), 500

    # 🔥 CREATE REAL JWT TOKEN
    access_token = create_access_token(identity=email)

    return jsonify({
        "success": True,
        "access_token": access_token,
        "message": "Login successful"
    }), 200


@app.route("/search-driver", methods=["GET"])
def search_driver():
    try:
        plate = (request.args.get("number_plate") or "").strip().upper().replace(" ", "")
        if not plate:
            return jsonify({"success": False, "error": "Number plate is required"}), 400

        # Lookup in Supabase
        lookup = supabase.table("dere")\
            .select("full_name, profile_pic_url, number_plate")\
            .eq("number_plate", plate)\
            .single()\
            .execute()

        if not lookup.data:
            return jsonify({"success": False, "error": "Driver not found"}), 404

        return jsonify({"success": True, "driver": lookup.data}), 200

    except Exception as e:
        logger.exception("Search driver error: %s", str(e))
        return jsonify({"success": False, "error": "Server error"}), 500




@app.route("/update-phone-number", methods=["POST"])
def update_phone_number():
    try:
        token = request.form.get("token", "").strip()
        phone = request.form.get("phone_number", "").strip()

        if not token:
            return jsonify({"success": False, "error": "Missing token"}), 400
        if not phone:
            return jsonify({"success": False, "error": "Phone number is required"}), 400

        # Update in Supabase
        update = supabase.table("dere") \
            .update({"phone_number": phone}) \
            .eq("token", token) \
            .execute()

        if not update.data:
            return jsonify({"success": False, "error": "Driver not found"}), 404

        return jsonify({"success": True, "message": "Phone number updated successfully"}), 200

    except Exception as e:
        logger.exception("Phone number update error: %s", str(e))
        return jsonify({"success": False, "error": "Server error"}), 500                   



@app.route("/update-sacco", methods=["POST"])
def update_sacco():
    try:
        token = request.form.get("token", "").strip()
        sacco = request.form.get("sacco", "").strip()

        if not token:
            return jsonify({"success": False, "error": "Missing token"}), 400
        if not sacco:
            return jsonify({"success": False, "error": "Sacco name is required"}), 400

        # Update in Supabase
        update = supabase.table("dere") \
            .update({"sacco": sacco}) \
            .eq("token", token) \
            .execute()

        if not update.data:
            return jsonify({"success": False, "error": "Driver not found"}), 404

        return jsonify({"success": True, "message": "Sacco updated successfully"}), 200

    except Exception as e:
        logger.exception("Sacco update error: %s", str(e))
        return jsonify({"success": False, "error": "Server error"}), 500



 
        



@app.route("/register-owner", methods=["POST"])
def register_owner():
    try:
        # -----------------------------
        # 1. Read inputs ONCE
        # -----------------------------
        form = request.form
        files = request.files

        plate = (form.get("number_plate") or "").strip()
        car_make = (form.get("car_make") or "").strip()
        car_model = (form.get("car_model") or "").strip()

        car_image = files.get("car_image")
        logbook = files.get("logbook")
        inspection = files.get("inspection_report")
        uber_report = files.get("uber_report")

        # -----------------------------
        # 2. Required field validation
        # -----------------------------
        if not plate:
            return jsonify({"success": False, "error": "Number plate is required"}), 400

        if not car_make or not car_model:
            return jsonify({"success": False, "error": "Car make and model are required"}), 400

        if not car_image or not logbook or not inspection:
            return jsonify({"success": False, "error": "Missing required documents"}), 400

        # -----------------------------
        # 3. Plate validation
        # -----------------------------
        normalized_plate = normalize_plate(plate)
        if not valid_plate(normalized_plate):
            return jsonify({"success": False, "error": "Invalid number plate"}), 400

        # -----------------------------
        # 4. Upload helper
        # -----------------------------
        def upload_doc(file, folder):
            if not allowed_file(file):
                raise ValueError("Invalid file format")

            image = Image.open(file)
            if image.mode in ("RGBA", "P"):
                image = image.convert("RGB")

            image.thumbnail((1200, 1200))
            buffer = BytesIO()
            image.save(buffer, format="JPEG", quality=85)
            buffer.seek(0)

            result = cloudinary.uploader.upload(
                buffer,
                folder=folder,
                resource_type="image"
            )
            return result.get("secure_url")

        car_image_url = upload_doc(car_image, "owner/car")
        logbook_url = upload_doc(logbook, "owner/logbook")
        inspection_url = upload_doc(inspection, "owner/inspection")
        uber_url = upload_doc(uber_report, "owner/uber") if uber_report else None

        # -----------------------------
        # 5. Build INSERT payload
        # -----------------------------
        payload = {
            "number_plate": normalized_plate,
            "car_make": car_make,
            "car_model": car_model,
            "car_image_url": car_image_url,
            "logbook_url": logbook_url,
            "inspection_report_url": inspection_url,
            "uber_report_url": uber_url
        }

        logger.info("INSERT PAYLOAD KEYS: %s", list(payload.keys()))

        # -----------------------------
        # 6. Insert into Supabase
        # -----------------------------
        response = supabase.table("owner").insert(payload).execute()

        if getattr(response, "error", None):
            logger.error("Supabase insert error: %s", response.error)
            return jsonify({"success": False, "error": "Database insert failed"}), 500

        if not response.data:
            return jsonify({"success": False, "error": "Insert returned no data"}), 500

        return jsonify({
            "success": True,
            "message": "Car owner registered successfully"
        }), 200

    except ValueError as ve:
        return jsonify({"success": False, "error": str(ve)}), 400

    except Exception as e:
        logger.exception("Owner registration error: %s", e)
        return jsonify({"success": False, "error": "Server error"}), 500



@app.route("/partner-reg", methods=["POST"])
def partner_reg():
    try:
        data = request.get_json(force=True, silent=False) or {}
    except Exception as e:
        logger.exception("Failed to parse JSON body: %s", str(e))
        return jsonify({"success": False, "error": "Invalid JSON body"}), 400

    # -----------------------------
    # FIELDS
    # -----------------------------
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    phone = (data.get("phone_number") or "").strip()
    password = data.get("password") or ""
    confirm = data.get("confirm") or ""

    # -----------------------------
    # REQUIRED FIELDS
    # -----------------------------
    if not name:
        return jsonify({"success": False, "error": "Name is required"}), 400

    if not email:
        return jsonify({"success": False, "error": "Email is required"}), 400

    if not phone:
        return jsonify({"success": False, "error": "Phone number is required"}), 400

    # -----------------------------
    # EMAIL FORMAT
    # -----------------------------
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return jsonify({"success": False, "error": "Invalid email address"}), 400

    # -----------------------------
    # PHONE FORMAT (+254XXXXXXXXX)
    # -----------------------------
    if not re.match(r"^\+254\d{9}$", phone):
        return jsonify(
            {"success": False, "error": "Phone must be in +254XXXXXXXXX format"}), 400

    # -----------------------------
    # PASSWORD VALIDATION
    # -----------------------------
    if not password:
        return jsonify({"success": False, "error": "Password is required"}), 400

    if not confirm:
        return jsonify({"success": False, "error": "Confirm password is required"}), 400

    if password != confirm:
        return jsonify({"success": False, "error": "Passwords do not match"}), 400

    ok, msg = check_password_strength(password)
    if not ok:
        return jsonify({"success": False, "error": msg}), 400

    # -----------------------------
    # HASH PASSWORD
    # -----------------------------
    try:
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    except Exception as e:
        logger.exception("Password hashing failed: %s", str(e))
        return jsonify({"success": False, "error": "Server error hashing password"}), 500

    # -----------------------------
    # DB CLIENT CHECK
    # -----------------------------
    if supabase is None:
        return jsonify({"success": False, "error": "Database client missing"}), 500

    # -----------------------------
    # INSERT INTO partners table
    # -----------------------------
    try:
        response = supabase.table("partner").insert({
            "full_name": name,
            "email": email,
            "password_hash": hashed,
            "phone_number": phone
        }).execute()

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
        return jsonify(
            {"success": False, "error": "Internal server error during registration"}), 500

@app.route("/available-cars", methods=["GET"])
def available_cars():
    try:
        # Fetch all cars from Supabase
        response = supabase.table("owner").select(
            "car_image_url, car_make, car_model, number_plate"
        ).execute()

        if getattr(response, "error", None):
            return jsonify({"success": False, "error": "Failed to fetch cars"}), 500

        cars = response.data  # This is a list of dictionaries

        return jsonify({
            "success": True,
            "cars": cars
        }), 200

    except Exception as e:
        logger.exception("Fetching available cars error: %s", str(e))
        return jsonify({"success": False, "error": "Server error"}), 500


@app.route("/connect-owner", methods=["POST"])
def connect_owner():
    try:
        data = request.get_json()

        number_plate = (data.get("number_plate") or "").strip()
        location = (data.get("location") or "").strip()

        if not number_plate or not location:
            return jsonify({
                "success": False,
                "error": "Number plate and location are required"
            }), 400

        # Insert into dere table
        result = supabase.table("dere").insert({
            "number_plate": number_plate,
            "location": location
        }).execute()

        return jsonify({
            "success": True,
            "message": "Connection request saved"
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route("/update-location", methods=["POST", "OPTIONS"])
def update_location():

    # --- CORS preflight ---
    if request.method == "OPTIONS":
        return jsonify(success=True), 200

    if supabase is None:
        return jsonify({
            "success": False,
            "error": "Database client missing"
        }), 500

    try:
        data = request.get_json(force=True) or {}

        # Validate ID
        try:
            record_id = int(data.get("id"))
        except (TypeError, ValueError):
            return jsonify({
                "success": False,
                "error": "ID must be a number"
            }), 400

        location = (data.get("location") or "").strip()

        if not location:
            return jsonify({
                "success": False,
                "error": "Location is required"
            }), 400

        # 1️⃣ Check ID exists
        lookup = (
            supabase
            .table("dere")
            .select("id")
            .eq("id", record_id)
            .execute()
        )

        if not lookup.data:
            return jsonify({
                "success": False,
                "error": "ID not found"
            }), 404

        # 2️⃣ Update location
        update_resp = (
            supabase
            .table("dere")
            .update({"location": location})
            .eq("id", record_id)
            .execute()
        )

        if getattr(update_resp, "error", None):
            return jsonify({
                "success": False,
                "error": "Failed to update location"
            }), 500

        return jsonify({
            "success": True,
            "message": "Location updated successfully",
            "id": record_id,
            "location": location
        }), 200

    except Exception as e:
        logger.exception("Update location error: %s", str(e))
        return jsonify({
            "success": False,
            "error": "Server error"
        }), 500


# ============================================================
# ROUTE: GET OWNERS WITH LOCATION (OWNER DASHBOARD)
# ============================================================
@app.route("/owners-with-location", methods=["GET"])
@limiter.limit("20 per minute")
def owners_with_location():
    if supabase is None:
        return jsonify({
            "success": False,
            "error": "Database client missing"
        }), 500

    try:
        response = (
            supabase
            .table("dere")
            .select("id, full_name, profile_pic_url, location")
            .not_.is_("location", "null")
            .execute()
        )

        if getattr(response, "error", None):
            logger.error("Supabase fetch error: %s", response.error)
            return jsonify({
                "success": False,
                "error": "Failed to fetch owners"
            }), 500

        owners = [
            row for row in response.data
            if row.get("location") and row["location"].strip()
        ]

        return jsonify(owners), 200

    except Exception as e:
        logger.exception("owners-with-location error: %s", str(e))
        return jsonify({
            "success": False,
            "error": "Server error"
        }), 500


# ============================================================
# ROUTE: CONNECT OWNER (SECURE, RENAMED)
# ============================================================
@app.route("/connect-owner-secure", methods=["POST"])
@limiter.limit("5 per minute")
def connect_owner_secure():
    if supabase is None:
        return jsonify({
            "success": False,
            "error": "Database client missing"
        }), 500

    try:
        data = request.get_json(force=True) or {}
        owner_id = data.get("owner_id")

        # Validate owner_id
        try:
            owner_id = int(owner_id)
        except (TypeError, ValueError):
            return jsonify({
                "success": False,
                "error": "Invalid owner ID"
            }), 400

        # Fetch owner safely
        lookup = (
            supabase
            .table("dere")
            .select("phone_number, location")
            .eq("id", owner_id)
            .single()
            .execute()
        )

        if not lookup.data:
            return jsonify({
                "success": False,
                "error": "Owner not found"
            }), 404

        # SECURITY: location must exist
        if not lookup.data.get("location"):
            return jsonify({
                "success": False,
                "error": "Owner location not set"
            }), 403

        phone = lookup.data.get("phone_number")
        if not phone:
            return jsonify({
                "success": False,
                "error": "Phone number unavailable"
            }), 404

        return jsonify({
            "success": True,
            "phone_number": phone
        }), 200

    except Exception as e:
        logger.exception("connect-owner-secure error: %s", str(e))
        return jsonify({
            "success": False,
            "error": "Server error"
        }), 500



@app.route('/payment', methods=['POST'])
def receive_payment_sms():
    try:
        data = request.get_json()
        sms_text = data.get("message")

        if not sms_text:
            return jsonify({"error": "No SMS message provided"}), 400

        # 1️⃣ Extract the code from the start of the SMS
        code_match = re.match(r'^([A-Z0-9]+)', sms_text)
        code = code_match.group(1) if code_match else None

        # 2️⃣ Extract amount after "Ksh"
        amount_match = re.search(r'Ksh\s*([\d,]+(?:\.\d{2})?)', sms_text)
        amount = amount_match.group(1) if amount_match else None

        # 3️⃣ Extract sender names after "from"
        name_match = re.search(
            r'from\s+(?:[A-Z\s]+-\s*)?([A-Za-z]+(?:\s+[A-Za-z]+)+)(?=\s+\d|\s+has|\s+on|\.)',
            sms_text
        )
        names = name_match.group(1).strip() if name_match else None

        # 4️⃣ Extract phone number (masked or full)
        phone_match = re.search(r'\b(\d{6,10}\*{0,4})\b', sms_text)
        phone = phone_match.group(1) if phone_match else None

        # 5️⃣ Normalize phone number (Kenya)
        normalized_phone = phone
        if phone and '*' not in phone:
            if phone.startswith('07') and len(phone) == 10:
                normalized_phone = '+254' + phone[1:]
            elif len(phone) == 9:
                normalized_phone = '+254' + phone
            elif phone.startswith('254'):
                normalized_phone = '+' + phone
            elif phone.startswith('+254'):
                normalized_phone = phone

        # 6️⃣ Extract payment date/time (Kenya time)
        paid_at_match = re.search(
            r'on\s+(\d{1,2}/\d{1,2}/\d{2,4}(?:\s+\d{1,2}:\d{2})?)',
            sms_text
        )

        if paid_at_match:
            paid_at_str = paid_at_match.group(1)
            try:
                paid_at = datetime.strptime(paid_at_str, '%d/%m/%y %H:%M')
            except ValueError:
                try:
                    paid_at = datetime.strptime(paid_at_str, '%d/%m/%y')
                except ValueError:
                    paid_at = datetime.now(KENYA_TZ)
            paid_at = paid_at.replace(tzinfo=KENYA_TZ)
        else:
            paid_at = datetime.now(KENYA_TZ)

        # Insert into Supabase payment table
        insert_response = supabase.table("payment").insert({
            "sms": sms_text,
            "code": code,
            "amount": amount,
            "names": names,
            "phone": normalized_phone,
            "paid_at": paid_at.isoformat()
        }).execute()

        if insert_response.data:
            return jsonify({"status": "success", "inserted": insert_response.data[0]}), 200
        else:
            return jsonify({"status": "failed", "error": "Could not insert SMS"}), 500

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500



@app.route("/set-purpose-figures", methods=["POST"])
def set_purpose_figures():
    try:
        if supabase is None:
            return jsonify({"success": False, "error": "Database client missing"}), 500

        data = request.get_json(force=True) or {}

        required_fields = [
            "registration_total",
            "registration_deadline",
            "partner_connection_total",
            "partner_connection_deadline",
            "insurance_total",
            "insurance_deadline"
        ]

        for field in required_fields:
            if data.get(field) is None:
                return jsonify({
                    "success": False,
                    "error": f"{field} is required"
                }), 400

        try:
            registration_total = int(data["registration_total"])
            partner_total = int(data["partner_connection_total"])
            insurance_total = int(data["insurance_total"])
        except ValueError:
            return jsonify({
                "success": False,
                "error": "Totals must be numbers"
            }), 400

        registration_deadline = data["registration_deadline"]
        partner_deadline = data["partner_connection_deadline"]
        insurance_deadline = data["insurance_deadline"]

        for date_str in [registration_deadline, partner_deadline, insurance_deadline]:
            datetime.strptime(date_str, "%Y-%m-%d")

        payload = {
            "registration_total": registration_total,
            "registration_deadline": registration_deadline,
            "partner_connection_total": partner_total,
            "partner_connection_deadline": partner_deadline,
            "insurance_total": insurance_total,
            "insurance_deadline": insurance_deadline
        }

        # 1️⃣ Try update first
        update_resp = supabase.table("purpose_settings") \
            .update(payload) \
            .eq("id", 1) \
            .execute()

        # 2️⃣ If no row updated, insert (WITHOUT id)
        if not update_resp.data:
            insert_resp = supabase.table("purpose_settings") \
                .insert(payload) \
                .execute()

            if getattr(insert_resp, "error", None):
                return jsonify({"success": False, "error": str(insert_resp.error)}), 500

        return jsonify({
            "success": True,
            "message": "Purpose figures saved successfully"
        }), 200

    except Exception as e:
        logger.exception("Set purpose figures error")
        return jsonify({"success": False, "error": "Server error"}), 500

@app.route("/get-purpose-figures", methods=["GET"])
def get_purpose_figures():
    try:
        if supabase is None:
            return jsonify({"success": False, "error": "Database client missing"}), 500

        resp = supabase.table("purpose_settings") \
            .select("*") \
            .eq("id", 1) \
            .single() \
            .execute()

        if getattr(resp, "error", None):
            return jsonify({"success": False, "error": str(resp.error)}), 500

        return jsonify({
            "success": True,
            "purpose": resp.data
        }), 200

    except Exception as e:
        logger.exception("Get purpose figures error")
        return jsonify({"success": False, "error": "Server error"}), 500





# -------------------------
# CREATE PAYMENT INTENT
# -------------------------
@app.route("/create-payment-intent", methods=["POST", "OPTIONS"])
def create_payment_intent():
    if request.method == "OPTIONS":
        return jsonify({"ok": True}), 200

    data = request.get_json()
    phone = data.get("phone")
    purpose = data.get("purpose")

    if not phone or not purpose:
        return jsonify({"error": "Missing fields"}), 400

    # Insert into payment_intent table
    result = supabase.table("payment_intent").insert({
        "phone": phone,
        "purpose": purpose
    }).execute()

    intent_id = result.data[0]["id"]
    return jsonify({"status": "ok", "intent_id": intent_id})

# -------------------------
# BACKGROUND PROCESSING
# -------------------------
def process_payment_intents():
    while True:
        try:
            # 1️⃣ Get all payment intents
            intents = supabase.table("payment_intent").select("*").execute().data

            for intent in intents:
                phone = intent["phone"]
                purpose = intent["purpose"]

                # 2️⃣ Find payment with same phone not yet confirmed
                payment_resp = supabase.table("payment") \
                    .select("*") \
                    .eq("phone", phone) \
                    .neq("verification", "confirmed") \
                    .execute()
                
                payments = payment_resp.data
                if not payments:
                    continue  # No new payment, skip

                payment = payments[0]
                amount = float(payment["amount"])

                # 3️⃣ Get purpose settings
                settings_resp = supabase.table("purpose_settings").select("*").single().execute()
                settings = settings_resp.data

                # 4️⃣ Get dere table row
                dere_resp = supabase.table("dere").select("*").single().execute()
                dere = dere_resp.data

                # 5️⃣ Update balances and paid amounts
                updates = {}
                if purpose == "registration":
                    new_paid = dere["registration_paid"] + amount
                    updates["registration_paid"] = new_paid
                    updates["registration_balance"] = settings["registration_total"] - new_paid
                elif purpose == "partner_connection":
                    new_paid = dere["partner_connection_paid"] + amount
                    updates["partner_connection_paid"] = new_paid
                    updates["partner_connection_balance"] = settings["partner_connection_total"] - new_paid
                elif purpose == "insurance":
                    new_paid = dere["insurance_paid"] + amount
                    updates["insurance_paid"] = new_paid
                    updates["insurance_balance"] = settings["insurance_total"] - new_paid
                else:
                    continue  # Unknown purpose

                # 6️⃣ Update dere table
                supabase.table("dere").update(updates).execute()

                # 7️⃣ Mark payment as confirmed
                supabase.table("payment").update({"verification": "confirmed"}) \
                    .eq("phone", phone) \
                    .execute()

        except Exception as e:
            print("Error processing payment intents:", e)

        # Wait a few seconds before checking again
        time.sleep(5)

# Start background thread
threading.Thread(target=process_payment_intents, daemon=True).start()

# -------------------------
# HEALTH CHECK
# -------------------------
@app.route("/health")
def health():
    return jsonify({"status": "Payment intent processor running"})


@app.route("/test-password", methods=["POST"])
def test_password():
    try:
        password = (request.form.get("password") or "").strip()

        if not password:
            return jsonify({"error": "Password missing"}), 400

        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        payload = {
            "password_hash": password_hash
        }

        # 🔍 HARD PROOF LOGS
        logger.critical("TEST HASH >>> %r", password_hash)
        logger.critical("TEST HASH LENGTH >>> %d", len(password_hash))

        res = supabase.table("owner").insert(payload).execute()

        return jsonify({
            "success": True,
            "hash_length": len(password_hash)
        }), 200

    except Exception as e:
        logger.exception("Test password insert failed")
        return jsonify({"error": "Server error"}), 500
        

@app.route("/register-owner-basic", methods=["POST"])
def register_owner_basic():
    try:
        data = request.get_json(force=True) or {}

        full_name = (data.get("full_name") or "").strip()
        phone = (data.get("phone_number") or "").strip()
        email = (data.get("email") or "").strip().lower()
        password = data.get("password") or ""

        # -----------------------------
        # Basic validation
        # -----------------------------
        if not full_name:
            return jsonify({"success": False, "error": "Full name is required"}), 400
        if not phone:
            return jsonify({"success": False, "error": "Phone number is required"}), 400
        if not email:
            return jsonify({"success": False, "error": "Email is required"}), 400
        if not password:
            return jsonify({"success": False, "error": "Password is required"}), 400

        # -----------------------------
        # Hash password
        # -----------------------------
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        # -----------------------------
        # Insert into owner table
        # -----------------------------
        response = supabase.table("owner").insert({
            "full_name": full_name,
            "phone_number": phone,
            "email": email,
            "password_hash": password_hash
        }).execute()

        if getattr(response, "error", None):
            return jsonify({
                "success": False,
                "error": "Database insert failed"
            }), 500

        return jsonify({
            "success": True,
            "message": "Owner registered successfully"
        }), 200

    except Exception as e:
        logger.exception("Owner basic registration error: %s", e)
        return jsonify({
            "success": False,
            "error": "Server error"
        }), 500

# ============================================================
# RUN APP
# ============================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
