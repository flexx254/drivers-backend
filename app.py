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
def upload_documents():
    try:
        # -----------------------------
        # 1. Read form fields
        # -----------------------------
        token = request.form.get("token")
        id_number = request.form.get("id_number")

        license_exp = request.form.get("license_expiry")
        psv_exp = request.form.get("psv_badge_expiry")
        gc_exp = request.form.get("good_conduct_expiry")

        if not token:
            return jsonify({"success": False, "error": "Missing token"}), 400

        # -----------------------------
        # 2. Find user by token
        # -----------------------------
        lookup = supabase.table("dere").select("*").eq("continue_token", token).single().execute()

        if not lookup.data:
            return jsonify({"success": False, "error": "Invalid token"}), 400

        email = lookup.data["email"]

        # -----------------------------
        # 3. Upload files to Cloudinary
        # -----------------------------
        def upload_file(file):
            if not file:
                return None
            upload = cloudinary.uploader.upload(file, folder="driver_docs")
            return upload.get("secure_url")

        profile_file = request.files.get("profile_pic")
        license_file = request.files.get("license")
        psv_file = request.files.get("psv_badge")
        good_conduct_file = request.files.get("good_conduct")

        profile_url = upload_file(profile_file)
        license_url = upload_file(license_file)
        psv_url = upload_file(psv_file)
        gc_url = upload_file(good_conduct_file)

        # -----------------------------
        # 4. Build update fields
        # -----------------------------
        update_data = {
            "id_number": id_number,
            "license_expiry": license_exp,
            "psv_badge_expiry": psv_exp,
            "good_conduct_expiry": gc_exp,
        }

        if profile_url: update_data["profile_pic_url"] = profile_url
        if license_url: update_data["license_url"] = license_url
        if psv_url: update_data["psv_badge_url"] = psv_url
        if gc_url: update_data["good_conduct_url"] = gc_url

        # -----------------------------
        # 5. Save to database
        # -----------------------------
        supabase.table("dere").update(update_data).eq("email", email).execute()

        return jsonify({
            "success": True,
            "message": "Documents uploaded successfully."
        })

    except Exception as e:
        logger.exception("Document upload error: %s", str(e))
        return jsonify({"success": False, "error": str(e)}), 500





# ============================================================
# ROUTE: UPDATE ID NUMBER ONLY
# ============================================================
@app.route("/update-id", methods=["POST"])
def update_id():
    try:
        token = request.form.get("token", "").strip()
        id_number = request.form.get("id_number", "").strip()

        print("Received token:", token)
        print("Received ID:", id_number)

        if not token:
            return jsonify({"success": False, "error": "Token is required"}), 400
        if not id_number:
            return jsonify({"success": False, "error": "ID number is required"}), 400

        # Find user by token
        lookup = supabase.table("dere").select("*").eq("continue_token", token).single().execute()
        print("Token lookup:", lookup.data)

        if not lookup.data:
            return jsonify({"success": False, "error": "Invalid token"}), 400

        email = lookup.data.get("email")
        if not email:
            return jsonify({"success": False, "error": "No email found for token"}), 400

        # Update ID number
        update_resp = supabase.table("dere").update({
            "id_number": id_number
        }).eq("email", email).execute()

        print("Supabase update response:", update_resp)

        if getattr(update_resp, "error", None):
            return jsonify({"success": False, "error": str(update_resp.error)}), 500

        return jsonify({
            "success": True,
            "message": "ID number saved successfully."
        }), 200

    except Exception as e:
        logger.exception("ID update error: %s", str(e))
        return jsonify({"success": False, "error": str(e)}), 500



@app.route("/update-number-plate", methods=["POST"])
def update_number_plate():
    try:
        token = request.form.get("token", "").strip()
        plate = request.form.get("number_plate", "").strip()

        if not token:
            return jsonify({"success": False, "error": "Missing token"}), 400

        if not plate:
            return jsonify({"success": False, "error": "Number plate is required"}), 400

        # Normalize and validate
        normalized = normalize_plate(plate)
        if not valid_plate(normalized):
            return jsonify({"success": False, "error": "Invalid number plate format"}), 400

        # ------------------------------------------------------------------
        # 1. Look up user by continue_token
        # ------------------------------------------------------------------
        lookup = supabase.table("dere")\
            .select("*")\
            .eq("continue_token", token)\
            .single()\
            .execute()

        if not lookup.data:
            return jsonify({"success": False, "error": "Invalid token"}), 400

        email = lookup.data.get("email")

        # ------------------------------------------------------------------
        # 2. Check for duplicate number plate (exclude this user)
        # ------------------------------------------------------------------
        duplicate = supabase.table("dere")\
            .select("*")\
            .eq("number_plate", normalized)\
            .neq("email", email)\
            .execute()

        if duplicate.data:
            return jsonify({"success": False, "error": "Number plate already exists"}), 400

        # ------------------------------------------------------------------
        # 3. Update number plate
        # ------------------------------------------------------------------
        update_resp = supabase.table("dere")\
            .update({"number_plate": normalized})\
            .eq("continue_token", token)\
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
# ROUTE: UPDATE PROFILE PICTURE ONLY
# ============================================================
@app.route("/update-profile-picture", methods=["POST"])
def update_profile_picture():
    try:
        token = request.form.get("token", "").strip()
        file = request.files.get("profile_picture")

        if not token:
            return jsonify({"success": False, "error": "Missing token"}), 400

        if not file:
            return jsonify({"success": False, "error": "No image uploaded"}), 400

        # Validate file
        if not allowed_file(file):
            return jsonify({"success": False, "error": "Invalid image format. Use JPG or PNG."}), 400

        # ----------------------------------------------------------
        # 1. Find user by token
        # ----------------------------------------------------------
        lookup = supabase.table("dere")\
            .select("*")\
            .eq("continue_token", token)\
            .single()\
            .execute()

        if not lookup.data:
            return jsonify({"success": False, "error": "Invalid token"}), 400

        email = lookup.data.get("email")

        # ----------------------------------------------------------
        # 2. Resize image using Pillow before upload
        # ----------------------------------------------------------
        try:
            resized_buffer = resize_image(file)
        except Exception as e:
            return jsonify({"success": False, "error": f"Image processing failed: {str(e)}"}), 500

        # ----------------------------------------------------------
        # 3. Upload to Cloudinary
        # ----------------------------------------------------------
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

        # ----------------------------------------------------------
        # 4. Save URL to Supabase
        # ----------------------------------------------------------
        update_resp = supabase.table("dere")\
            .update({"profile_pic_url": image_url})\
            .eq("email", email)\
            .execute()

        if getattr(update_resp, "error", None):
            return jsonify({"success": False, "error": "Database update failed"}), 500

        # ----------------------------------------------------------
        # 5. SUCCESS
        # ----------------------------------------------------------
        return jsonify({
            "success": True,
            "profile_pic_url": image_url,
            "message": "Profile picture uploaded successfully."
        }), 200

    except Exception as e:
        logger.exception("Profile picture update error: %s", str(e))
        return jsonify({"success": False, "error": "Server error"}), 500


@app.route("/update-driving-license", methods=["POST"])
def update_driving_license():
    try:
        token = request.form.get("token", "").strip()
        license_expiry = request.form.get("license_expiry")
        file = request.files.get("driving_license")

        if not token:
            return jsonify({"success": False, "error": "Missing token"}), 400

        if not file:
            return jsonify({"success": False, "error": "No file uploaded"}), 400

        # Validate image
        if not allowed_file(file):
            return jsonify({"success": False, "error": "Invalid file format. Use JPG or PNG"}), 400

        # Find user
        lookup = supabase.table("dere").select("*").eq("continue_token", token).single().execute()
        if not lookup.data:
            return jsonify({"success": False, "error": "Invalid token"}), 400
        email = lookup.data.get("email")

        # Resize image
        resized_buffer = resize_image(file)

        # Upload to Cloudinary
        upload_resp = cloudinary.uploader.upload(resized_buffer, folder="driver_docs")
        license_url = upload_resp.get("secure_url")

        # Update Supabase
        supabase.table("dere").update({
            "license_url": license_url,
            "license_expiry": license_expiry
        }).eq("email", email).execute()

        return jsonify({
            "success": True,
            "license_url": license_url,
            "message": "Driving license uploaded successfully."
        })

    except Exception as e:
        logger.exception("Driving license upload error: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500



@app.route("/update-psv-badge", methods=["POST"])
def update_psv_badge():
    try:
        token = request.form.get("token", "").strip()
        psv_expiry = request.form.get("psv_badge_expiry")
        file = request.files.get("psv_badge")

        if not token:
            return jsonify({"success": False, "error": "Missing token"}), 400
        if not file:
            return jsonify({"success": False, "error": "No file uploaded"}), 400
        if not allowed_file(file):
            return jsonify({"success": False, "error": "Invalid file format. Use JPG or PNG"}), 400

        # Find user
        lookup = supabase.table("dere").select("*").eq("continue_token", token).single().execute()
        if not lookup.data:
            return jsonify({"success": False, "error": "Invalid token"}), 400
        email = lookup.data.get("email")

        # Resize & upload
        resized_buffer = resize_image(file)
        upload_resp = cloudinary.uploader.upload(resized_buffer, folder="driver_docs")
        psv_url = upload_resp.get("secure_url")

        # Save to DB
        supabase.table("dere").update({
            "psv_badge_url": psv_url,
            "psv_badge_expiry": psv_expiry
        }).eq("email", email).execute()

        return jsonify({
            "success": True,
            "psv_badge_url": psv_url,
            "message": "PSV badge uploaded successfully."
        })

    except Exception as e:
        logger.exception("PSV badge upload error: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/update-good-conduct", methods=["POST"])
def update_good_conduct():
    try:
        token = request.form.get("token", "").strip()
        gc_expiry = request.form.get("good_conduct_expiry")
        file = request.files.get("good_conduct")

        if not token:
            return jsonify({"success": False, "error": "Missing token"}), 400
        if not file:
            return jsonify({"success": False, "error": "No file uploaded"}), 400
        if not allowed_file(file):
            return jsonify({"success": False, "error": "Invalid file format. Use JPG or PNG"}), 400

        # Find user
        lookup = supabase.table("dere").select("*").eq("continue_token", token).single().execute()
        if not lookup.data:
            return jsonify({"success": False, "error": "Invalid token"}), 400
        email = lookup.data.get("email")

        # Resize & upload
        resized_buffer = resize_image(file)
        upload_resp = cloudinary.uploader.upload(resized_buffer, folder="driver_docs")
        gc_url = upload_resp.get("secure_url")

        # Save to DB
        supabase.table("dere").update({
            "good_conduct_url": gc_url,
            "good_conduct_expiry": gc_expiry
        }).eq("email", email).execute()

        return jsonify({
            "success": True,
            "good_conduct_url": gc_url,
            "message": "Good conduct certificate uploaded successfully."
        })

    except Exception as e:
        logger.exception("Good conduct upload error: %s", e)
        return jsonify({"success": False, "error": str(e)}), 500

# ============================================================
# ROUTE: LOGIN
# ============================================================
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

    # Fetch user from Supabase
    try:
        response = supabase.table("dere").select("*").eq("email", email).single().execute()
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

    # Return continue token for authenticated requests
    token = user.get("continue_token") or ""
    return jsonify({
        "success": True,
        "token": token,
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
