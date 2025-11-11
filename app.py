import os
import re
import random
import bcrypt
import cloudinary
import cloudinary.uploader
from datetime import datetime, timedelta
from io import BytesIO

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.datastructures import FileStorage
from dotenv import load_dotenv
from supabase import create_client, Client

# -----------------------------
# SENDGRID IMPORTS
# -----------------------------
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# -----------------------------
# PILLOW IMPORT
# -----------------------------
from PIL import Image

# -----------------------------
# LOAD ENV
# -----------------------------
load_dotenv()

app = Flask(__name__)

# -----------------------------
# SUPABASE CONFIG
# -----------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
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
# APP CONFIG
# -----------------------------
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20MB upload limit
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret")

CORS(app)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["10 per minute", "200 per day"]
)

# -----------------------------
# ALLOWED FILES
# -----------------------------
ALLOWED_EXT = {"jpg", "jpeg", "png"}
ALLOWED_MIME = {"image/png", "image/jpeg"}

def allowed_file(file: FileStorage):
    if not file or not file.filename:
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
        img = Image.open(file)
        img.thumbnail(max_size)  # Resize while maintaining aspect ratio
        buffer = BytesIO()
        img.save(buffer, format="JPEG", quality=85)  # Compress to JPEG
        buffer.seek(0)
        return buffer
    except Exception as e:
        raise ValueError(f"Image processing failed: {str(e)}")

# -----------------------------
# ROUTES
# -----------------------------
@app.route("/")
def home():
    return jsonify({"message": "D4D Flask Backend (Supabase + Cloudinary + SendGrid + Pillow Ready)"})

# -----------------------------
# DRIVER SIGNUP
# -----------------------------
@app.route("/signup", methods=["POST"])
@limiter.limit("5 per minute")
def signup():
    full_name = request.form.get("full_name")
    email = request.form.get("email")
    password = request.form.get("password")
    psv_expiry = request.form.get("psv_expiry")
    car_plate = request.form.get("car_plate")
    sacco = request.form.get("sacco")

    profile_photo = request.files.get("profile_photo")
    psv_badge = request.files.get("psv_badge")

    allowed_saccos = ["OOD", "UOD", "NONE"]

    # Required fields
    if not all([full_name, email, password, psv_expiry, car_plate, sacco, profile_photo, psv_badge]):
        return jsonify({"error": "All fields are required"}), 400

    if sacco not in allowed_saccos:
        return jsonify({"error": "Invalid sacco"}), 400

    clean_plate = normalize_plate(car_plate)
    if not valid_plate(clean_plate):
        return jsonify({"error": "Invalid car plate"}), 400

    ok, msg = check_password_strength(password)
    if not ok:
        return jsonify({"error": msg}), 400

    for f, name in [(profile_photo, "profile_photo"), (psv_badge, "psv_badge")]:
        if not allowed_file(f):
            return jsonify({"error": f"{name} must be jpg/jpeg/png"}), 400

    # Check duplicates in Supabase
    existing_driver = supabase.table("drivers").select("*").or_(f"email.eq.{email},car_plate.eq.{clean_plate}").execute()
    if existing_driver.data:
        return jsonify({"error": "Email or car plate already registered"}), 400

    # Resize images using Pillow
    try:
        resized_profile = resize_image(profile_photo)
        resized_badge = resize_image(psv_badge)
        up_profile = cloudinary.uploader.upload(resized_profile, folder="drivers/profile")
        profile_url = up_profile["secure_url"]
        up_badge = cloudinary.uploader.upload(resized_badge, folder="drivers/psv")
        badge_url = up_badge["secure_url"]
    except Exception as e:
        return jsonify({"error": "Image upload failed", "details": str(e)}), 500

    # Insert into Supabase
    driver_id = generate_driver_id()
    supabase.table("drivers").insert({
        "driver_id": driver_id,
        "full_name": full_name,
        "email": email,
        "password_hash": hash_password(password),
        "car_plate": clean_plate,
        "sacco": sacco,
        "profile_url": profile_url,
        "psv_badge_url": badge_url,
        "psv_expiry": parse_date(psv_expiry).isoformat(),
        "verified": False,
        "created_at": datetime.utcnow().isoformat()
    }).execute()

    return jsonify({
        "message": "Signup successful",
        "driver_id": driver_id,
        "driver": {
            "name": full_name,
            "email": email,
            "car_plate": clean_plate,
            "sacco": sacco,
            "profile_photo": profile_url,
            "psv_badge": badge_url,
            "psv_expiry": parse_date(psv_expiry).isoformat(),
        }
    }), 201

# -----------------------------
# SEND OTP VIA EMAIL
# -----------------------------
@app.route("/send_otp", methods=["POST"])
@limiter.limit("3 per minute")
def send_otp():
    email = request.json.get("email")
    if not email:
        return jsonify({"error": "Email required"}), 400

    code = str(random.randint(100000, 999999))
    expires = datetime.utcnow() + timedelta(minutes=5)

    # Save OTP in Supabase
    supabase.table("otp").insert({
        "email": email,
        "code": code,
        "expires_at": expires.isoformat(),
        "used": False
    }).execute()

    # Send email via SendGrid
    try:
        message = Mail(
            from_email=EMAIL_FROM,
            to_emails=email,
            subject="Your OTP Code",
            plain_text_content=f"Your OTP code is: {code}. It expires in 5 minutes."
        )
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        sg.send(message)
    except Exception as e:
        return jsonify({"error": "Failed to send OTP email", "details": str(e)}), 500

    return jsonify({"message": "OTP sent", "expires": expires.isoformat()})

# -----------------------------
# VERIFY OTP
# -----------------------------
@app.route("/verify_otp", methods=["POST"])
@limiter.limit("10 per minute")
def verify_otp():
    email = request.json.get("email")
    code = request.json.get("code")
    if not email or not code:
        return jsonify({"error": "email & code required"}), 400

    response = supabase.table("otp").select("*").eq("email", email).eq("code", code).eq("used", False).execute()
    otp = response.data[0] if response.data else None

    if not otp:
        return jsonify({"error": "Invalid OTP"}), 400

    if datetime.utcnow() > datetime.fromisoformat(otp["expires_at"]):
        return jsonify({"error": "OTP expired"}), 400

    supabase.table("otp").update({"used": True}).eq("id", otp["id"]).execute()
    supabase.table("drivers").update({"verified": True}).eq("email", email).execute()

    return jsonify({"message": "OTP verified"}), 200

# -----------------------------
# RUN
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
