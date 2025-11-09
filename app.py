import os
import re
import random
import bcrypt
import cloudinary
import cloudinary.uploader
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.datastructures import FileStorage
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# -----------------------------
# DATABASE (SUPABASE POSTGRES)
# -----------------------------
# Render automatically injects DATABASE_URL
database_url = os.getenv("DATABASE_URL")

# Supabase uses postgres, must fix sslmode
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://")

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB upload limit
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret")

# Extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
CORS(app)

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["10 per minute", "200 per day"]
)

# -----------------------------
# CLOUDINARY CONFIG
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
    if not file or not file.filename:
        return False
    ext = file.filename.rsplit(".", 1)[-1].lower()
    return ext in ALLOWED_EXT and file.mimetype in ALLOWED_MIME


# -----------------------------
# MODELS
# -----------------------------
class Driver(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    driver_id = db.Column(db.String(32), unique=True, nullable=False)

    full_name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(32), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    car_plate = db.Column(db.String(32), unique=True, nullable=False)
    sacco = db.Column(db.String(32), nullable=False)

    profile_url = db.Column(db.String(400))
    psv_badge_url = db.Column(db.String(400))
    psv_expiry = db.Column(db.Date, nullable=False)

    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(32), nullable=False)
    code = db.Column(db.String(8), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)


# -----------------------------
# UTILITIES
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


def generate_driver_id(db_id: int) -> str:
    return f"{db_id}-{random.randint(100000, 999999)}"


# -----------------------------
# ROUTES
# -----------------------------
@app.route("/")
def home():
    return jsonify({"message": "D4D Flask Backend (Supabase Ready)"})


# -----------------------------
# DRIVER SIGNUP
# -----------------------------
@app.route("/signup", methods=["POST"])
@limiter.limit("5 per minute")
def signup():
    full_name = request.form.get("full_name")
    phone = request.form.get("phone")
    password = request.form.get("password")
    psv_expiry = request.form.get("psv_expiry")
    car_plate = request.form.get("car_plate")
    sacco = request.form.get("sacco")

    profile_photo = request.files.get("profile_photo")
    psv_badge = request.files.get("psv_badge")

    allowed_saccos = ["OOD", "UOD", "NONE"]

    # Required fields
    if not all([full_name, phone, password, psv_expiry, car_plate,
                sacco, profile_photo, psv_badge]):
        return jsonify({"error": "All fields are required"}), 400

    # Sacco check
    if sacco not in allowed_saccos:
        return jsonify({"error": "Invalid sacco"}), 400

    # Phone validation
    if not PHONE_REGEX.match(phone):
        return jsonify({"error": "Phone must be +2547XXXXXXXX"}), 400

    # PSV expiry date
    expiry = parse_date(psv_expiry)
    if not expiry:
        return jsonify({"error": "Invalid date format"}), 400
    if expiry <= datetime.utcnow().date():
        return jsonify({"error": "PSV expiry must be a future date"}), 400

    # Plate
    clean_plate = normalize_plate(car_plate)
    if not valid_plate(clean_plate):
        return jsonify({"error": "Invalid car plate format"}), 400

    # Password strength
    ok, msg = check_password_strength(password)
    if not ok:
        return jsonify({"error": msg}), 400

    # File validation
    for f, name in [(profile_photo, "profile_photo"), (psv_badge, "psv_badge")]:
        if not allowed_file(f):
            return jsonify({"error": f"{name} must be jpg/jpeg/png"}), 400

    # Duplicate checks
    if Driver.query.filter_by(phone=phone).first():
        return jsonify({"error": "Phone already registered"}), 400

    if Driver.query.filter_by(car_plate=clean_plate).first():
        return jsonify({"error": "Car plate already registered"}), 400

    # Upload
    try:
        up_profile = cloudinary.uploader.upload(profile_photo, folder="drivers/profile")
        profile_url = up_profile["secure_url"]
    except Exception as e:
        return jsonify({"error": "Profile upload failed", "details": str(e)}), 500

    try:
        up_badge = cloudinary.uploader.upload(psv_badge, folder="drivers/psv")
        badge_url = up_badge["secure_url"]
    except Exception as e:
        return jsonify({"error": "PSV badge upload failed", "details": str(e)}), 500

    # Save to DB
    driver = Driver(
        full_name=full_name,
        phone=phone,
        password_hash=hash_password(password),
        car_plate=clean_plate,
        sacco=sacco,
        profile_url=profile_url,
        psv_badge_url=badge_url,
        psv_expiry=expiry
    )

    db.session.add(driver)
    db.session.commit()  # driver.id now available

    driver.driver_id = generate_driver_id(driver.id)
    db.session.commit()

    return jsonify({
        "message": "Signup successful",
        "driver_id": driver.driver_id,
        "driver": {
            "name": driver.full_name,
            "phone": driver.phone,
            "car_plate": driver.car_plate,
            "sacco": driver.sacco,
            "profile_photo": driver.profile_url,
            "psv_badge": driver.psv_badge_url,
            "psv_expiry": driver.psv_expiry.isoformat(),
        }
    }), 201


# -----------------------------
# SEND OTP
# -----------------------------
@app.route("/send_otp", methods=["POST"])
@limiter.limit("3 per minute")
def send_otp():
    phone = request.json.get("phone")

    if not phone or not PHONE_REGEX.match(phone):
        return jsonify({"error": "Invalid phone"}), 400

    code = str(random.randint(100000, 999999))
    expires = datetime.utcnow() + timedelta(minutes=5)

    otp = OTP(phone=phone, code=code, expires_at=expires)
    db.session.add(otp)
    db.session.commit()

    print("OTP for", phone, "=", code)

    return jsonify({"message": "OTP sent", "expires": expires.isoformat()})


# -----------------------------
# VERIFY OTP
# -----------------------------
@app.route("/verify_otp", methods=["POST"])
@limiter.limit("10 per minute")
def verify_otp():
    phone = request.json.get("phone")
    code = request.json.get("code")

    if not phone or not code:
        return jsonify({"error": "phone & code required"}), 400

    otp = OTP.query.filter_by(phone=phone, code=code, used=False).first()

    if not otp:
        return jsonify({"error": "Invalid OTP"}), 400

    if datetime.utcnow() > otp.expires_at:
        return jsonify({"error": "OTP expired"}), 400

    otp.used = True
    db.session.commit()

    driver = Driver.query.filter_by(phone=phone).first()
    if driver:
        driver.verified = True
        db.session.commit()

    return jsonify({"message": "OTP verified"}), 200


# -----------------------------
# RUN
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
