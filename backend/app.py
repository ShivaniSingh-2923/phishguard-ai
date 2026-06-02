from dotenv import load_dotenv
load_dotenv()

import os
import re
import logging
import socket
import uuid
import tempfile
from datetime import datetime, timezone

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)
import bcrypt
from werkzeug.utils import secure_filename

# ✅ CORRECT IMPORTS (with backend.)
from backend.services.llm_explainer import generate_llm_explanation
from backend.routes.password_reset import password_reset_bp
from backend.routes.profile_security import profile_security_bp

from backend.config.db import (
    scans_collection,
    blacklist_collection,
    stats_collection,
    users_collection
)

from backend.modules.url_detector import analyze_url
from backend.modules.sms_detector import analyze_sms_text
from backend.modules.number_checker import check_phone_number
from backend.modules.voice_detector import VoiceDetector
from backend.modules.ocr_detector import analyze_image


# ✅ Upload folder (perfect)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── App Setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)

from flask import make_response

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = make_response()

        response.headers["Access-Control-Allow-Origin"] = "http://localhost:5173"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Credentials"] = "true"

        return response, 200

# ✅ Fixed — added port 5173 (Vite's default port)
CORS(app,
     supports_credentials=True,
     resources={r"/*": {
         "origins": [
             "http://localhost:5173",    # ← Vite (your actual React port)
             "http://127.0.0.1:5173",   # ← Vite alternative
             "http://localhost:3000",    # ← Keep for safety
         ],
         "allow_headers": ["Content-Type", "Authorization"],
         "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
     }}
)

# ADD after `app.register_blueprint(password_reset_bp)`:
app.register_blueprint(profile_security_bp) 


socket.setdefaulttimeout(3)

# ── JWT Config ────────────────────────────────────────────────────────────────
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "change-this-in-production")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 3600        # 1 hour
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = 2592000    # 30 days
jwt = JWTManager(app)

app.register_blueprint(password_reset_bp)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

file_handler = logging.FileHandler('app.log')
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
logger.addHandler(file_handler)

# ── Rate Limiting ─────────────────────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["60 per hour"],
    storage_uri="memory://"
)
limiter.limit("5 per 15 minutes")(password_reset_bp) 
limiter.limit("10 per 15 minutes")(profile_security_bp)

# ── Voice Model (lazy-loaded) ─────────────────────────────────────────────────
_voice_model = None

def get_voice_model():
    """Lazy-load the voice model to avoid slow cold starts."""
    global _voice_model
    if _voice_model is None:
        logger.info("Loading VoiceDetector model...")
        _voice_model = VoiceDetector()
        logger.info("VoiceDetector model loaded.")
    return _voice_model

# ── Helper: persistent stats ──────────────────────────────────────────────────
def increment_stat(field: str):
    """Atomically increment a stat counter in MongoDB."""
    stats_collection.update_one(
        {"_id": "global"},
        {"$inc": {field: 1}},
        upsert=True
    )

def get_stats() -> dict:
    doc = stats_collection.find_one({"_id": "global"}) or {}
    return {
        "total_scans":       doc.get("total_scans", 0),
        "scams_detected":    doc.get("scams_detected", 0),
        "community_reports": doc.get("community_reports", 0),
    }

# ── Helper: persistent blacklist ──────────────────────────────────────────────
def is_blacklisted(url: str) -> bool:
    return blacklist_collection.find_one({"url": url.lower()}) is not None

def add_to_blacklist(url: str):
    blacklist_collection.update_one(
        {"url": url.lower()},
        {"$set": {"url": url.lower(), "added_at": datetime.now(timezone.utc)}},
        upsert=True
    )

# ── Global Error Handler ──────────────────────────────────────────────────────
@app.errorhandler(Exception)
def handle_global_error(e):
    logger.error(f"Unhandled Exception: {str(e)}")
    return jsonify({"status": "ERROR", "message": "Something went wrong on the server"}), 500

# ── Security Headers ──────────────────────────────────────────────────────────
@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"]   = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# ─────────────────────────── AUTH ROUTES ─────────────────────────────────────

def _verify_password(plain: str, stored: str) -> bool:
    """
    Handles both hash formats during migration:
      - Legacy werkzeug hashes  → pbkdf2:sha256:... or scrypt:...
      - New bcrypt hashes       → $2b$...
    Old users are verified with werkzeug; new/updated users with bcrypt.
    """
    if not stored:
        return False
    if stored.startswith(("pbkdf2", "scrypt")):
        from werkzeug.security import check_password_hash
        return check_password_hash(stored, plain)
    try:
        return bcrypt.checkpw(plain.encode(), stored.encode())
    except Exception:
        return False

@app.route("/auth/register", methods=["POST"])
@limiter.limit("10 per hour")
def register():
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data provided"}), 400

    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    name     = data.get("name", "").strip()

    # Basic validation
    if not email or not password or not name:
        return jsonify({"error": "Name, email and password are required"}), 400

    if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w{2,}$', email):
        return jsonify({"error": "Invalid email format"}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    # Duplicate check
    if users_collection.find_one({"email": email}):
        return jsonify({"error": "Email already registered"}), 409
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user = {
        "name":       name,
        "email":      email,
        "password":   hashed_pw,
        "created_at": datetime.now(timezone.utc),
        "role":       "user",
    }
    result = users_collection.insert_one(user)
    user_id = str(result.inserted_id)

    access_token  = create_access_token(identity=user_id)
    refresh_token = create_refresh_token(identity=user_id)

    logger.info(f"New user registered: {email}")
    return jsonify({
        "message":       "Registration successful",
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "user": {"id": user_id, "name": name, "email": email}
    }), 201


@app.route("/auth/login", methods=["POST"])
@limiter.limit("20 per hour")
def login():
    data = request.get_json()
 
    if not data:
        return jsonify({"error": "No data provided"}), 400
 
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
 
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
 
    user = users_collection.find_one({"email": email})
 
    # Block soft-deleted accounts
    if user and user.get("is_deleted"):
        return jsonify({"error": "This account has been deleted."}), 403
 
    # ── Debug block (safe — no hash method called directly) ───────────────────
    print(f"--- LOGIN DEBUG ---")
    print(f"Target Email: {email}")
    print(f"User Found in DB: {user is not None}")
    print(f"-------------------")
    # ── End debug (remove these print statements before going to production) ──
 
    # Same error for wrong email AND wrong password — prevents user enumeration
    if not user or not _verify_password(password, user["password"]):
        logger.warning(f"Failed login attempt for: {email}")
        return jsonify({"error": "Invalid email or password"}), 401
 
    # ── Silent hash upgrade ───────────────────────────────────────────────────
    # If user still has an old werkzeug hash, upgrade it to bcrypt transparently.
    # They notice nothing — next login uses bcrypt automatically.
    if user["password"].startswith(("pbkdf2", "scrypt")):
        new_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"password": new_hash}}
        )
        logger.info(f"Password hash upgraded to bcrypt for: {email}")
 
    user_id       = str(user["_id"])
    access_token  = create_access_token(identity=user_id)
    refresh_token = create_refresh_token(identity=user_id)
 
    logger.info(f"User logged in: {email}")
    return jsonify({
        "message":       "Login successful",
        "access_token":  access_token,
        "refresh_token": refresh_token,
        "user": {
            "id":    user_id,
            "name":  user.get("name"),
            "email": user.get("email"),
            "role":  user.get("role", "user"),
            "password_changed_at": (
                user.get("password_changed_at").isoformat()
                if user.get("password_changed_at") else None
            ),
        }
    })



@app.route("/auth/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh_token():
    """Issue a new access token using a valid refresh token."""
    user_id      = get_jwt_identity()
    access_token = create_access_token(identity=user_id)
    return jsonify({"access_token": access_token})


@app.route("/auth/me", methods=["GET"])
@jwt_required()
def get_me():
    """Return the currently logged-in user's profile."""
    from bson import ObjectId
    user_id = get_jwt_identity()
    user    = users_collection.find_one({"_id": ObjectId(user_id)})

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
    "id":                   str(user["_id"]),
    "name":                 user.get("name"),
    "email":                user.get("email"),
    "role":                 user.get("role", "user"),
    "created_at":           user.get("created_at").isoformat() if user.get("created_at") else None,
    # ↓ NEW — lets the frontend show cooldown state
    "password_changed_at":  user.get("password_changed_at").isoformat()
                            if user.get("password_changed_at") else None,
})

# ─────────────────────────── SCAN ROUTES ─────────────────────────────────────



@app.route("/")
def home():
    return render_template("index.html")


@app.route('/detect', methods=['POST'])
@limiter.limit("20 per minute")
@jwt_required(optional=True)
def detect():
    data = request.get_json()

    if not data or "url" not in data:
        logger.warning("Bad request: missing URL in body")
        return jsonify({"error": "No URL provided"}), 400

    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    if len(url) > 2048:
        logger.warning(f"Bad request: URL too long ({len(url)} chars)")
        return jsonify({"error": "URL too long (max 2048 characters)"}), 400

    if not re.match(r'https?://', url):
        url = 'https://' + url

    logger.info(f"URL scan requested: {url[:80]}")
    increment_stat("total_scans")

    if is_blacklisted(url):
        logger.info(f"Blacklisted URL blocked: {url[:80]}")
        increment_stat("scams_detected")
        return jsonify({
            "status": "SCAM",
            "score": 100,
            "verdict": "CRITICAL",
            "verdict_color": "danger",
            "summary": "This URL is on a community blacklist of known scam sites.",
            "indicators": [{
                "label": "Community blacklist",
                "explanation": "This URL was reported and confirmed malicious by the community.",
                "raw": "Community Blacklisted"
            }],
            "positive_signals": [],
            "recommendation": "Do NOT proceed. Close this page immediately.",
            "llm_explanation": None,
            "endee_match": None,
            "reasons": ["Community Blacklisted"],
        })

    result = analyze_url(url)

    if result.get("status") == "SCAM":
        increment_stat("scams_detected")

    exp = result.pop("explanation", {}) or {}
    result["verdict"] = exp.get("verdict", result.get("status", "UNKNOWN"))
    result["verdict_color"] = exp.get("verdict_color", "info")
    result["summary"] = exp.get("summary", "")
    result["indicators"] = exp.get("indicators", [])
    result["positive_signals"] = exp.get("positive_signals", [])
    result["recommendation"] = exp.get("recommendation", "")

    # 🔥 LLM ADD
    try:
        llm_explanation = generate_llm_explanation(
            input_data=url,
            reasons=result.get("reasons", []),
            score=result.get("score", 0),
            confidence=result.get("confidence", 0),
            scan_type="url"
        )
    except Exception as e:
        logger.error(f"LLM error (URL): {e}")
        llm_explanation = None

    result["llm_explanation"] = llm_explanation

    user_id = get_jwt_identity()

    scans_collection.insert_one({
        "type": "url",
        "content": url,
        "result": {
            "score": result.get("score"),
            "status": result.get("status"),
            "verdict": result.get("verdict"),
        },
        "timestamp": datetime.now(timezone.utc),
        "user_id": user_id,
    })

    return jsonify(result)


@app.route('/analyze-sms', methods=['POST'])
@limiter.limit("30 per minute")
@jwt_required(optional=True)
def analyze_sms():
    data = request.get_json()

    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400

    text = data.get("text", "").strip()

    if not text:
        return jsonify({"error": "Text cannot be empty"}), 400
    if len(text) > 5000:
        return jsonify({"error": "Text too long (max 5000 characters)"}), 400

    logger.info(f"SMS scan: '{text[:50]}...'")
    increment_stat("total_scans")

    result = analyze_sms_text(text)
    user_id = get_jwt_identity()

    if result.get("status") == "SCAM":
        increment_stat("scams_detected")

    scans_collection.insert_one({
        "type": "sms",
        "content": text[:200],
        "result": {
            "score": result["score"],
            "status": result["status"]
        },
        "timestamp": datetime.now(timezone.utc),
        "user_id": user_id,
    })

    # 🔥 LLM ADD
    try:
        llm_explanation = generate_llm_explanation(
            input_data=text,
            reasons=result.get("detections", []),
            score=result.get("score", 0),
            confidence=result.get("confidence", 0),
            scan_type="sms"
        )
    except Exception as e:
        logger.error(f"LLM error (SMS): {e}")
        llm_explanation = None

    logger.info(f"SMS result: {result['status']} (score={result['score']})")

    return jsonify({
        "status": result["status"],
        "score": result["score"],
        "reasons": result["detections"],
        "endee_match": result["endee_match"],
        "llm_explanation": llm_explanation
    })


@app.route('/check-number', methods=['POST'])
@limiter.limit("30 per minute")
@jwt_required(optional=True)
def check_number():
    data = request.get_json()

    if not data or "number" not in data:
        return jsonify({"error": "No number provided"}), 400

    number = data.get('number', '').strip().replace(' ', '').replace('-', '')

    if not number:
        return jsonify({"error": "Number cannot be empty"}), 400

    logger.info(f"Phone check: {number[:6]}****")
    increment_stat("total_scans")

    result = check_phone_number(number)
    user_id = get_jwt_identity()

    scans_collection.insert_one({
        "type": "phone",
        "content": f"+{number}" if not number.startswith('+') else number,
        "result": {
            "score": result.get("score"),
            "status": result.get("status")
        },
        "timestamp": datetime.now(timezone.utc),
        "user_id": user_id,
    })

    # 🔥 LLM ADD
    try:
        llm_explanation = generate_llm_explanation(
            input_data=number,
            reasons=result.get("reasons", []),
            score=result.get("score", 0),
            confidence=result.get("confidence", 0),
            scan_type="phone"
        )
    except Exception as e:
        logger.error(f"LLM error (Phone): {e}")
        llm_explanation = None

    result["llm_explanation"] = llm_explanation

    return jsonify(result)

ALLOWED_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.webp'}
@app.route('/analyze-image', methods=['POST'])
@limiter.limit("10 per minute")
@jwt_required(optional=True)
def analyze_image_route():

    # ── 1. Get file ────────────────────────────────────────
    file = request.files.get('image')
    if not file or not file.filename:
        logger.warning("OCR: no file received. Keys: %s", list(request.files.keys()))
        return jsonify({"error": "No image file provided"}), 400

    # ── 2. Validate extension ──────────────────────────────
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        return jsonify({"error": f"Unsupported file type '{ext}'. Use JPG, PNG, or WEBP."}), 400

    # ── 3. Temp path ───────────────────────────────────────
    temp_dir  = tempfile.gettempdir()
    temp_name = f"ocr_{uuid.uuid4().hex}{ext}"
    temp_path = os.path.join(temp_dir, temp_name)

    try:
        file.save(temp_path)
        logger.info(f"OCR temp saved: {temp_path}")

        # ── 4. Size check ───────────────────────────────────
        size_mb = os.path.getsize(temp_path) / (1024 * 1024)
        if size_mb > 5:
            return jsonify({"error": "File too large (max 5MB)"}), 400

        # ── 5. OCR analysis ─────────────────────────────────
        from backend.modules.ocr_detector import analyze_image
        result  = analyze_image(temp_path)
        user_id = get_jwt_identity()

        # ── 6. Persist ──────────────────────────────────────
        increment_stat("total_scans")
        if result.get("status") == "SCAM":
            increment_stat("scams_detected")

        scans_collection.insert_one({
            "type":      "ocr",
            "filename":  file.filename,
            "result":    result,
            "timestamp": datetime.now(timezone.utc),
            "user_id":   user_id,
        })

        # ── 7. LLM FIX (CLEAN + SAFE) ───────────────────────
        try:
            llm_explanation = generate_llm_explanation(
                input_data=result.get("text", "Image Text"),  # ✅ better than static text
                reasons=result.get("reasons", []),
                score=result.get("score", 0),
                confidence=result.get("confidence", 0),
                scan_type="image"
            )
        except Exception as e:
            logger.error(f"LLM error (OCR): {e}")
            llm_explanation = None

        result["llm_explanation"] = llm_explanation

        logger.info(f"OCR complete: {result.get('status')} score={result.get('score')}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"OCR route error: {e}", exc_info=True)
        return jsonify({"error": "Image analysis failed. Please try again."}), 500

    finally:
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass

@app.route("/detect_voice", methods=["POST"])
@limiter.limit("10 per minute")
@jwt_required(optional=True)
def detect_voice():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    voice_model = get_voice_model()
    result = voice_model.predict(file)

    # 🔥 LLM ADD
    try:
        llm_explanation = generate_llm_explanation(
            input_data=file.filename,
            reasons=[result.get("label")],
            score=result.get("risk_score", 0),
            confidence=result.get("confidence", 0),
            scan_type="voice"
        )
    except Exception as e:
        logger.error(f"LLM error (Voice): {e}")
        llm_explanation = None

    result["llm_explanation"] = llm_explanation

    return jsonify(result)


@app.route('/explain', methods=['POST'])
def explain_url():
    data = request.get_json() or {}

    explanation = generate_llm_explanation(
        input_data=data.get('url', ''),
        reasons=data.get('reasons', []),
        score=data.get('score', 0),
        confidence=data.get('confidence', 0),
        scan_type="url"
    )

    return jsonify({
        "success": True,
        "llm_explanation": explanation
    })


@app.route("/auth/change-password", methods=["POST"])
@jwt_required()
def change_password():
    from bson import ObjectId
    user_id = get_jwt_identity()
    data    = request.get_json() or {}
 
    current_password = data.get("current_password", "")
    new_password     = data.get("new_password", "")
    confirm_password = data.get("confirm_password", "")
 
    if not current_password or not new_password or not confirm_password:
        return jsonify({"error": "All fields are required."}), 400
 
    if new_password != confirm_password:
        return jsonify({"error": "New passwords do not match."}), 400
 
    if len(new_password) < 8 or not any(c.isdigit() for c in new_password):
        return jsonify({"error": "Password must be 8+ characters with at least one number."}), 400
 
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"error": "User not found."}), 404
 
    # Use _verify_password so it works with both werkzeug and bcrypt hashes
    if not _verify_password(current_password, user["password"]):
        return jsonify({"error": "Current password is incorrect."}), 401
 
    # Save new password as bcrypt hash (consistent with the rest of the app)
    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {
            "password":            new_hash,
            "password_changed_at": datetime.now(timezone.utc),
        }}
    )
    return jsonify({"message": "Password updated successfully."}), 200



# ─────────────────────────── ENTRY POINT ─────────────────────────────────────
if __name__ == "__main__":
    logger.info("Starting PhishGuard AI server...")
    
    # 1. Dynamically get the port from Render (defaults to 5000 locally)
    port = int(os.environ.get("PORT", 5000))
    
    # 2. Pass the dynamic port variable into app.run()
    app.run(
        host="0.0.0.0", 
        port=port, 
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true"
    )