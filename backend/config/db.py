# config/db.py — clean version

import os
import logging
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

MONGO_URI = os.getenv("MONGO_URI")

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")
    logger.info("MongoDB connected successfully.")
except ConnectionFailure as e:
    logger.critical(f"MongoDB connection failed: {e}")
    raise

db = client["phishGuard"]

# ── Core collections ──────────────────────────────────────────────────────────
scans_collection     = db["scans"]
users_collection     = db["users"]
blacklist_collection = db["blacklist"]
stats_collection     = db["stats"]

# ── OTP collections — TWO SEPARATE ones, no naming conflict ──────────────────
forgot_password_otp_collection = db["otp_tokens"]   # ← forgot-password system
change_password_otp_collection = db["otps"]          # ← change-password system

# ── Indexes: core ────────────────────────────────────────────────────────────
scans_collection.create_index([("user_id", ASCENDING), ("timestamp", DESCENDING)])
scans_collection.create_index([("timestamp", DESCENDING)])
users_collection.create_index([("email", ASCENDING)], unique=True)
blacklist_collection.create_index([("url", ASCENDING)], unique=True)

# ── Indexes: forgot-password OTPs ────────────────────────────────────────────
forgot_password_otp_collection.create_index(
    "expires_at", expireAfterSeconds=0   # TTL — MongoDB auto-deletes expired docs
)
forgot_password_otp_collection.create_index(
    "email", unique=True                 # one pending OTP per email at a time
)

# ── Indexes: change-password OTPs ────────────────────────────────────────────
change_password_otp_collection.create_index(
    [("user_id", ASCENDING)],
    unique=True,
    name="unique_user_change_otp"        # one pending OTP per logged-in user
)
change_password_otp_collection.create_index(
    [("expires_at", ASCENDING)],
    expireAfterSeconds=600,              # hard cleanup 10 min after expiry
    name="ttl_change_otp_expiry"
)

logger.info("MongoDB indexes ensured.")