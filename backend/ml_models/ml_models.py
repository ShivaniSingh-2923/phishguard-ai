import os
import joblib
import requests

print("📦 ML module initialized (lazy mode)")

BASE_DIR = os.path.dirname(__file__)

MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")
FEATURE_PATH = os.path.join(BASE_DIR, "feature_columns.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")

# 🔥 YOUR GOOGLE DRIVE DIRECT LINK
MODEL_URL = "https://drive.google.com/uc?export=download&id=1B4dXqJ_8qXDaUJLSY5o8JijY3IyUPYbl"

model = None
scaler = None
feature_columns = None


# ✅ STEP 1: Download model if not present
def download_model():
    if not os.path.exists(MODEL_PATH):
        print("📥 Model not found. Downloading from Google Drive...")

        os.makedirs(BASE_DIR, exist_ok=True)

        try:
            response = requests.get(MODEL_URL, stream=True)
            with open(MODEL_PATH, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            print("✅ Model downloaded successfully!")

        except Exception as e:
            print("❌ Error downloading model:", e)


# ✅ STEP 2: Load models (lazy loading)
def load_models():
    global model, scaler, feature_columns

    if model is None:
        print("📥 Loading ML models into memory...")

        # 🔥 Ensure model exists
        download_model()

        try:
            model = joblib.load(MODEL_PATH)
            feature_columns = joblib.load(FEATURE_PATH)
            scaler = joblib.load(SCALER_PATH)

            print("✅ Models loaded successfully!")

        except Exception as e:
            print("❌ Error loading models:", e)
            model = None

    return model, scaler, feature_columns