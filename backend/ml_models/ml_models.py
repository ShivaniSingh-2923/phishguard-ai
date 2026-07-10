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
import requests

def download_model():
    if not os.path.exists(MODEL_PATH):
        print("⬇️ Downloading model...")

        URL = MODEL_URL
        session = requests.Session()

        response = session.get(URL, stream=True)

        # Handle Google Drive warning
        for key, value in response.cookies.items():
            if key.startswith('download_warning'):
                params = {'id': URL.split("id=")[-1], 'confirm': value}
                response = session.get("https://drive.google.com/uc", params=params, stream=True)
                break

        with open(MODEL_PATH, "wb") as f:
            for chunk in response.iter_content(1024 * 1024):
                if chunk:
                    f.write(chunk)

        print("✅ Model downloaded!")


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