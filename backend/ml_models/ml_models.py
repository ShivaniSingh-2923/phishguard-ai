import os
import joblib

print("📦 ML module initialized (lazy mode)")

BASE_DIR = os.path.dirname(__file__)

MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")
FEATURE_PATH = os.path.join(BASE_DIR, "feature_columns.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")

model = None
scaler = None
feature_columns = None

def load_models():
    global model, scaler, feature_columns

    if model is None:
        print("📥 Loading ML models into memory...")
        model = joblib.load(MODEL_PATH)
        feature_columns = joblib.load(FEATURE_PATH)
        scaler = joblib.load(SCALER_PATH)
        print("✅ Models loaded successfully!")

    return model, scaler, feature_columns