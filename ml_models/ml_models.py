import joblib

print("📦 Loading trained model...")

model = joblib.load("phishing_model.pkl")
feature_columns = joblib.load("feature_columns.pkl")
scaler = joblib.load("scaler.pkl")

print("✅ Model loaded successfully")