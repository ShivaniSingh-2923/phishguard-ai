import os
import urllib.request
import joblib

print("📦 Initializing machine learning model components...")

# 1. Define where the model will be stored on Render's local disk
MODEL_PATH = "phishing_model.pkl"

# 2. Your modified direct-download Google Drive link
# (Converted from '/view' to the raw file endpoint 'uc?export=download')
MODEL_URL = "https://docs.google.com/uc?export=download&id=1W2oGS7Nsmg_wzPlBiW49Q3xRZx5JWBIa"

# 3. Check if the file exists on disk. If not, download it dynamically!
if not os.path.exists(MODEL_PATH):
    print("📥 Model file not found locally. Downloading from Google Drive...")
    try:
        # This downloads the raw 57MB file straight to your local directory
        urllib.request.urlretrieve(MODEL_URL, MODEL_PATH)
        print("✅ Download complete!")
    except Exception as e:
        print(f"❌ Failed to download model file: {e}")
        raise e

# 4. Now load the components safely from the local disk
model = joblib.load(MODEL_PATH)
feature_columns = joblib.load("feature_columns.pkl")
scaler = joblib.load("scaler.pkl")

print("✅ All model components loaded successfully into RAM!")