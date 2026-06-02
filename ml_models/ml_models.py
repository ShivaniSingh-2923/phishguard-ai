import os
import urllib.request
import joblib

print("📦 Initializing machine learning model components...")

MODEL_PATH = "phishing_model.pkl"

# 🔗 Paste your direct Kaggle file download link here!
MODEL_URL = "https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset"
if not os.path.exists(MODEL_PATH):
    print("📥 Model file not found locally. Downloading from Kaggle...")
    try:
        # We add a User-Agent header so Kaggle allows the script to download it cleanly
        opener = urllib.request.build_opener()
        opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
        urllib.request.install_opener(opener)
        
        # Download the file
        urllib.request.urlretrieve(MODEL_URL, MODEL_PATH)
        print("✅ Kaggle download complete!")
    except Exception as e:
        print(f"❌ Failed to download model from Kaggle: {e}")
        raise e

# Now load your model safely from the disk
model = joblib.load(MODEL_PATH)
feature_columns = joblib.load("feature_columns.pkl")
scaler = joblib.load("scaler.pkl")

print("✅ All model components loaded successfully into RAM!")