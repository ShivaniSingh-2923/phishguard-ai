# 🛡️ PhisGuard — Phishing & Scam Detection System

> An AI-powered cybersecurity platform using **Random Forest ML**, **XAI**, **feature engineering**, and **Google APIs** for semantic and heuristic phishing detection.

---

## 📌 Problem Statement

Phishing and online scams cause billions in losses annually. Traditional detection systems often fail against:

- Semantically disguised phishing messages  
- Brand impersonation URLs  
- AI-generated voice scams  
- Fake payment screenshots  

**PhisGuard** solves this by combining **ML**, **vector similarity / semantic analysis**, and **heuristics** for accurate, context-aware threat detection.

---

## 🧠 System Design
User Input (URL / SMS / Phone / Document / Audio)
│
▼
┌─────────────────────┐
│ Feature Extraction │ ← dots, entropy, brand check, HTTPS
└─────────┬───────────┘
│
┌─────────▼───────────┐
│ Random Forest (ML) │ ← scikit-learn, feature engineering
└─────────┬───────────┘
│
┌─────────▼───────────┐
│ Semantic Analysis │ ← Google APIs + sentence embeddings
└─────────┬───────────┘
│
┌─────────▼───────────┐
│ Combined Risk Score │ ← Final: SAFE / WARNING / SCAM
└─────────────────────┘


---

## ⚡ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python (Flask + Flask-CORS) |
| Frontend | React + Tailwind CSS |
| Database | MongoDB Atlas |
| Authentication | JWT |
| Machine Learning | Random Forest, Feature Engineering, XAI |
| Semantic / Vector Analysis | Google APIs, sentence-transformers embeddings |
| OCR & Vision | Tesseract.js |
| PDF Processing | PDF.js |
| WHOIS & URL Analysis | python-whois, tldextract |

---

## 🚀 Features

- 🔍 **URL Scanner** — Heuristics + ML + Semantic Analysis  
- 💬 **SMS Detector** — Keyword + vector similarity  
- 📱 **Phone Number Checker** — Blacklist + prefix analysis  
- 📦 **Bulk URL Scan** — Parallel CSV processing  
- 👁️ **Vision AI (OCR)** — Detects screenshot forgeries  
- 🎙️ **Voice Detection** — AI-generated speech pattern analysis  
- 🎓 **Safety Academy** — Gamified cybersecurity education  
- 📊 **Analytics Dashboard** — Real-time scan statistics  
- 🌍 **Live Threat Feed** — Animated threat alerts  

---

## ⚙️ Setup & Installation

### Prerequisites

- Python 3.8+  
- Node.js & npm  
- Git  

### Step 1 — Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/PhisGuard.git
cd PhisGuard
Step 2 — Backend Setup
pip install -r requirements.txt
python app.py
Step 3 — Frontend Setup
cd frontend
npm install
npm start
Step 4 — Open the Application
Visit http://localhost:3000 in your browser
Scan URLs, SMS, phone numbers, documents, or audio
📊 Detection Logic
Check	Weight	Method
Unverified domain	+40	WHOIS
New domain <30 days	+50	WHOIS
Brand impersonation	+45	String matching
Suspicious TLD	+30	TLD check
High entropy	+20	Shannon entropy
HTTP (no SSL)	+15	Protocol check
ML prediction	+25	Random Forest
Semantic / Vector match	+30	Google API embeddings + XAI

Final verdict:

SCAM (≥75)
WARNING (≥40)
SAFE (<40)
📁 Project Structure
PhisGuard/
├── app.py                # Backend + ML + Semantic Analysis
├── frontend/             # React + Tailwind UI
├── templates/            # HTML templates if any
├── requirements.txt
├── README.md
└── ...
👨‍💻 Author

Built as part of a personal project with emphasis on AI-powered cybersecurity and real-world phishing detection.

---

✅ **Instructions to use:**  

1. Open your project folder.  
2. Replace your existing `README.md` with the text above.  
3. Save the file.  
4. Commit and push to GitHub:  

```bash
git add README.md
git commit -m "Update README with new PhisGuard features, ML, XAI, Google API"
git push