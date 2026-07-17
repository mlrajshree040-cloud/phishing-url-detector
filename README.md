# 🛡️ CyberShield – AI-Powered Phishing URL Detection System

A hybrid web-application that protects users from malicious URLs using Heuristic Rules, Google Safe Browsing API, and Machine Learning.



## 📌 Overview

CyberShield is a full-stack phishing detection platform that analyzes URLs in real-time. It combines 3 powerful detection layers to deliver a highly accurate risk score (0–100) and an easy-to-understand verdict (SAFE, MEDIUM_RISK, or DANGEROUS). The system is accessible via a Web Dashboard, a Chrome Browser Extension, and a Context-Aware Link Security Analyzer.

## ✨ Key Features

 ### 	Module	Core Responsibility
 
1	🔐 User Authentication	Secure registration, login, bcrypt hashing, and session management (Flask-Login).

2	🧠 Core Detection Engine	4‑Layer hybrid analysis: Preprocessing + Heuristics (10 rules) + Google API + Random Forest ML.

3	🌐 Multi-Channel Access	Web dashboard + Chrome extension + Link Security Analyzer for real-time context-aware validation.

4	📊 Reporting & Analytics	Persistent scan history (SQLite/PostgreSQL), interactive dashboard, and professional PDF report generation (ReportLab).

## 🛠️ Tech Stack
Category	          Tools & Libraries

Backend         	  Python, Flask, Flask-Login, Flask-SQLAlchemy

Machine Learning	  Scikit-learn (Random Forest), joblib, NumPy

Security	          bcrypt (password hashing), Werkzeug

External APIs	      Google Safe Browsing API, WHOIS API

Frontend          	HTML5, CSS3, JavaScript (Jinja2 templating)

Reporting	          ReportLab (PDF generation)

Database	          SQLite (dev) / PostgreSQL (prod)

Extensions	        Chrome Extension APIs, Manifest v3, Content Scripts

## ⚙️ How It Works (The 4‑Layer Detection Engine)

Layer 1 – Preprocessing & Whitelist

  Adds http:// if missing, expands shortened links (up to 5 redirects).

  Checks against a trusted whitelist (e.g., google.com) → immediate SAFE verdict.

Layer 2 – Heuristic Rule Engine (10 Rules)

   Evaluates behavioral indicators: HTTPS status, Domain age, Suspicious keywords, IP address usage, URL shortener, URL length, Special character ratio, '@' symbol, Double slashes, and Homoglyph substitutions.

   Each rule adds or deducts specific points from the base score (100).

Layer 3 – Google Safe Browsing API

   Validates the URL against Google's global threat database (Malware, Social Engineering, Unwanted Software).

   If flagged, deducts -50 points from the risk score.

Layer 4 – Machine Learning Classifier

   Extracts 9 numerical features (length, dot count, HTTPS flag, IP flag, '@' flag, double-slash flag, keyword count, slash ratio, domain age).

   Loads a pre-trained Random Forest model (phishing_model.pkl).

   Outputs a Phishing Probability (e.g., 0.87) and a Prediction (0 = Legitimate, 1 = Phishing).

   If phishing is predicted, deducts an additional -30 points.

  Final Scoring & Verdict

   Combines all adjustments → final score clamped between 0–100.

Mapped to:

🟢 SAFE (≥ 70)

🟡 MEDIUM_RISK (40–69)

🔴 DANGEROUS (< 40)

## 🚀 Getting Started (Installation & Setup)

Follow these steps to run the project locally:

 1. Clone the Repository

git clone https://github.com/mlrajshree040-cloud/phishing-url-detector.git
cd phishing-url-detector

 1. Create a Virtual Environment
bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

 3. Install Dependencies
bash
pip install -r requirements.txt
 4. Set Up Environment Variables
Create a .env file in the root directory and add your API keys:

env
SECRET_KEY=your_secret_key
DATABASE_URL=sqlite:///phishing.db
GOOGLE_SAFE_BROWSING_KEY=your_google_api_key
WHOIS_API_KEY=your_whois_api_key  # (Optional, if required)

5. Initialize the Database
bash
python
>>> from app import db
>>> db.create_all()
>>> exit()

6. Run the Application
bash
python app.py
The application will be available at: http://127.0.0.1:5000


## 🔌 Deployment Channels
🌐 Web Dashboard: Paste URLs directly into the browser interface for detailed reports.

🔌 Chrome Extension: Right‑click any link or use the toolbar for instant scanning.

🔍 Link Security Analyzer: Automatically validates links embedded in emails, documents, or web pages to detect hidden redirections.

## 🤝 Contributing
Contributions are welcome! If you'd like to improve CyberShield:

Fork the repository.

Create a new branch (git checkout -b feature/AmazingFeature).

Commit your changes (git commit -m 'Add some AmazingFeature').

Push to the branch (git push origin feature/AmazingFeature).

Open a Pull Request.

## 📄 License
This project is open-source and available under the MIT License.

## 📬 Contact
Project Maintainer: Rajshree
GitHub: mlrajshree040-cloud
Project Link: https://github.com/mlrajshree040-cloud/phishing-url-detector

## ⭐️ If you found this project helpful, please give it a star on GitHub!

