Phishing URL Detector
🚨 The Problem
Phishing attacks are one of the most common cybersecurity threats today. Attackers send fake emails or create fraudulent websites that look legitimate (bank login, PayPal, social media) to trick users into clicking malicious links. Once clicked, users may:
Lose sensitive personal information (passwords, credit card numbers)
Become victims of bank fraud or account takeover
Install malware on their devices
Traditional antivirus software is often reactive – it only detects known threats. Many phishing URLs are brand new, short‑lived, and designed to bypass simple filters.
The challenge: Build a tool that can analyse any URL in real time and tell the user whether it is safe or suspicious before they click.

 My Solution – Multi‑Layer Phishing URL Detector
I developed a web‑based Phishing URL Detector that evaluates a URL using three independent detection layers:
Heuristic (Rule‑Based) Engine – checks 10+ suspicious patterns (HTTPS, domain age, keywords, homoglyphs, IP address, @ symbol, etc.)
Real‑Time Threat Intelligence APIs – Google Safe Browsing API (and optionally VirusTotal) for up‑to‑date blacklist checking
Machine Learning Model – a Random Forest classifier trained on thousands of URLs to recognise complex phishing patterns 
The tool outputs a risk score (0–100), a colour‑coded verdict (🟢 SAFE / 🟡 MEDIUM RISK / 🔴 DANGEROUS), and a detailed breakdown of issues and warnings. It also generates a professional PDF report that can be downloaded and shared.

 
🚀 What Makes This Project Exciting (Key Improvements Over a Basic Version)
Basic Version                   	My Improved Version
Simple “SAFE / SUSPICIOUS” verdict           	Risk score (0–100) + three‑level verdict (Safe / Medium Risk / Dangerous)
Only heuristic rules (e.g., HTTPS, keywords)	Three layers: heuristics + Google Safe Browsing API + Machine Learning
No ML                                          	Random Forest model trained on real phishing datasets, achieving 92% accuracy
No downloadable output	                        PDF report generation with full scan details using ReportLab
No visual feedback	                            Progress bar and colour‑coded risk badges
Basic frontend	                                Dynamic HTML/CSS/JS with async fetch, loading spinner, and responsive design
Hardcoded API keys                            	Environment variables for secure API key management
Minimal detection rules	10+ advanced heuristics: homoglyph detection (g00gle.com), @ symbol, double slashes, URL shorteners, domain age, etc.
These improvements turn a simple “link checker” into a real‑world security tool suitable for a portfolio, internship, or even a small business use case.

🛠️ Technologies Used
Category	             Tools & Libraries
Backend	              Python 3.12, Flask, Gunicorn (production server)
Heuristics          	python‑whois, requests, tld, regex, urllib.parse
Machine Learning	  scikit‑learn (Random Forest), pandas, numpy, joblib
APIs	              Google Safe Browsing API (free tier), VirusTotal API (optional)
Frontend	          HTML5, CSS3, JavaScript (ES6), Fetch API
Reporting             reportlab (PDF generation)
Deployment	          Git, GitHub, Render (free cloud hosting)
Environment	           venv, pip, python‑dotenv

  project
phishing-url-detector/
├── app.py                     # Flask main application
├── requirements.txt           # Dependencies
├── train_model.py             # Script to train the ML model
├── utils/
│   ├── scanner.py             # Heuristic scanner + API integration
│   ├── feature_extraction.py  # Convert URL → feature vector (9 features)
│   └── report_generator.py    # PDF report creation
├── templates/
│   └── index.html             # Web interface
├── static/
│   ├── style.css              # Styling (risk badges, progress bar)
│   └── script.js              # Frontend logic (fetch, display, download PDF)
└── phishing_model.pkl         # Trained ML model (generated)

To Run :

git clone https://github.com/mlrajshree040-cloud/phishing-url-detector.git
cd phishing-url-detector
python -m venv venv
source venv/bin/activate   # or venv\Scripts\activate on Windows
pip install -r requirements.txt
python train_model.py      # trains the ML model (optional, but recommended)
python app.py
