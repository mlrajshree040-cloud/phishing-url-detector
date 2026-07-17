# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_babel import Babel, gettext as _
import json
import joblib
import numpy as np
from utils.scanner import PhishingScanner
from utils.feature_extraction import extract_features
from utils.report_generator import generate_pdf_report
import os

# ------------------------------
# App configuration
# ------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.jinja_env.add_extension('jinja2.ext.i18n')
# ------------------------------
# Babel Internationalization
# ------------------------------
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_SUPPORTED_LOCALES'] = ['en', 'hi', 'es', 'fr', 'ar']
babel = Babel(app)

@babel.localeselector
def get_locale():
    # Check for language preference in the URL arguments
    lang = request.args.get('lang')
    if lang in app.config['BABEL_SUPPORTED_LOCALES']:
        session['lang'] = lang
        return lang
    # Check for language stored in the user's session
    return session.get('lang', app.config['BABEL_DEFAULT_LOCALE'])



# ------------------------------
# Database and Login setup
# ------------------------------
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ------------------------------
# Database Models
# ------------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    scans = db.relationship('ScanHistory', backref='user', lazy=True)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    scan_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    verdict = db.Column(db.String(50))
    risk_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(20))
    issues = db.Column(db.Text)      # JSON string
    warnings = db.Column(db.Text)    # JSON string

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ------------------------------
# Load ML model (optional)
# ------------------------------
try:
    ml_model = joblib.load('phishing_model.pkl')
    print("✅ ML Model loaded successfully.")
except FileNotFoundError:
    print("⚠️ ML Model not found. Run train_model.py first. Continuing without ML.")
    ml_model = None

heuristic_scanner = PhishingScanner()

# ------------------------------
# Authentication Routes
# ------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed = generate_password_hash(password)
        user = User(username=username, email=email, password_hash=hashed)
        try:
            db.session.add(user)
            db.session.commit()
            flash(_('Registration successful! Please log in.'), 'success')
            return redirect(url_for('login'))
        except:
            flash(_('Username or email already exists.'), 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(f"Login attempt: {username}")   # temporary debug
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            print("Login successful, redirecting...")   # debug
            return redirect(url_for('index'))
        else:
            print("Login failed")   # debug
            flash(_('Invalid username or password'), 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ------------------------------
# Scanning & Report Routes
# ------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url', '').strip()
    if not url:
        return jsonify({'error': _('Please enter a URL')}), 400

    # 1. Heuristic scan
    heuristic_result = heuristic_scanner.scan(url)

    # 2. ML prediction (if available)
    ml_prediction = None
    ml_probability = None
    if ml_model is not None:
        try:
            features = extract_features(url)
            feature_array = np.array(features).reshape(1, -1)
            ml_prediction = int(ml_model.predict(feature_array)[0])
            ml_probability = float(ml_model.predict_proba(feature_array)[0][1])
        except Exception as e:
            print(f"❌ ML Prediction Error: {e}")

    # 3. Combine verdicts
    final_verdict = heuristic_result['verdict']
    if ml_prediction == 1:
        final_verdict = "DANGEROUS"
    heuristic_result['verdict'] = final_verdict
    heuristic_result['ml_prediction'] = ml_prediction
    heuristic_result['ml_probability'] = ml_probability

    # 4. Save history if user is logged in
    if current_user.is_authenticated:
        history = ScanHistory(
            user_id=current_user.id,
            url=url,
            verdict=final_verdict,
            risk_score=heuristic_result['risk_score'],
            risk_level=heuristic_result['risk_level'],
            issues=json.dumps(heuristic_result.get('issues', [])),
            warnings=json.dumps(heuristic_result.get('warnings', []))
        )
        db.session.add(history)
        db.session.commit()

    return jsonify(heuristic_result)

@app.route('/download_report', methods=['POST'])
def download_report():
    url = request.form.get('url', '').strip()
    if not url:
        return jsonify({'error': _('No URL provided')}), 400

    # Re‑scan the URL
    heuristic_result = heuristic_scanner.scan(url)

    # Get ML prediction if model exists
    ml_prediction = None
    ml_probability = None
    if ml_model is not None:
        try:
            features = extract_features(url)
            feature_array = np.array(features).reshape(1, -1)
            ml_prediction = int(ml_model.predict(feature_array)[0])
            ml_probability = float(ml_model.predict_proba(feature_array)[0][1])
        except Exception as e:
            print(f"ML error in report: {e}")

    # Combine verdicts
    final_verdict = heuristic_result['verdict']
    if ml_prediction == 1:
        final_verdict = "DANGEROUS"
    heuristic_result['verdict'] = final_verdict
    heuristic_result['ml_prediction'] = ml_prediction
    heuristic_result['ml_probability'] = ml_probability

    # Generate PDF
    try:
        pdf_filename = generate_pdf_report(url, heuristic_result)
        return send_file(pdf_filename, as_attachment=True, download_name=pdf_filename)
    except Exception as e:
        return jsonify({'error': f'Failed to generate report: {str(e)}'}), 500

@app.route('/history')
@login_required
def history():
    scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.scan_date.desc()).all()
    return render_template('index.html', scans=scans)

@app.route('/landing')
def landing():
    return render_template('landing.html')

# ------------------------------
# Create database tables
# ------------------------------
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=5001)