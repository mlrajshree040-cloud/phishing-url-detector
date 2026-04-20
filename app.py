# app.py
from flask import Flask, render_template, request, jsonify, send_file
from utils.scanner import PhishingScanner
import joblib
import numpy as np
from utils.feature_extraction import extract_features
from utils.report_generator import generate_pdf_report

app = Flask(__name__)

# Load the ML model globally (if available)
try:
    ml_model = joblib.load('phishing_model.pkl')
    print("✅ ML Model loaded successfully.")
except FileNotFoundError:
    print("⚠️ ML Model not found. Run train_model.py first. Continuing without ML.")
    ml_model = None

# Initialize heuristic scanner
heuristic_scanner = PhishingScanner()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url', '').strip()
    if not url:
        return jsonify({'error': 'Please enter a URL'}), 400

    # 1. Get heuristic results
    heuristic_result = heuristic_scanner.scan(url)

    # 2. Get ML prediction (if model is available)
    ml_prediction = None
    ml_probability = None
    if ml_model is not None:
        try:
            features = extract_features(url)
            feature_array = np.array(features).reshape(1, -1)
            ml_prediction = int(ml_model.predict(feature_array)[0])  # 0 or 1
            ml_probability = float(ml_model.predict_proba(feature_array)[0][1])
        except Exception as e:
            print(f"❌ ML Prediction Error: {e}")

    # 3. Combine verdicts
    final_verdict = heuristic_result['verdict']
    if ml_prediction == 1:
        final_verdict = "DANGEROUS"

    # 4. Update result with ML info
    heuristic_result['verdict'] = final_verdict
    heuristic_result['ml_prediction'] = ml_prediction
    heuristic_result['ml_probability'] = ml_probability

    return jsonify(heuristic_result)

@app.route('/download_report', methods=['POST'])
def download_report():
    url = request.form.get('url', '').strip()
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    # Re-scan the URL to get fresh results
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
            print(f"❌ ML error in report: {e}")

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

if __name__ == '__main__':
    app.run(debug=True, port=5001)