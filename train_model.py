# train_model.py
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
from utils.feature_extraction import extract_features

print("Loading dataset...")
try:
    df = pd.read_csv('url_data.csv')
except FileNotFoundError:
    print("❌ Error: 'url_data.csv' not found. Please create it with 'url' and 'label' columns.")
    exit(1)

if 'url' not in df.columns or 'label' not in df.columns:
    print("❌ Error: CSV must contain 'url' and 'label' columns.")
    exit(1)


print("Extracting features from URLs...")
feature_list = []
for url in df['url']:
    features = extract_features(url)   
    feature_list.append(features)

X = np.array(feature_list)
y = df['label'].values

print(f"Feature matrix shape: {X.shape}")
print(f"Labels shape: {y.shape}")

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


print("Training Random Forest model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)


y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

joblib.dump(model, 'phishing_model.pkl')
print("✅ Model saved as 'phishing_model.pkl'")
df = pd.read_csv('url_data.csv', delimiter='|')