# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('ScanHistory', backref='user', lazy=True)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    verdict = db.Column(db.String(50))
    risk_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(50))
    issues = db.Column(db.Text)   # store as JSON string
    warnings = db.Column(db.Text)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)