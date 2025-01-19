from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    color = db.Column(db.String(20), nullable=False)
    otp_secret = db.Column(db.String(32))
    recovery_key = db.Column(db.String(50), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
