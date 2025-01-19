from flask import Flask
from models import db
from config import Config
from routes.auth import auth_bp, bcrypt, mail

app = Flask(__name__)
app.config.from_object(Config)

# Initialize Extensions
db.init_app(app)
bcrypt.init_app(app)
mail.init_app(app)

# Register Blueprints
app.register_blueprint(auth_bp)

# Create Database Tables
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
