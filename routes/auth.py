from flask import Blueprint, render_template, redirect, url_for, flash, session
from models import db, User
from forms import RegistrationForm, LoginForm, OTPVerificationForm
from flask_bcrypt import Bcrypt
import pyotp, random, string
from flask_mail import Mail, Message

auth_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt()
mail = Mail()

# Generate Random Recovery Key
def generate_recovery_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

# Registration Route
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        recovery_key = generate_recovery_key()
        otp_secret = pyotp.random_base32()
        
        new_user = User(
            email=form.email.data, 
            password=hashed_password, 
            color=form.color.data, 
            otp_secret=otp_secret, 
            recovery_key=recovery_key
        )
        db.session.add(new_user)
        db.session.commit()

        # Send Verification Email
        otp = pyotp.TOTP(otp_secret).now()
        msg = Message('Email Verification OTP', recipients=[form.email.data])
        msg.body = f"Your OTP for registration: {otp}"
        mail.send(msg)

        flash('Please verify your email using the OTP sent.', 'info')
        session['email'] = form.email.data
        return redirect(url_for('auth.email_verification'))
    return render_template('register.html', form=form)

# Email Verification
@auth_bp.route('/email_verification', methods=['GET', 'POST'])
def email_verification():
    form = OTPVerificationForm()
    email = session.get('email')
    user = User.query.filter_by(email=email).first()
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(form.otp.data):
            user.is_verified = True
            db.session.commit()
            flash('Email successfully verified. Please log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Invalid OTP, please try again.', 'danger')
    return render_template('email_verification.html', form=form)

# Login Route
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if not user.is_verified:
                flash('Please verify your email first.', 'warning')
                return redirect(url_for('auth.email_verification'))
            session['email'] = user.email
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard.dashboard'))  # Redirecting to dashboard after successful login
        flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)
