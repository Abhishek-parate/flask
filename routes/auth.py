from flask import Blueprint, render_template, redirect, url_for, flash, session
from models import db, User
from forms import RegisterForm, OTPForm, LoginForm
from flask_bcrypt import Bcrypt
import pyotp, random, string
from flask_mail import Mail, Message
from datetime import datetime, timedelta  # Added timedelta for OTP expiry

import time

auth_bp = Blueprint('auth', __name__)
bcrypt = Bcrypt()
mail = Mail()

# Helper: Generate Random Recovery Key
def generate_recovery_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

# Registration Route
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if email already exists
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered. Please log in.', 'warning')
            return redirect(url_for('auth.login'))

        # Create a new user (unverified)
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        recovery_key = generate_recovery_key()
        otp_secret = pyotp.random_base32()

        new_user = User(
            email=form.email.data,
            password=hashed_password,
            color=form.color.data,
            otp_secret=otp_secret,
            recovery_key=recovery_key,
            is_verified=False
        )
        db.session.add(new_user)
        db.session.commit()

        # Send OTP Email
        otp = pyotp.TOTP(otp_secret).now()
        
        html_content = f"""
        <html>
        <body>
            <h2>Your OTP for Registration</h2>
            <p>Thank you for registering with us. Please use the OTP below to verify your email address:</p>
            <h3 style="color: #4CAF50; font-size: 24px;">{otp}</h3>
            <p>This OTP will expire in 30 seconds. If you did not request this, please ignore this message.</p>
            <br>
            <p>Best Regards,<br>3 Way Auth</p>
        </body>
        </html>
        """
        
        try:
            msg = Message('Email Verification OTP', recipients=[form.email.data])
            msg.body = f"Your OTP for registration is: {otp}"  # Plain text body as a fallback
            msg.html = html_content  # HTML body for email
            mail.send(msg)
            flash('Registration successful! Verify your email using the OTP sent.', 'info')
        except Exception as e:
            flash(f'Error sending email. Please try again later. Error: {str(e)}', 'danger')
            return redirect(url_for('auth.register'))

        # Save email in session for verification
        session['email'] = form.email.data
        return redirect(url_for('auth.email_verification'))
    return render_template('register.html', form=form)

# Email Verification Route
@auth_bp.route('/email_verification', methods=['GET', 'POST'])
def email_verification():
    form = OTPForm()

    # Get email from session
    email = session.get('email')  # Retrieve email from session
    if not email:
        flash('Session expired. Please register again.', 'danger')
        return redirect(url_for('auth.register'))

    # Get user object from the database using the email
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found. Please register again.', 'danger')
        return redirect(url_for('auth.register'))

    if form.validate_on_submit():
        totp = pyotp.TOTP(user.otp_secret)
        otp = form.otp.data.strip()  # Remove any leading/trailing spaces
        generated_otp = totp.now()

        # Debugging Logs for OTP generation and user input
        print(f"Generated OTP: {generated_otp}")  # Log generated OTP
        print(f"Entered OTP: {otp}")  # Log entered OTP
        print(f"OTP Secret: {user.otp_secret}")  # Check if the secret is the same

        # Check if the generated OTP matches the entered OTP
        if generated_otp == otp:
            # OTP verified successfully, mark user as verified
            user.is_verified = True
            db.session.commit()

            # Send Recovery Key Email
            try:
                msg = Message('Account Recovery Key', recipients=[user.email])
                msg.body = f"Your recovery key is: {user.recovery_key}"
                mail.send(msg)
            except Exception as e:
                flash(f'Error sending recovery key email. Please try again later. Error: {str(e)}', 'danger')
                return redirect(url_for('auth.email_verification'))

            flash('Email verified successfully. Please log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(f'Invalid OTP. Please try again. Generated OTP: {generated_otp}', 'danger')

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
