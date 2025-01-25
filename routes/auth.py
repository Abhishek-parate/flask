from flask import Blueprint, render_template, redirect,request, url_for, flash, session
from models import db, User
from forms import RegisterForm, OTPForm, LoginForm, SelectColorForm
from flask_bcrypt import Bcrypt
import pyotp, random, string
from flask_mail import Mail, Message
from datetime import datetime
import logging


auth_bp = Blueprint('auth', __name__)  # Blueprint
bcrypt = Bcrypt()
mail = Mail()

# Helper: Generate Random Recovery Key
def generate_recovery_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=12))

# Helper: Send Email
def send_email(subject, recipient, body, html=None):
    try:
        msg = Message(subject, recipients=[recipient])
        msg.body = body
        if html:
            msg.html = html
        mail.send(msg)
        return True
    except Exception as e:
        flash(f'Error sending email: {str(e)}', 'danger')
        return False

# Helper: Generate OTP
def generate_otp(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()

# Registration Route
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered. Please log in.', 'warning')
            return redirect(url_for('auth.login'))

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

        otp = generate_otp(otp_secret)
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
        if not send_email('Email Verification OTP', form.email.data, f"Your OTP is: {otp}", html_content):
            return redirect(url_for('auth.register'))

        session['email'] = form.email.data
        flash('Registration successful! Verify your email using the OTP sent.', 'info')
        return redirect(url_for('auth.email_verification'))
    return render_template('register.html', form=form)

# Email Verification Route
@auth_bp.route('/email_verification', methods=['GET', 'POST'])
def email_verification():
    form = OTPForm()
    email = session.get('email')
    if not email:
        flash('Session expired. Please register again.', 'danger')
        return redirect(url_for('auth.register'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found. Please register again.', 'danger')
        return redirect(url_for('auth.register'))

    if form.validate_on_submit():
        totp = pyotp.TOTP(user.otp_secret)
        otp = form.otp.data.strip()

        if totp.verify(otp, valid_window=1):
            user.is_verified = True
            db.session.commit()

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
            flash('Invalid or expired OTP. Please try again.', 'danger')

    return render_template('email_verification.html', form=form)

# Login Route (using `auth_bp.route`)
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('auth.select_color'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html', form=form)


@auth_bp.route('/select-color', methods=['GET', 'POST'])
def select_color():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in first.", "warning")
        return redirect(url_for('auth.login'))

    form = SelectColorForm()

    if form.validate_on_submit():
        selected_color = form.color.data.strip()
        user = User.query.get(user_id)

        if user and selected_color.lower() == user.color.lower():
            try:
                # Generate OTP
                totp = pyotp.TOTP(user.otp_secret)
                otp = totp.now()

                # Send OTP email
                subject = "Your OTP for Color Verification"
                body = f"Your OTP is: {otp}"
                html_content = f"""
                <html>
                <body>
                    <h2>Your OTP for Color Verification</h2>
                    <p>You selected the correct color. Please use the OTP below to verify your identity:</p>
                    <h3 style="color: #4CAF50; font-size: 24px;">{otp}</h3>
                    <p>This OTP will expire in 5 minutes. If you did not request this, please ignore this message.</p>
                    <br>
                    <p>Best Regards,<br>3 Way Auth</p>
                </body>
                </html>
                """
                if send_email(subject, user.email, body, html_content):
                    flash('Color selected successfully! Please check your email for the OTP.', 'info')
                    return redirect(url_for('auth.verify_otp'))
                else:
                    flash('Error sending OTP email. Please try again later.', 'danger')
            except Exception as e:
                logging.error(f"Error during OTP generation or email sending for user {user.email}: {str(e)}")
                flash("An error occurred while generating or sending the OTP. Please try again.", "danger")
        else:
            flash('Incorrect color selection. Please try again.', 'danger')

    return render_template('select_color.html', form=form)


@auth_bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in first.", "warning")
        return redirect(url_for('auth.login'))

    form = OTPForm()
    user = User.query.get(user_id)
    
    if not user:
        flash("User not found. Please log in again.", "danger")
        session.pop('user_id', None)
        return redirect(url_for('auth.login'))

    if form.validate_on_submit():
        entered_otp = form.otp.data.strip()

        # Use pyotp to verify OTP
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(entered_otp, valid_window=1):  # Allow a slight time window
            # Clear session data and log the user in
            session.pop('user_id', None)
            session['email'] = user.email  # Store user email for dashboard access
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard.dashboard'))  # Redirect to the dashboard route
        else:
            flash('Invalid or expired OTP. Please try again.', 'danger')

    return render_template('verify_otp.html', form=form)
