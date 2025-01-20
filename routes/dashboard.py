from flask import Blueprint, render_template, session, redirect, url_for, flash
from models import User

dashboard_bp = Blueprint('dashboard', __name__)

# Protected Dashboard Route
@dashboard_bp.route('/dashboard')
def dashboard():
    if 'email' not in session:
        flash('Please log in to access your dashboard', 'warning')
        return redirect(url_for('auth.login'))  # This is correct for login route

    user = User.query.filter_by(email=session['email']).first()

    if user and user.is_verified:
        return render_template('dashboard.html')
    else:
        flash('Your email is not verified. Please check your inbox for OTP verification.', 'warning')
        return redirect(url_for('auth.email_verification'))  # Correct for email verification route

# Logout Route
@dashboard_bp.route('/logout')
def logout():
    session.pop('email', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))  # Correct usage of 'auth.login'
