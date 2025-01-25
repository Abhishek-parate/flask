from flask import Blueprint, render_template, session, redirect, url_for, flash
from models import User
import logging

dashboard_bp = Blueprint('dashboard', __name__)

# Protected Dashboard Route
@dashboard_bp.route('/dashboard')
def dashboard():
    email = session.get('email')
    if not email:
        flash('Please log in to access your dashboard.', 'warning')
        return redirect(url_for('auth.login'))  # Redirect to login if session is missing

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found. Please log in again.', 'danger')
        session.pop('email', None)
        return redirect(url_for('auth.login'))

    if user.is_verified:
        logging.info(f"User {email} accessed the dashboard.")
        return render_template('dashboard.html', user=user)
    else:
        flash('Your email is not verified. Please check your inbox for OTP verification.', 'warning')
        return redirect(url_for('auth.email_verification'))  # Redirect to email verification

# Logout Route
@dashboard_bp.route('/logout')
def logout():
    email = session.get('email')
    if email:
        logging.info(f"User {email} logged out.")
    session.clear()  # Clear the entire session
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))  # Redirect to login after logout
