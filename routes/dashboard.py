from flask import Blueprint, render_template, session, redirect, url_for, flash, request
from models import db, User
import logging

dashboard_bp = Blueprint('dashboard', __name__)

# Protected Dashboard Route
@dashboard_bp.route('/')
def dashboard():
    email = session.get('email')
    if not email:
        flash('Please log in to access your dashboard.', 'warning')
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found. Please log in again.', 'danger')
        session.pop('email', None)
        return redirect(url_for('auth.login'))
    
    users = User.query.all()  # Fetch all users
    return render_template('dashboard.html', user=user, users=users)

# Add User Route
@dashboard_bp.route('/add_user', methods=['POST'])
def add_user():
    email = request.form.get('email')
    color = request.form.get('color')
    new_user = User(email=email, color=color, password='default', recovery_key='default')
    db.session.add(new_user)
    db.session.commit()
    flash('User added successfully!', 'success')
    return redirect(url_for('dashboard.dashboard'))

# Update User Route
@dashboard_bp.route('/update_user/<int:user_id>', methods=['POST'])
def update_user(user_id):
    user = User.query.get(user_id)
    if user:
        user.email = request.form.get('email')
        user.color = request.form.get('color')
        db.session.commit()
        flash('User updated successfully!', 'success')
    return redirect(url_for('dashboard.dashboard'))

# Delete User Route
@dashboard_bp.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'danger')
    return redirect(url_for('dashboard.dashboard'))

# Logout Route
@dashboard_bp.route('/logout')
def logout():
    email = session.get('email')
    if email:
        logging.info(f"User {email} logged out.")
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
