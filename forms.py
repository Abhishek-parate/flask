from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp, ValidationError
from models import User

# Custom validator to check if email already exists in the database
def email_exists(form, field):
    if User.query.filter_by(email=field.data).first():
        raise ValidationError('Email is already registered. Please log in.')

# Custom validator for password strength (at least one number, one letter, one special character)
def password_strength(form, field):
    password = field.data
    if not any(char.isdigit() for char in password):
        raise ValidationError('Password must contain at least one digit.')
    if not any(char.isalpha() for char in password):
        raise ValidationError('Password must contain at least one letter.')
    if not any(char in '!@#$%^&*()_+' for char in password):
        raise ValidationError('Password must contain at least one special character (!@#$%^&*()_+).')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), email_exists])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6), password_strength])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    color = StringField('Favorite Color (Hex Code)', validators=[DataRequired(), Length(min=3, max=7), Regexp(r'^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$', message='Please enter a valid hex color code.')])
    submit = SubmitField('Register')

class OTPForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify OTP')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Login')


class SelectColorForm(FlaskForm):
    color = StringField('Favorite Color (Hex Code)', validators=[DataRequired(), Length(min=3, max=7), Regexp(r'^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$', message='Please enter a valid hex color code.')])
    submit = SubmitField('Submit')


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    recovery_key = StringField('Recovery Key', validators=[DataRequired()])
    submit = SubmitField('Verify')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=6), password_strength])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Reset Password')
