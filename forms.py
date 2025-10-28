from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
import re

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required"),
        Length(min=3, max=50, message="Username must be between 3 and 50 characters")
    ])
    
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Please enter a valid email address")
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=6, message="Password must be at least 6 characters long")
    ])
    
    confirm = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password"),
        EqualTo('password', message='Passwords must match')
    ])
    
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        # Check for special characters
        if not re.match("^[a-zA-Z0-9_]+$", username.data):
            raise ValidationError('Username can only contain letters, numbers, and underscores')
    
    def validate_password(self, password):
        # Check if password contains at least one letter and one number
        if not re.search("[a-zA-Z]", password.data):
            raise ValidationError('Password must contain at least one letter')
        if not re.search("[0-9]", password.data):
            raise ValidationError('Password must contain at least one number')