from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegisterForm
from models import db, User

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db.init_app(app)

with app.app_context():
    db.create_all()


# Landing Page / Login
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username_or_email = request.form['username_or_email']
        password = request.form['password']
        
        # Check if fields are empty
        if not username_or_email or not password:
            flash("Please fill in all fields", "danger")
            return render_template('index.html')
        
        user = User.query.filter((User.username==username_or_email) | (User.email==username_or_email)).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username/email or password. Please try again.", "danger")
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if username already exists
        existing_username = User.query.filter_by(username=form.username.data).first()
        if existing_username:
            flash('Username already taken. Please choose a different username.', 'danger')
            return render_template('register.html', form=form)
        
        # Check if email already exists
        existing_email = User.query.filter_by(email=form.email.data).first()
        if existing_email:
            flash('Email already registered. Please use a different email or login.', 'danger')
            return render_template('register.html', form=form)
        
        # Check password strength
        if len(form.password.data) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('register.html', form=form)
        
        # Create new user
        try:
            hashed_pw = generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            return render_template('register.html', form=form)
    
    # Display form validation errors
    if form.errors:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field.capitalize()}: {error}", 'danger')
    
    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    username = session.get('username', 'User')
    session.clear()
    flash(f'Goodbye, {username}! You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('index'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/home')
def home():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('index'))
    return render_template('home.html')

@app.route('/about')
def about():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('index'))
    return render_template('about.html')

@app.route('/activity')
def activity():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('index'))
    return render_template('activity.html')

@app.route('/act1', methods=['GET', 'POST'])
def act1():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('index'))
    name = None
    if request.method == 'POST':
        name = request.form.get('name')
        if name:
            flash(f'Welcome, {name}!', 'success')
        else:
            flash('Please enter your name.', 'danger')
    return render_template('act1.html', name=name)

@app.route('/act2')
def act2():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('index'))
    return render_template('act2.html')

@app.route('/act3')
def act3():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('index'))
    return render_template('act3.html')

if __name__ == '__main__':
    app.run(debug=True)