import jwt
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_socketio import SocketIO, emit, disconnect
import sqlite3
import bcrypt
import secrets
from tokens import generate_password_reset_token, verify_password_reset_token
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'abc123'
socketio = SocketIO(app, cors_allowed_origins="*")  # Allow CORS for testing

DB_FILE = 'users.db'
JWT_SECRET = 'nigarish_uroosha'  # Use a strong secret key in production

# Initialize DB with password as BLOB (bytes)
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password BLOB NOT NULL
        );
    ''')
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def generate_jwt(username):
    payload = {
        'sub': username,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(seconds=10)  # Token valid for 1 hour
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token

def verify_jwt(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload['sub']
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def generate_secret_message(username):
    phrases = [
        "Keep going, {user}! Your journey is unique.",
        "Hey {user}, remember: every day is a new chance.",
        "You, {user}, are capable of amazing things.",
        "{user}, your creativity knows no bounds!",
        "Stay curious, {user}, and keep learning.",
    ]
    import random
    phrase = random.choice(phrases).replace("{user}", username)
    random_code = secrets.token_hex(4)
    return f"{phrase} [Secret Code: {random_code}]"

# Routes

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip().lower()  # Normalize username to lowercase
        password = request.form['password'].strip()
        if not username or not password:
            flash('Please fill in both fields.')
            return render_template('register.html')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            flash('Username already exists.')
            conn.close()
            return render_template('register.html')

        # Hash password as bytes and store as BLOB
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed))
        conn.commit()
        conn.close()

        flash('Registration successful! Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','').strip().lower()  # Normalize username to lowercase
        password = request.form['password'].strip()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        # user['password'] is bytes, so no encoding needed here
        if user and bcrypt.checkpw(password.encode(), user['password']):
            session['username'] = username
            token = generate_jwt(username)
            flash('Login successful!')
            return jsonify({'token': token, 'redirect': url_for('dashboard')})
        else:
            return jsonify({'error': 'Invalid username or password'}), 401

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Please login first.')
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    username = session.pop('username', None)
    return render_template('logout.html', username=username)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        app.logger.debug(f"Forgot password requested for username: {username}")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            token = generate_password_reset_token(username)
            reset_url = url_for('reset_password', token=token, _external=True)
            return render_template('forgot_password.html', reset_url=reset_url)
        else:
            flash('Username not found.')
            app.logger.debug(f"Forgot password requested for username: '{username}'")
            
            app.logger.debug(f"User found: {user}")

            return render_template('forgot_password.html')

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    username = verify_password_reset_token(token)
    if not username:
        flash('The password reset link is invalid or has expired.')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if password != confirm_password:
            flash('Passwords do not match.')
            return render_template('reset_password.html', token=token)

        # Hash new password as bytes and store as BLOB
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_pw, username))
        conn.commit()
        conn.close()

        flash('Your password has been reset successfully. Please log in.')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# SocketIO events

@socketio.on('connect')
def socket_connect(auth):
    token = None
    if auth and 'token' in auth:
        token = auth['token']
    if not token:
        disconnect()
        return
    username = verify_jwt(token)
    if not username:
        disconnect()
        return
    emit('server_response', {'message': f'Connected as {username}'})

@socketio.on('get_secret')
def handle_get_secret(data):
    token = data.get('token')
    username = verify_jwt(token)
    if not username:
        emit('secret_message', {'message': 'Unauthorized'})
        disconnect()
        return
    msg = generate_secret_message(username)
    emit('secret_message', {'message': msg})

@app.context_processor
def inject_current_date():
    return {
        'current_date': datetime.now().strftime("%A, %B %d, %Y")
    }

if __name__ == '__main__':
    #init_db()
    if not os.path.exists(DB_FILE):
        init_db()
    socketio.run(app, debug=True)



