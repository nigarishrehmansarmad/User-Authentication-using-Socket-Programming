import pytest
import bcrypt
import jwt
from app import app, generate_jwt, verify_jwt, DB_FILE
import sqlite3

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def init_test_db():
    # Initialize a fresh test database for isolation
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('DROP TABLE IF EXISTS users')
    c.execute('''
        CREATE TABLE users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def test_register_login(client):
    init_test_db()

    # Register a new user
    response = client.post('/register', data={
        'username': 'testuser',
        'password': 'testpass'
    }, follow_redirects=True)
    assert b'Registration successful' in response.data or response.status_code == 200

    # Attempt to register same user again (should fail)
    response = client.post('/register', data={
        'username': 'testuser',
        'password': 'testpass'
    })
    assert b'Username already exists' in response.data

    # Login with correct credentials
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'testpass'
    }, headers={'X-Requested-With': 'XMLHttpRequest'})
    assert response.status_code == 200
    json_data = response.get_json()
    assert 'token' in json_data
    token = json_data['token']

    # Login with wrong password
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'wrongpass'
    })
    assert b'Invalid username or password' in response.data

    # Verify JWT token
    username = verify_jwt(token)
    assert username == 'testuser'

def test_password_hashing():
    password = 'mypassword'
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    assert bcrypt.checkpw(password.encode(), hashed)
