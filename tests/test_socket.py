import pytest
from app import app, socketio, generate_jwt
from flask_socketio import SocketIOTestClient

@pytest.fixture
def test_client():
    app.config['TESTING'] = True
    client = app.test_client()
    yield client

@pytest.fixture
def socket_client():
    # Flask-SocketIO test client
    test_client = socketio.test_client(app)
    yield test_client
    test_client.disconnect()

def test_socket_connect_authorized():
    token = generate_jwt('testuser')

    # Connect with valid token
    client = socketio.test_client(app, auth={'token': token})
    assert client.is_connected()

    # Receive server_response event on connect
    received = client.get_received()
    messages = [msg for msg in received if msg['name'] == 'server_response']
    assert any('Connected as testuser' in msg['args'][0]['message'] for msg in messages)

    client.disconnect()

def test_socket_connect_unauthorized():
    # Connect without token should fail
    client = socketio.test_client(app, auth={})
    assert not client.is_connected()

def test_get_secret_event():
    token = generate_jwt('testuser')
    client = socketio.test_client(app, auth={'token': token})
    assert client.is_connected()

    # Emit 'get_secret' event with valid token
    client.emit('get_secret', {'token': token})
    received = client.get_received()
    secret_msgs = [msg for msg in received if msg['name'] == 'secret_message']
    assert len(secret_msgs) == 1
    assert 'Secret Code' in secret_msgs[0]['args'][0]['message']

    client.disconnect()
