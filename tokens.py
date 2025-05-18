from itsdangerous import URLSafeTimedSerializer
from flask import current_app

def generate_password_reset_token(username):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(username, salt='password-reset-salt')

def verify_password_reset_token(token, expiration=120):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        username = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except Exception:
        return None
    return username
