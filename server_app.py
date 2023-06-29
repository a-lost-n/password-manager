from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from datetime import datetime, timedelta
from utils import *

app = Flask(__name__)

db_user = "postgres"
db_password = "201810044"
db_host = "127.0.0.1:5432"
db_name = "password_manager"
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://{}:{}@{}/{}'.format(
    db_user, db_password, db_host, db_name)
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = password

class Password(db.Model):
    username = db.Column(db.String(50), primary_key=True)
    site = db.Column(db.String(128), primary_key=True)
    secret = db.Column(db.String(128), nullable=False)

    def __init__(self, username, site, secret):
        self.username = username
        self.site = site
        self.secret = secret

with app.app_context():
    db.create_all()


# Una sesión contiene:
# [0]: El ID del usuario (no puede repetirse)
# [1]: La llave del usuario
# [2]: El nonce del usuario
# [3]: El username activo (si está autenticado)
# [4]: El tiempo de expiración del la llave
active_sessions = []
SESSION_DURATION = 1
PRIVATE_KEY = ec.generate_private_key(ec.SECP384R1())
PUBLIC_KEY = PRIVATE_KEY.public_key()


@app.route("/connect_secure", methods=["POST"])
def connect_secure():
    client_public_key = decode_key(request.json.get("client_public_key"))

    shared_key = PRIVATE_KEY.exchange(ec.ECDH(), client_public_key)
    communication_key = bytes_to_ascii(HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b'',).derive(shared_key))

    session_id = generate_session_id()

    active_sessions.append({"session_id": session_id,
                            "key": communication_key,
                            "nonce": 0,
                            "username": None,
                            "expiration": datetime.now()+timedelta(minutes=SESSION_DURATION)})

    print(communication_key, session_id)
    return jsonify({"server_public_key": encode_key(PUBLIC_KEY),
                    "session_id": session_id})


@app.route("/")
def home():
    return "<p>Server is Active</p>"


@app.route("/username-availability", methods=["POST"])
def username_availability():
    session_id = request.json.get('session_id')
    key, nonce, _ = get_data_from_session(session_id)
    
    username = aes_decrypt(key, nonce, request.json.get('username'))
    user = User.query.filter_by(username=username).first()

    increment_nonce(session_id)
    return jsonify({"success": user is None})


@app.route("/register", methods=["POST"])
def register():
    session_id = request.json.get('session_id')
    key, nonce, _ = get_data_from_session(session_id)

    username = aes_decrypt(key, nonce, request.json.get('username'))
    password = aes_decrypt(key, nonce, request.json.get('password'))
    register_user(username, password)
    if autenticate_user(session_id, username, password): 
        increment_nonce(session_id)     
        return jsonify({'success': True})
    
    return jsonify({"success": False})


@app.route('/login', methods=['POST'])
def login():
    session_id = request.json.get('session_id')
    key, nonce, _ = get_data_from_session(session_id)

    username = aes_decrypt(key, nonce, request.json.get('username'))
    password = aes_decrypt(key, nonce, request.json.get('password'))  

    if autenticate_user(session_id, username, password): 
        increment_nonce(session_id)     
        return jsonify({'success': True})
    
    return jsonify({"success": False})


@app.route('/get_secrets', methods=['POST'])
def get_passwords():
    session_id = request.json.get('session_id')
    key, nonce, username = get_data_from_session(session_id)
    if username is not None:
        passwords = Password.query.filter_by(username=username).all()
        # print(passwords[0].site, passwords[0].secret)
        encrypted_sites = [aes_encrypt(key, nonce, password.site) for password in passwords]
        encrypted_secrets = [aes_encrypt(key, nonce, password.secret) for password in passwords]
        increment_nonce(session_id)
        return jsonify({'success': True,
                        'sites': encrypted_sites,
                        'secrets': encrypted_secrets})
    return jsonify({'success': False})


@app.route("/add", methods=['POST'])
def add_secret():
    session_id = request.json.get('session_id')
    key, nonce, username = get_data_from_session(session_id)

    site = aes_decrypt(key, nonce, request.json.get('site'))
    secret = aes_decrypt(key, nonce, request.json.get('secret'))

    try:
        add_password(username, site, secret)
    except:
        return jsonify({'success': False})
    increment_nonce(session_id)
    return jsonify({'success': True})

@app.route("/delete", methods=['POST'])
def delete_site():
    session_id = request.json.get('session_id')
    key, nonce, username = get_data_from_session(session_id)

    site = aes_decrypt(key, nonce, request.json.get('site'))

    delete_password(username, site)
    increment_nonce(session_id)
    return jsonify({'success': True})

@app.route("/logout", methods=['POST'])
def logout():
    session_id = request.json.get('session_id')
    key, nonce, username = get_data_from_session(session_id)

    target_username = aes_decrypt(key, nonce, request.json.get('username'))
    if username == target_username:
        delete_session(session_id)
        return jsonify({'success': True})
    return jsonify({'success': False})


@app.route("/check_validity", methods=['POST'])
def check_validity():
    session_id = request.json.get('session_id')
    session = search_active_sessions(session_id)
    if session['expiration'] <= datetime.now():
        delete_session(session_id)
        return jsonify({'success': False})
    return jsonify({'success': True})


def register_user(username, password):
    db.session.add(User(username=username, password=password))
    db.session.commit()

def login_user(session_id, username):
    session = search_active_sessions(session_id)
    session['username'] = username

def add_password(username, site, secret):
    db.session.add(Password(username=username, site=site, secret=secret))
    db.session.commit()

def delete_password(username, site):
    password_to_delete = Password.query.filter_by(username=username, site=site).first()
    if password_to_delete:
        db.session.delete(password_to_delete)
        db.session.commit()

# Temporal
def generate_session_id():
    return str(random.randint(0, 2**32))

def search_active_sessions(session_id):
    for session in reversed(active_sessions):
        if session['session_id'] == session_id:
            return session

def get_data_from_session(session_id):
    s = search_active_sessions(session_id)
    return s['key'], s['nonce'], s['username']

def delete_session(session_id):
    for i in range(len(active_sessions)):
        if active_sessions[i]['session_id'] == session_id:
            del active_sessions[i]
            return
            

def increment_nonce(session_id):
    s = search_active_sessions(session_id)
    s['nonce'] += 1

def autenticate_user(session_id, username, password):
    user = User.query.filter_by(username=username).first()
    if user and user.password == password:
        s = search_active_sessions(session_id)
        s['username'] = username
        return True
    return False