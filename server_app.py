from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from datetime import datetime, timedelta
from utils import *
import binascii

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


with app.app_context():
    db.create_all()


# Una sesión es una 3-tupla que contiene:
# [0]: El nombre del usuario (no puede repetirse)
# [1]: La llave del usuario
# [2]: El tiempo de expiración del la llave
active_sessions = []
active_users = []

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
    key = get_key_from_session(session_id)
    iv = request.json.get('iv')
    
    username = aes_decrypt(key, iv, request.json.get('username'))
    user = User.query.filter_by(username=username).first()
    return jsonify({"success": user is None})


@app.route("/register", methods=["POST"])
def register():
    try:
        session_id = request.json.get('session_id')
        key = get_key_from_session(session_id)
        iv = request.json.get('iv')

        username = aes_decrypt(key, iv, request.json.get('username'))
        password = aes_decrypt(key, iv, request.json.get('password'))
        register_user(username, password)
        success = True
    except:
        success = False
    return jsonify({"success": success})


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template("login.html")
    elif request.method == 'POST':
        session_id = request.json.get('session_id')
        key = get_key_from_session(session_id)
        iv = request.json.get('iv')

        username = aes_decrypt(key, iv, request.json.get('username'))
        password = aes_decrypt(key, iv, request.json.get('password'))

        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            user_secret = generate_secret()
            active_users.append({'secret': user_secret, 'username': username})

            encrypted_user_secret = aes_encrypt(key, iv, user_secret)
            return jsonify({'user_secret': encrypted_user_secret,
                            'success': True})
        else:
            return jsonify({"success": False})

def register_user(username, password):
    db.session.add(User(username=username, password=password))
    db.session.commit()

# Temporal
def generate_session_id():
    return str(random.randint(0, 2**32))

def search_active_sessions(session_id):
    for session in reversed(active_sessions):
        if session['session_id'] == session_id:
            return session

def get_key_from_session(session_id):
    return search_active_sessions(session_id)['key']
