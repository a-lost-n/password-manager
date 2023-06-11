from flask import Flask, flash, render_template, request, redirect, url_for
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from utils import *
import requests
import binascii

SERVER_URL = "127.0.0.1:5002"
PRIVATE_KEY = ec.generate_private_key(ec.SECP384R1())
PUBLIC_KEY = PRIVATE_KEY.public_key()
communication_key = None
session_id = None
user_secret = None

app = Flask(__name__)
    

@app.route("/", methods=["GET"])
def home():
    return render_template("home.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    elif request.method == "POST":
        if connect():
            username = request.form.get("username")
            password = request.form.get("password")
            re_password = request.form.get("re_password")

            # Pruebas de integridad
            if len(password) < 8 or len(password) > 16:
                error = "Password should contain from 8 to 16 characters"
                return render_template("register.html",error=error)
            if password != re_password:
                error = "Passwords don't match"
                return render_template("register.html",error=error)
            
            iv = generate_iv()
            encrypted_username = aes_encrypt(communication_key, iv, username)
            response = requests.post("http://{}/username-availability".format(SERVER_URL), json={"session_id": session_id,
                                                                                                 "iv": iv,
                                                                                                 "username": encrypted_username})
            if not response.json()['success']:
                error = "Username is already registered"
                return render_template("register.html",error=error) 

            hashed_password = hash_string(password)
            encrypted_password = aes_encrypt(communication_key, iv, hashed_password)
            response = requests.post("http://{}/register".format(SERVER_URL), json={"session_id": session_id,
                                                                                    "iv": iv,
                                                                                    "username": encrypted_username,
                                                                                    "password": encrypted_password})
            if not response.json()['success']:
                error = "Error del servidor al registrar"
                return render_template("register.html",error=error) 
            return redirect("/")


@app.route("/login", methods=["GET","POST"])
def login():
    global user_secret
    if request.method == "GET":
        return render_template("login.html")
    elif request.method == "POST":
        if connect():
            username = request.form.get("username")
            password = request.form.get("password")

            iv = generate_iv()
            encrypted_username = aes_encrypt(communication_key, iv, username)
            hashed_password = hash_string(password)
            encrypted_password = aes_encrypt(communication_key, iv, hashed_password)

            response = requests.post("http://{}/login".format(SERVER_URL), json={"session_id": session_id,
                                                                                "iv": iv,
                                                                                "username": encrypted_username,
                                                                                "password": encrypted_password})
            if not response.json()['success']:
                error = "Error del servidor al iniciar sessión"
                return render_template("login.html",error=error)
            user_secret = aes_decrypt(communication_key, iv, response.json()['user_secret'])
            print(user_secret)
            return redirect("/")
    

def connect():
    global communication_key, session_id
    if communication_key is not None and session_id is not None:
        return True
    
    try:
        response = requests.post("http://{}/connect_secure".format(SERVER_URL),
                                json={"client_public_key": encode_key(PUBLIC_KEY)})

        server_public_key = decode_key(response.json()['server_public_key'])
        shared_key = PRIVATE_KEY.exchange(ec.ECDH(), server_public_key)

        communication_key = bytes_to_ascii(HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'',).derive(shared_key))
        session_id = response.json()['session_id']
        print(communication_key, session_id)
        return True
    except:
        print("Ocurrió un error de conexión")
        return False

