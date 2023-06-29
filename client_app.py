from flask import Flask, flash, render_template, request, redirect, url_for
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from utils import *
import requests

SERVER_URL = "127.0.0.1:5002"
PRIVATE_KEY = ec.generate_private_key(ec.SECP384R1())
PUBLIC_KEY = PRIVATE_KEY.public_key()
session_key = None
session_id = None
session_nonce = None
session_username = None

app = Flask(__name__)
    

@app.route("/", methods=["GET"])
def home():
    if session_username is None:
        return render_template("home.html")
    else:
        redirect("/dashboard")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    elif request.method == "POST":
        if connect():
            global session_id, session_nonce

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
            

            encrypted_username = aes_encrypt(session_key, session_nonce, username)
            response = requests.post("http://{}/username-availability".format(SERVER_URL), json={"session_id": session_id,
                                                                                                 "username": encrypted_username})
            if not response.json()['success']:
                error = "Username is already registered"
                return render_template("register.html",error=error)
            session_nonce += 1

            encrypted_username = aes_encrypt(session_key, session_nonce, username)
            hashed_password = hash_string(password)
            encrypted_password = aes_encrypt(session_key, session_nonce, hashed_password)
            response = requests.post("http://{}/register".format(SERVER_URL), json={"session_id": session_id,
                                                                                    "username": encrypted_username,
                                                                                    "password": encrypted_password})
            
            # print(session_nonce)
            if not response.json()['success']:
                error = "Error del servidor al registrar"
                return render_template("register.html",error=error)
            session_nonce += 1
            return redirect("/dashboard")


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    elif request.method == "POST":
        if connect():
            global session_key, session_id, session_nonce, session_username

            username = request.form.get("username")
            password = request.form.get("password")

            encrypted_username = aes_encrypt(session_key, session_nonce, username)
            hashed_password = hash_string(password)
            encrypted_password = aes_encrypt(session_key, session_nonce, hashed_password)
            # print(session_nonce)

            response = requests.post("http://{}/login".format(SERVER_URL), json={"session_id": session_id,
                                                                                "username": encrypted_username,
                                                                                "password": encrypted_password})
            if not response.json()['success']:
                error = "Error del servidor al iniciar sessión"
                return render_template("login.html",error=error)
            session_username = username
            session_nonce += 1
            # print(session_username)
            return redirect("/dashboard")
        return redirect('/')

@app.route("/dashboard", methods=['GET'])
def dashboard():
    if connect() and loggedIn():
        global session_key, session_id, session_nonce, session_username

        response = requests.post("http://{}/get_secrets".format(SERVER_URL), json={"session_id": session_id})
        if response.json()['success']:
            sites = [aes_decrypt(session_key, session_nonce, site) for site in response.json()['sites']]
            secrets = [aes_decrypt(session_key, session_nonce, secret) for secret in response.json()['secrets']]
            session_nonce += 1
            return render_template("dashboard.html", rows=zip(sites, secrets))

    return redirect('/logout')

@app.route("/add", methods=['POST'])
def add_secret():
    if connect() and loggedIn():
        global session_key, session_id, session_nonce, session_username

        site = request.form.get("site")
        secret = request.form.get("secret")

        print(site, secret)

        encrypted_site = aes_encrypt(session_key, session_nonce, site)
        encrypted_secret = aes_encrypt(session_key, session_nonce, secret)

        response = requests.post("http://{}/add".format(SERVER_URL), json={"session_id": session_id,
                                                                           "site": encrypted_site,
                                                                           "secret": encrypted_secret})
        if response.json()['success']:
            session_nonce += 1
            return redirect("/dashboard")
        
    return redirect('/logout')

@app.route("/delete/<site>", methods=['GET'])
def delete_site(site):
    if connect() and loggedIn():
        global session_key, session_id, session_nonce, session_username

        encrypted_site = aes_encrypt(session_key, session_nonce, site)

        response = requests.post("http://{}/delete".format(SERVER_URL), json={"session_id": session_id,
                                                                              "site": encrypted_site})
        if response.json()['success']:
            session_nonce += 1
            return redirect("/dashboard")


@app.route("/logout", methods=['GET'])
def logout():
    global session_key, session_id, session_nonce, session_username
    if session_username is not None:
        encrypted_username = aes_encrypt(session_key, session_nonce, session_username)
        response = requests.post("http://{}/logout".format(SERVER_URL), json={"session_id": session_id,
                                                                            "username": encrypted_username})
        if response.json()['success']:
            session_key = None
            session_id = None
            session_username = None
            session_nonce = None
    return redirect("/")

def connect():
    global session_key, session_id, session_nonce
    if session_key is not None and session_id is not None:
        return True
    
    try:
        response = requests.post("http://{}/connect_secure".format(SERVER_URL),
                                json={"client_public_key": encode_key(PUBLIC_KEY)})

        server_public_key = decode_key(response.json()['server_public_key'])
        shared_key = PRIVATE_KEY.exchange(ec.ECDH(), server_public_key)

        session_key = bytes_to_ascii(HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'').derive(shared_key))
        session_id = response.json()['session_id']
        session_nonce = 0
        print(session_key, session_id)
        return True
    except:
        print("Ocurrió un error de conexión")
        return False
    
def loggedIn():
    global session_username
    return session_username is not None
    




