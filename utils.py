import random
import string
import binascii
import hashlib
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def encode_key(key):
	return binascii.b2a_hex(key.public_bytes(encoding=serialization.Encoding.PEM,
					  format=serialization.PublicFormat.SubjectPublicKeyInfo)).decode()

def decode_key(key):
	return serialization.load_pem_public_key(bytes(binascii.a2b_hex(key).decode(),encoding='ascii'))

def bytes_to_ascii(input):
	return input.hex()

def ascii_to_bytes(input):
	return bytes.fromhex(input)

def generate_iv():
	return bytes_to_ascii(os.urandom(16))

def generate_secret():
	return bytes_to_ascii(secrets.token_bytes(32))

def hash_string(input):
	return hashlib.sha256(input.encode('UTF-8')).hexdigest()

def aes_encrypt(key, nonce, plaintext):
	if isinstance(key, str): key = ascii_to_bytes(key)
	if isinstance(nonce, int): nonce = get_nonce(nonce)
	if isinstance(nonce, str): nonce = ascii_to_bytes(nonce)

	padder = padding.PKCS7(128).padder()
	padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()

	cipher = Cipher(algorithms.AES(key), modes.CBC(nonce), backend=default_backend())

	encryptor = cipher.encryptor()
	ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

	return bytes_to_ascii(ciphertext)

def aes_decrypt(key, nonce, ciphertext):
	if isinstance(key, str): key = ascii_to_bytes(key)
	if isinstance(nonce, int): nonce = get_nonce(nonce)
	if isinstance(nonce, str): nonce = ascii_to_bytes(nonce)
	if isinstance(ciphertext, str): ciphertext = ascii_to_bytes(ciphertext)
	
	cipher = Cipher(algorithms.AES(key), modes.CBC(nonce), backend=default_backend())

	decryptor = cipher.decryptor()
	padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

	unpadder = padding.PKCS7(128).unpadder()
	plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

	return plaintext.decode()

def get_nonce(nonce):
    return hash_string(str(nonce))[:32]

# def XOR(m1: list, m2: list):
# 	res = [0 for i in range(KEY_LENGHT)]
# 	for i in range(KEY_LENGHT):
# 		res[i] = m1[i] ^ m2[i]
# 	return res



