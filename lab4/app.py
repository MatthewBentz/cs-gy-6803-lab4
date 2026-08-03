from flask import render_template, Flask, request, redirect
import os
import hmac
import infinc
import SampleNetworkClient
import sqlite3
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)

# AES-EAX stores a 16-byte nonce followed by a 16-byte authentication tag
# and then the ciphertext. The nonce must be unique for each encryption.
PASSWORD_ENCRYPTION_KEY = bytes(
    b'\x93n\x12\xcbC\xe0|\xd0\xa6%7(?KW\xa9\xc2\x02\x97\xc6\\\xd6\xd9c\xf4x\xb9\xe2\x89\x88<\x9d'
)
NONCE_SIZE = 16
TAG_SIZE = 16

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def encrypt_password(password):
    """Encrypt a password with AES-EAX using a fresh nonce every time.

    The previous implementation reused a hardcoded nonce. That made encryption
    deterministic, so encrypting the same password produced the same encrypted
    value. AES-EAX requires a unique nonce for each encryption operation.
    """
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(PASSWORD_ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode("utf-8"))
    return nonce + tag + ciphertext

def split_encrypted_password(encrypted_password):
    """Split the stored password blob into nonce, tag, and ciphertext."""
    encrypted_password = bytes(encrypted_password)
    minimum_length = NONCE_SIZE + TAG_SIZE + 1
    if len(encrypted_password) < minimum_length:
        raise ValueError("Encrypted password is too short or malformed.")

    nonce = encrypted_password[:NONCE_SIZE]
    tag = encrypted_password[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = encrypted_password[NONCE_SIZE + TAG_SIZE:]
    return nonce, tag, ciphertext

def decrypt_password(encrypted_password):
    """Decrypt and authenticate a stored AES-EAX password value."""
    nonce, tag, ciphertext = split_encrypted_password(encrypted_password)
    cipher = AES.new(PASSWORD_ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")

def verify_password(conn, user_password):
    """Verify a submitted password against the encrypted database value.

    Random nonce generation means the submitted password cannot be re-encrypted
    and compared byte-for-byte. Instead, the stored value is decrypted using the
    nonce saved with it, and the plaintext values are compared safely.
    """
    if user_password is None:
        return False, ''

    db_query = "SELECT * FROM users"
    db_result = conn.execute(db_query).fetchone()
    if db_result is None:
        return False, ''

    try:
        db_password = db_result["password"]
        act_token = db_result["act_token"]
    except (IndexError, KeyError, TypeError):
        db_password = db_result[1]
        act_token = db_result[2]

    try:
        stored_password = decrypt_password(db_password)
    except (ValueError, UnicodeDecodeError, TypeError):
        return False, ''

    if hmac.compare_digest(stored_password, user_password):
        return True, act_token
    return False, ''


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method=='GET': # if the request is a GET we return the login page
        return render_template('login.html')
    else:
        conn = get_db_connection()
        password = request.form.get('authToken')
        is_password, act_token = verify_password(conn, password)

        if is_password:
            snc = SampleNetworkClient.SimpleNetworkClient(23456, 23457)
            is_auth = snc.authenticate(23456, bytes(act_token, 'utf-8'))
            return render_template('authenticate.html', Temp="0.00", Token=is_auth.decode('utf-8'))
        else:
            try:
                db_message = ''
                db_query = "SELECT * FROM users WHERE password = ?"
                db_password = conn.execute(db_query, (password,)).fetchone()
                if db_password is None:
                    return render_template('login.html', Err="Wrong password")
                for x in db_password:
                    db_message = db_message + ":" + str(x)
                return render_template('login.html', Err=str(db_message))
            except Exception as ex:
                return render_template('login.html', Err=ex)
            return render_template('login.html', Err="Wrong password")


@app.route('/get_temp', methods=['POST'])
def start_infinc():
    auth_token = request.form.get('authToken')
    snc = SampleNetworkClient.SimpleNetworkClient(23456, 23457)
    try:
        temp =  snc.getTemperatureFromPort(23456, auth_token)
    except Exception:
        temp = "Bad Token"
    return render_template('authenticate.html', Token=auth_token, Temp=temp)


@app.route('/set_temp_c', methods=['POST'])
def set_temp_c():
    auth_token = request.form.get('authToken')
    snc = SampleNetworkClient.SimpleNetworkClient(23456, 23457)
    try:
        temp_change =  snc.setTemperatureC(23456, auth_token)
        temp =  snc.getTemperatureFromPort(23456, auth_token)
    except Exception as ex:
        temp = "Bad Token"
    return render_template('authenticate.html', Token=auth_token, Temp=temp)


@app.route('/set_temp_f', methods=['POST'])
def set_temp_f():
    auth_token = request.form.get('authToken')
    snc = SampleNetworkClient.SimpleNetworkClient(23456, 23457)
    try:
        temp_change =  snc.setTemperatureF(23456, auth_token)
        temp =  snc.getTemperatureFromPort(23456, auth_token)
    except Exception as ex:
        temp = "Bad Token"
    return render_template('authenticate.html', Token=auth_token, Temp=temp)


@app.route('/set_temp_k', methods=['POST'])
def set_temp_k():
    auth_token = request.form.get('authToken')
    snc = SampleNetworkClient.SimpleNetworkClient(23456, 23457)
    try:
        temp_change =  snc.setTemperatureK(23456, auth_token)
        temp =  snc.getTemperatureFromPort(23456, auth_token)
    except Exception as ex:
        temp = "Bad Token"
    return render_template('authenticate.html', Token=auth_token, Temp=temp)