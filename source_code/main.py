# Flask and web tools imports
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename

# Database-related imports
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor

# Email-related imports
from flask_mail import Mail, Message
import smtplib
from smtplib import SMTP, SMTPException
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.policy import default
import email
import poplib
from email.parser import Parser

# Cryptography-related imports
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding

# Security and password encryption imports
import crypt
import hashlib

# File and operating system handling imports
import os
import shutil
import subprocess
from io import BytesIO
from logging import FileHandler, StreamHandler
import logging

# Time and date-related imports
from datetime import datetime, timedelta, timezone

# Data analysis and machine learning imports
import virustotal_checker
from email_ml import analyze_email_ml, train_model_once

# Miscellaneous utilities imports
import secrets
import re
import base64
import zlib
import socket
import ssl
from collections import defaultdict

# Constants configuration
UPLOAD_FOLDER = '/home/CURR_USER/uploads/'
FORBIDDEN_EXTENSIONS = {'com', 'exe', 'dll'}
RESERVED_USERNAMES = {"root", "admin", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "operator", "nobody", "systemd", "system", "mysql", "postgres", "www-data"}
PERMITTED_SUBNETS = ['192.168.10.0/24', '192.168.20.0/24', '192.168.30.0/24', "10.0.2.0/24"]

# User context filter for logs
class UserContextFilter(logging.Filter):
    def filter(self, record):
        record.user_name = session.get('user_name', 'System')
        record.resource = request.path if request else 'Unknown'
        return True

user_filter = UserContextFilter()
for handler in logging.getLogger().handlers:
    handler.addFilter(user_filter)

# Application configuration
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Failed login attempts control per IP.
login_attempts = defaultdict(lambda: {'count': 0, 'last_attempt': None, 'blocked_until': None})
BLOCK_TIME = 10  # Block for 10 minutes.

# Database connection reuse.
connection_pool = pool.SimpleConnectionPool(
    minconn=1, 
    maxconn=10, 
    host='POSTGRES_IP',
    port='POSTGRES_PORT',
    database='smtp_server',
    user='POSTGRES_USER',
    password='POSTGRES_PASSWORD'
)

# Utility functions
def allowed_file(filename):
    #Check if the file has a permitted extension.
    is_allowed = '.' in filename and filename.rsplit('.', 1)[1].lower() not in FORBIDDEN_EXTENSIONS
    return is_allowed

def get_client_ip():
    #Get the client IP address.
    ip = request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or request.remote_addr
    app.logger.info(f"Client IP address: {ip}.")
    return ip

def is_ip_allowed(client_ip):
    import ipaddress
    for subnet in PERMITTED_SUBNETS:
        if ipaddress.IPv4Address(client_ip) in ipaddress.IPv4Network(subnet):
            return True
    return False

def get_db_connection():
    try:
        conn = connection_pool.getconn()
        if conn:
            return conn
    except Exception as e:
        raise

def release_db_connection(conn):
    try:
        if conn:
            connection_pool.putconn(conn)
    except Exception as e:
        raise

def hash_password(password):
    #Return a SHA-256 hashed password.
    return hashlib.sha256(password.encode()).hexdigest()

def is_authenticated():
    #Check if the user is authenticated and their session is valid.
    if 'user_name' not in session or 'session_token' not in session:
        return False

    expiry = session.get('expiry')
    if not expiry or datetime.fromisoformat(expiry) <= datetime.now(timezone.utc):
        return False

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT session_token FROM user_sessions WHERE email = %s', (session['user_email'],))
    db_token = cursor.fetchone()
    cursor.close()
    connection_pool.putconn(conn)

    return db_token and db_token[0] == session['session_token']

def generate_rsa_key_pair(email):
    #Generate an RSA key pair.
    try:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        app.logger.info(f"RSA key pair generated for {email}.")
        return private_key, private_key.public_key()
    except Exception as e:
        app.logger.error(f"Error generating RSA key pair for {emails}: {e}")
        raise

def save_key_to_pem(private_key, public_key, user_email):
    #Save RSA keys in PEM format.
    try:
        directory = os.path.join('/home','CURR_USER','contents', 'keys', user_email)
        os.makedirs(directory, exist_ok=True)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(os.path.join(directory, 'private_key.pem'), 'wb') as private_file:
            private_file.write(private_pem)
        with open(os.path.join(directory, 'public_key.pem'), 'wb') as public_file:
            public_file.write(public_pem)
        try:
           subprocess.run(['chmod', '444', os.path.join(directory, 'private_key.pem')], check=True)
           subprocess.run(['chmod', '444', os.path.join(directory, 'public_key.pem')], check=True)
        except subprocess.CalledProcessError as e:
           print(f"Error applying permissions to public and private key: {e}")

        app.logger.info(f"RSA keys saved for {user_email}.")
    except Exception as e:
        app.logger.error(f"Error saving RSA keys for {user_email}: {e}")
        raise

def load_private_key_from_pem(user_email):
    #Load the private key from a PEM file.
    try:
        with open(f'/home/CURR_USER/contents/keys/{user_email}/private_key.pem', 'rb') as private_file:
            private_key = serialization.load_pem_private_key(private_file.read(), password=None, backend=default_backend())
        app.logger.info(f"Private key loaded from PEM for {user_email}.")
        return private_key
    except Exception as e:
        app.logger.error(f"Error loading private key for {user_email}: {e}")
        raise

def load_public_key_from_pem(user_email):
    #Load the public key from a PEM file.
    try:
        with open(f'/home/CURR_USER/contents/keys/{user_email}/public_key.pem', 'rb') as public_file:
            public_key = serialization.load_pem_public_key(public_file.read(), backend=default_backend())
        app.logger.info(f"Public key loaded from PEM for {user_email}.")
        return public_key
    except Exception as e:
        app.logger.error(f"Error loading public key for {user_email}: {e}")
        raise

def encrypt_aes_key_with_rsa(aes_key, public_key):
    #Encrypt an AES key using an RSA public key.
    try:
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        app.logger.info("AES key encrypted with RSA.")
        return base64.b64encode(encrypted_key).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting AES key with RSA: {e}")
        raise

def decrypt_aes_key_with_rsa(encrypted_key, private_key):
    #Decrypt an AES key using an RSA private key.
    try:
        aes_key = private_key.decrypt(
            base64.b64decode(encrypted_key),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        app.logger.info("AES key decrypted with RSA.")
        return aes_key
    except Exception as e:
        app.logger.error(f"Error decrypting AES key with RSA: {e}")
        raise

def generate_aes_key():
    #Generate a 256-bit AES key.
    try:
        key = os.urandom(32)  # 256 bits
        app.logger.info("AES key generated.")
        return key
    except Exception as e:
        app.logger.error(f"Error generating AES key: {e}")
        raise

def encrypt_data(data, key):
    #Encrypt data using AES in CBC mode.
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        app.logger.info("Data encrypted with AES.")
        return base64.b64encode(iv + encrypted_data).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting data with AES: {e}")
        raise

def decrypt_data(encrypted_data, key):
    #Decrypt data using AES in CBC mode.
    try:
        encrypted_data = base64.b64decode(encrypted_data)
        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        data = unpadder.update(decrypted_data) + unpadder.finalize()
        app.logger.info("Data decrypted with AES.")
        return data.decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error decrypting data with AES: {e}")
        raise

def password_is_strong(password, confirm_password):
    #Validate if the password is strong.
    if password != confirm_password:
        return False, "Passwords do not match."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."
    return True, "The password is strong and valid."

def is_something_special(name):
    #Check if the name is not reserved and is valid.
    return name not in RESERVED_USERNAMES and all(reserved_name not in name for reserved_name in RESERVED_USERNAMES) and re.match(r'^[a-zA-Z0-9_]+$', name) is not None

def is_valid_name(name):
    #Check if the name contains only letters, numbers, and spaces.
    return re.match(r'^[a-zA-Z0-9 ]+$', name) is not None

def is_valid_email_name(email_name):
    #Check if the email name contains no special characters.
    return re.match(r'^[a-zA-Z0-9._%+-]+$', email_name) is not None

def get_login_attempts(client_ip):
    # Function to get login attempts from an IP
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM login_attempts WHERE ip_address = %s', (client_ip,))
    attempt = cursor.fetchone()
    cursor.close()
    connection_pool.putconn(conn)
    return attempt

def update_login_attempts(client_ip, count, blocked_until):
    # Function to update or insert login attempts from an IP
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO login_attempts (ip_address, attempt_count, last_attempt, blocked_until)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (ip_address)
        DO UPDATE SET attempt_count = EXCLUDED.attempt_count, last_attempt = EXCLUDED.last_attempt, blocked_until = EXCLUDED.blocked_until
    ''', (client_ip, count, datetime.now(), blocked_until))
    conn.commit()
    cursor.close()
    connection_pool.putconn(conn)

def is_text_file(filepath, chunk_size=512):
    # Check if a file is text by reading a small portion of it
    try:
        with open(filepath, 'rb') as file:
            chunk = file.read(chunk_size)
            if b'\0' in chunk:  # File contains null bytes (binary indication)
                return False
            text_characters = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(32, 127)) | set(range(128, 256)))
            return all(byte in text_characters for byte in chunk)
    except IOError:
        #print("Could not open the file.")
        return False

def detect_reverse_shell(filepath):
    if not is_text_file(filepath):
        #print("The file is not text or contains binary characters. It will not be analyzed.")
        return False

    # Common reverse shell patterns
    reverse_shell_patterns = [
        # Network connection patterns
        r'socket\.socket', r'connect\(', r'/dev/tcp/', r'/dev/udp/', r'nc\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        r'bash\s+-i', r'curl\s+', r'wget\s+', r'exec\(.*(sh|bash)', r'0\.0\.0\.0:\d+', r'127\.0\.0\.1:\d+',
        
        # Shell command execution patterns
        r'os\.system', r'subprocess\.', r'system\(', r'popen\(', r'Runtime\.getRuntime', r'ProcessBuilder',
        
        # Common network or remote execution patterns in various languages
        r'Invoke-Expression', r'Invoke-WebRequest', r'System\.Net\.Sockets', r'new-object Net\.Sockets\.TcpClient',
        
        # IP addresses with possible connection ports
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+'
    ]

    # Possible suspicious commands or modules
    suspicious_terms = [
        'socket', 'bash', 'sh', 'exec', 'system', 'subprocess', 'popen', 'Runtime', 'ProcessBuilder', 'curl', 
        'wget', 'tcpclient', 'Invoke-Expression', 'Invoke-WebRequest', 'tcp'
    ]

    with open(filepath, 'r', errors='ignore') as file:
        content = file.read()

        # Search for reverse shell patterns
        for pattern in reverse_shell_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                #print(f"Reverse shell pattern found: {pattern}")
                return True

        # Search for suspicious terms
        for term in suspicious_terms:
            if term in content:
                #print(f"Suspicious term found: {term}")
                return True

    #print("The file does not appear to contain reverse shells.")
    return False

# Application routes
@app.route('/')
def home():
    #Homepage displaying the login form.
    return render_template('inbox.html' if is_authenticated() else 'login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    #User registration page.
    if is_authenticated():
        flash("You are already registered. Please log in.")
        return redirect(url_for('inbox'))

    client_ip = get_client_ip()
    app.logger.info(f"Access to registration page from IP: {client_ip}")

    # Check if the IP is allowed
    if not is_ip_allowed(client_ip):
        app.logger.warning(f"Attempted access to registration from a suspicious IP: {client_ip}")
        flash("Access denied.")
        return render_template('login.html')

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        email_name = email.split('@')[0]

        # Verify that the name is valid
        if not is_valid_name(name) or not is_something_special(name):
            flash("The name contains invalid characters. Only letters, numbers, and spaces are allowed.")
            return redirect(url_for('register'))

        if not is_valid_email_name(email_name) or not is_something_special(email_name):
            flash("The email name contains invalid characters.")
            return redirect(url_for('register'))

        password = request.form['password']
        confirm_password = request.form['confirm_password']

        is_strong, message = password_is_strong(password, confirm_password)
        if not is_strong:
            flash(message)
            return redirect(url_for('register'))

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()

        if user:
            flash("This email is already registered.")
            app.logger.info(f"Attempted to register user {name} but it already exists in the database.")
            cursor.close()
            connection_pool.putconn(conn)
            return redirect(url_for('register'))

        # Generate RSA key pair
        private_key, public_key = generate_rsa_key_pair(email)
        save_key_to_pem(private_key, public_key, email)

        # Create user in the system
        salt = crypt.mksalt(crypt.METHOD_SHA512)

       # Encrypt the password
        encrypted_password = crypt.crypt(password, salt)
        try:
           subprocess.run(['sudo', 'useradd', '-m', '-s', '/bin/bash', email_name], check=True)
           subprocess.run(['sudo', 'usermod', '-p', encrypted_password, email_name], check=True)
           print(f"User {email_name} created successfully.")
        except subprocess.CalledProcessError as e:
           print(f"Error creating user: {e}")

        # Register user in the database
        password_hash = hash_password(password)
        cursor.execute('INSERT INTO users (name, email, password_hash) VALUES (%s, %s, %s)',
                       (name, email, password_hash))
        conn.commit()
        cursor.close()
        connection_pool.putconn(conn)

        flash("User registered successfully.")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    #User login page.
    client_ip = get_client_ip()
    app.logger.info(f"Access to login page from IP: {client_ip}")

    # Check if the IP is allowed
    if not is_ip_allowed(client_ip):
        app.logger.warning(f"Login attempt from a suspicious IP: {client_ip}")
        flash("Access denied.")
        return render_template('login.html')

    # Check login attempts in the DB.
    attempt = get_login_attempts(client_ip)

    # If the IP is blocked, check if the lockout period has expired.
    if attempt and attempt['blocked_until'] and datetime.now() < attempt['blocked_until']:
        app.logger.info(f"La IP {client_ip} ha sido bloqueada hasta las {attempt['blocked_until']}")
        flash(f"Too many failed attempts. Try again later.")
        return render_template('login.html')

    #Existing user login page.#
    if is_authenticated():
        flash("You are already logged in.")
        return redirect(url_for('inbox'))

    if request.method == 'POST':
        email = request.form['email'].split('@')[0] if '@MAIL_DOMAIN' in request.form['email'] else request.form['email']
        password = request.form['password']
        password_hash = hash_password(password)

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute('SELECT * FROM users WHERE email = %s AND password_hash = %s', (email, password_hash))
        user = cursor.fetchone()

        if user:
            session.update({
                'user_name': user['name'],
                'user_email': user['email'],
                'password': password,
                'session_token': secrets.token_hex(16),
                'IP': get_client_ip(),
                'expiry': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            })
            cursor.execute('DELETE FROM user_sessions WHERE email = %s', (email,))
            cursor.execute(
                'INSERT INTO user_sessions (email, session_token, created_at) VALUES (%s, %s, %s)',
                (email, session['session_token'], datetime.now(timezone.utc))
            )
            conn.commit()
            app.logger.info(f"User {session['user_name']} authenticated.")
            cursor.close()
            connection_pool.putconn(conn)
            return redirect(url_for('inbox'))
        else:
            # Failed login attempt handler.
            count = 1
            blocked_until = None
            if attempt:
                count = attempt['attempt_count'] + 1
                if count >= 5:
                    blocked_until = datetime.now() + timedelta(minutes=BLOCK_TIME)
                    flash(f"Too many failed login attempts. Login blocked for {BLOCK_TIME} minutes.")
                    app.logger.warning(f"The IP {client_ip} has been blocked after numerous login attempts.")
                else:
                    flash("Incorrect email or password.")
                    app.logger.info(f"Failed login attempt for {email}.")
            update_login_attempts(client_ip, count, blocked_until)

            cursor.close()
            connection_pool.putconn(conn)

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    #Log out the user.
    user_email = session.pop('user_email', None)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM user_sessions WHERE email = %s', (user_email,))
    conn.commit()
    cursor.close()
    connection_pool.putconn(conn)
    session.clear()
    app.logger.info(f"User {user_email} has logged out successfully.")
    flash("You have logged out.")
    return redirect(url_for('login'))

@app.route('/inbox')
def inbox():
    #Display the email inbox.
    if not is_authenticated():
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    pop_conn = poplib.POP3_SSL('pop3.MAIL_DOMAIN', '995')
    pop_conn.user(session['user_email'])
    pop_conn.pass_(session['password'])

    messages = [b"\n".join(mssg[1]).decode('utf-8') for mssg in [pop_conn.retr(i) for i in range(1, len(pop_conn.list()[1]) + 1)]]
    emails = [email.message_from_string(mssg, policy=default) for mssg in messages]
    app.logger.info(f"{session['user_email']} has accessed the inbox.")
    for email_msg in emails:
        message_id = str(email_msg['Message-ID'])
        cursor.execute('SELECT * FROM sent_emails WHERE message_id = %s', (message_id,))
        if not cursor.fetchone():
            cursor.execute(
                'UPDATE sent_emails SET deliver_time = %s, delivered = %s WHERE message_id = %s',
                (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), True, message_id)
            )
            conn.commit()

    pop_conn.quit()
    cursor.execute('SELECT * FROM sent_emails WHERE receiver_email = %s ORDER BY sent_time DESC', (session['user_email'],))
    received_emails = cursor.fetchall()

    for mail in received_emails:
        private_key = load_private_key_from_pem(mail['receiver_email'])
        decrypted_aes_key = decrypt_aes_key_with_rsa(mail['encrypted_key'], private_key)
        mail['encrypted_subject'] = decrypt_data(mail['encrypted_subject'], decrypted_aes_key)

    cursor.close()
    connection_pool.putconn(conn)
    return render_template('inbox.html', emails=received_emails)

@app.route('/send_email', methods=['GET', 'POST'])
def send_email():
    #Email sending page.
    if not is_authenticated():
        return redirect(url_for('login'))

    if request.method == 'POST':
        sender_email = session['user_email']
        receiver_emails = [email.strip() for email in request.form['receiver_email'].split(',')]
        subject = request.form['subject']
        body = request.form['body']
        has_attachments = False
        security_status = analyze_email_content(subject, body)
        app.logger.info(f"The content of the email sent by {sender_email} is {security_status}.")

        all_emails_sent_successfully = True

        for receiver_email in receiver_emails:
            email_id = None

            # Verify user existence in the database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE email = %s', (receiver_email,))
            receiver_user = cursor.fetchone()

            if not receiver_user:
                # Log that the email could not be sent because the user does not exist
                app.logger.info(f"Email not sent: the user {receiver_email} does not exist in the database.")
                continue  # Proceed to the next recipient
            
            try:
                # Load recipient’s public key
                public_key = load_public_key_from_pem(receiver_email)
                aes_key = generate_aes_key()
                encrypted_subject = encrypt_data(subject, aes_key)
                encrypted_body = encrypt_data(body, aes_key)
                encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)
                sent_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                # Create the Message-ID
                message_id = f"{secrets.token_hex(16)}"

                msg = MIMEMultipart()
                msg['From'] = sender_email
                msg['To'] = receiver_email
                msg['Subject'] = encrypted_subject
                msg['Date'] = sent_time 
                msg['Message-ID'] = message_id
                msg['Security'] = security_status
                msg.attach(MIMEText(encrypted_body, 'plain'))

                # Add attachments if present
                files = request.files.getlist('attachments')
                attachment_paths = []
                for file in files:
                    if file:
                        # Verify file size
                        if file.content_length > 5 * 1024 * 1024:
                            flash(f'The file {file.filename} exceeds the maximum allowed size of 5 MB.')
                            return redirect(url_for('send_email'))

                        filename = secure_filename(file.filename)
                        if not allowed_file(filename):
                            flash(f'The message was not sent because the file {filename} is potentially dangerous.')
                            return redirect(url_for('send_email'))

                        temp_file_path = os.path.join('/tmp', filename)
                        file.save(temp_file_path)
                        
                        if detect_reverse_shell(temp_file_path):
                            flash(f'The message was not sent. The file {filename} is malicious.')
                            app.logger.warning(f"User {sender_email} attempted to send a reverse shell ({filename}).")
                            return redirect(url_for('send_email'))

                        if virustotal_checker.process_file(temp_file_path):
                            virustotal_checker.close_connection()
                            os.remove(temp_file_path)
                            flash(f'The message was not sent. The file {filename} is malicious.')
                            app.logger.warning(f"User {sender_email} attempted to send a malicious file ({filename}).")
                            return redirect(url_for('send_email'))

                        has_attachments = True

                        file_path = os.path.join('/home','CURR_USER','uploads', message_id, filename)
                        os.makedirs(os.path.dirname(file_path), exist_ok=True)
                        shutil.move(temp_file_path, file_path)

                        with open(file_path, "rb") as f:
                            file_data = f.read()
                        encrypted_file_data = encrypt_data(file_data.hex(), aes_key)
                        with open(file_path, "w") as f:
                            f.write(encrypted_file_data)
                        attachment_paths.append(filename)

                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(encrypted_file_data.encode())
                        encoders.encode_base64(part)
                        part.add_header("Content-Disposition", f"attachment; filename={filename}")
                        msg.attach(part)

                # Send the message using SMTP
                with smtplib.SMTP('smtp.MAIL_DOMAIN', 25) as server:
                    server.sendmail(sender_email, receiver_email, msg.as_string())

                # Save in the database
                cursor.execute(
                    'INSERT INTO sent_emails (sender_email, receiver_email, encrypted_subject, encrypted_body, message_id, has_attachments, encrypted_key, sent_time, security_status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING message_id',
                    (sender_email, receiver_email, encrypted_subject, encrypted_body, message_id, has_attachments, encrypted_aes_key, sent_time, security_status)
                )
                email_id = cursor.fetchone()[0]

                for filename in attachment_paths:
                    cursor.execute('INSERT INTO email_attachments (email_id, filename) VALUES (%s, %s)', (email_id, filename))

                conn.commit()
                app.logger.info(f"Email sent from {sender_email} to {receiver_email} successfully. With attachments: {has_attachments}")

            except Exception as e:
                flash(f"Error sending email to {receiver_email}")
                all_emails_sent_successfully = False
                app.logger.error(f"Error sending email to {receiver_email}: {e}")

            finally:
                if cursor:
                    cursor.close()
                if conn:
                    connection_pool.putconn(conn)

        if all_emails_sent_successfully:
            flash("Email sent successfully.")
        else:
            app.logger.info("Some emails were not sent correctly.")

    return render_template('send_email.html')

@app.route('/sent_items')
def sent_items():
    #Display sent emails.
    if not is_authenticated():
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM sent_emails WHERE sender_email = %s ORDER BY sent_time DESC', (session['user_email'],))
    emails = cursor.fetchall()

    for email in emails:
        private_key = load_private_key_from_pem(email['receiver_email'])
        decrypted_aes_key = decrypt_aes_key_with_rsa(email['encrypted_key'], private_key)
        email['encrypted_subject'] = decrypt_data(email['encrypted_subject'], decrypted_aes_key)

    cursor.close()
    connection_pool.putconn(conn)
    return render_template('sent_items.html', sent_emails=emails)

def analyze_email_content(subject, body):
    train_model_once()
    #Analyze the subject and body of the email for insecure keywords.#
    return 'unsafe' if analyze_email_ml(subject, body) == "spam" else 'safe'

@app.route('/view_email/<email_id>')
def view_email(email_id):
    #Display a received email.
    if not is_authenticated():
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('''
        SELECT se.sender_email, se.receiver_email, se.sent_time, se.has_attachments, se.security_status, se.encrypted_body, se.encrypted_subject, se.encrypted_key, se.message_id,
               array_agg(ea.filename) as attachments
        FROM sent_emails se
        LEFT JOIN email_attachments ea ON se.message_id = ea.email_id
        WHERE se.message_id = %s AND se.receiver_email = %s
        GROUP BY se.sender_email, se.receiver_email, se.sent_time, se.has_attachments, se.security_status, se.encrypted_body, se.encrypted_subject, se.encrypted_key, se.message_id
    ''', (email_id, session['user_email']))
    email = cursor.fetchone()
    cursor.close()
    connection_pool.putconn(conn)

    if not email:
        flash('Email not found.')
        return redirect(url_for('inbox'))

    private_key = load_private_key_from_pem(session['user_email'])
    decrypted_aes_key = decrypt_aes_key_with_rsa(email['encrypted_key'], private_key)
    email['subject'] = decrypt_data(email['encrypted_subject'], decrypted_aes_key)
    email['body'] = decrypt_data(email['encrypted_body'], decrypted_aes_key)

    attachments = []
    if email['attachments']:
        email['attachments'] = [attachment for attachment in email['attachments'] if attachment]
        for attachment in email['attachments']:
            file_path = os.path.join(UPLOAD_FOLDER, email_id, attachment)
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
            decrypted_data = decrypt_data(encrypted_data.decode('utf-8'), decrypted_aes_key)
            attachment_stream = BytesIO(bytes.fromhex(decrypted_data))
            attachments.append({'name': attachment, 'data': attachment_stream})

    return render_template('view_email.html', email=email, attachments=attachments)

@app.route('/view_sent_email/<email_id>')
def view_sent_email(email_id):
    #Display a sent email.
    if not is_authenticated():
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('''
        SELECT se.sender_email, se.receiver_email, se.sent_time, se.has_attachments, se.security_status, se.encrypted_body, se.encrypted_subject, se.encrypted_key, se.message_id,
               array_agg(ea.filename) as attachments
        FROM sent_emails se
        LEFT JOIN email_attachments ea ON se.message_id = ea.email_id
        WHERE se.message_id = %s AND se.sender_email = %s
        GROUP BY se.sender_email, se.receiver_email, se.sent_time, se.has_attachments, se.security_status, se.encrypted_body, se.encrypted_subject, se.encrypted_key, se.message_id
    ''', (email_id, session['user_email']))
    email = cursor.fetchone()
    cursor.close()
    connection_pool.putconn(conn)

    if not email:
        flash('Email not found.')
        return redirect(url_for('inbox'))

    private_key = load_private_key_from_pem(email['receiver_email'])
    decrypted_aes_key = decrypt_aes_key_with_rsa(email['encrypted_key'], private_key)
    email['subject'] = decrypt_data(email['encrypted_subject'], decrypted_aes_key)
    email['body'] = decrypt_data(email['encrypted_body'], decrypted_aes_key)

    attachments = []
    if email['attachments']:
        email['attachments'] = [attachment for attachment in email['attachments'] if attachment]
        for attachment in email['attachments']:
            file_path = os.path.join(UPLOAD_FOLDER, email_id, attachment)
            with open(file_path, 'rb') as file:
                encrypted_data = file.read()
            decrypted_data = decrypt_data(encrypted_data.decode('utf-8'), decrypted_aes_key)
            attachment_stream = BytesIO(bytes.fromhex(decrypted_data))
            attachments.append({'name': attachment, 'data': attachment_stream})

    return render_template('view_sent_email.html', email=email, attachments=attachments)

@app.route('/download_attachment/<email_id>/<filename>')
def download_attachment(email_id, filename):
    #Download an attachment.
    if not is_authenticated():
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM sent_emails WHERE message_id = %s AND (receiver_email = %s OR sender_email = %s)',
                   (email_id, session['user_email'], session['user_email']))
    email_data = cursor.fetchone()
    cursor.close()
    connection_pool.putconn(conn)

    if not email_data:
        flash('Email not found, or you do not have permission to access this attachment.')
        return redirect(url_for('inbox'))

    # Load and decrypt the attachment from memory
    private_key = load_private_key_from_pem(email_data['receiver_email'])
    decrypted_aes_key = decrypt_aes_key_with_rsa(email_data['encrypted_key'], private_key)

    file_path = os.path.join(UPLOAD_FOLDER, email_id, filename)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = decrypt_data(encrypted_data.decode('utf-8'), decrypted_aes_key)

    # Create a memory stream to send the file
    file_stream = BytesIO(bytes.fromhex(decrypted_data))

     # Log that the attachment has been downloaded
    app.logger.info(f"User {session['user_email']} downloaded the attachment '{filename}' from the email with ID '{email_id}'.")

    return send_file(file_stream, as_attachment=True, download_name=filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000,debug=True)


