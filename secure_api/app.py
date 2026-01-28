from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import random
import base64
import hmac
import hashlib
import time
import os
from functools import wraps
from cryptography.fernet import Fernet

otp_store = {}  # {user_id: (otp, expiry_time)}
SECRET_KEY = os.environ.get('SECRET_KEY', 'supersecretkey').encode()

# Generate a key for encryption (In production, load this from environment!)
# For this demo, we ensure it's consistent if restart happens by checking for a file or env, 
# but simply regenerating for now as per "Demonstrate secure key generation"
# A real system would persist this key.
FERNET_KEY = Fernet.generate_key() 
cipher_suite = Fernet(FERNET_KEY)

def get_db():
    return sqlite3.connect("users.db")
def generate_token(user_id, role):
    # 1. Create the payload
    # Add randomness/salt to ensuring unique tokens even for same user/time? 
    # Current: user|role|issue|expire. Good enough for demo.
    expiry_time = int(time.time()) + 3600
    payload = f"{user_id}|{role}|{int(time.time())}|{expiry_time}"
    
    # 2. Encode & Sign (Integrity)
    encoded_token = base64.b64encode(payload.encode()).decode() # The "Token" String
    signature = hmac.new(SECRET_KEY, encoded_token.encode(), hashlib.sha256).hexdigest()
    
    # 3. Encrypt & Store (Confidentiality & Revocation capability)
    # We store the 'encoded_token' string, encrypted.
    encrypted_token = cipher_suite.encrypt(encoded_token.encode())
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO tokens (user_id, encrypted_token, expires_at) VALUES (?, ?, ?)", 
                (user_id, encrypted_token, expiry_time))
    conn.commit()
    conn.close()

    return encoded_token, signature

def verify_token(token, signature):
    # 1. Integrity Check (HMAC)
    encoded = token.encode()
    expected_sig = hmac.new(SECRET_KEY, encoded, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, signature):
        return None # Tampered

    # 2. Decode & Expiry Check (Stateless)
    try:
        decoded = base64.b64decode(encoded).decode()
        user_id, role, issued, expiry = decoded.split("|")
        
        if int(time.time()) > int(expiry):
            return None # Expired
            
    except Exception:
        return None # Malformed

    # 3. Authenticity & Revocation Check (Stateful - DB)
    # We must find this token in the DB, encrypted.
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT encrypted_token FROM tokens WHERE user_id = ?", (user_id,))
    stored_tokens = cur.fetchall()
    
    token_is_valid_in_db = False
    for (enc_tok,) in stored_tokens:
        try:
            # Decrypt token from DB
            decrypted_db_token = cipher_suite.decrypt(enc_tok).decode()
            if decrypted_db_token == token:
                token_is_valid_in_db = True
                break
        except Exception as e:
            continue # Skip invalid/old keys if any
            
    conn.close()
    
    if not token_is_valid_in_db:
        return None # Revoked or Fake

    return role


app = Flask(__name__)

# ---------- Database ----------
def get_db():
    return sqlite3.connect("users.db")

def init_db():
    conn = get_db()
    cur = conn.cursor()
    # Users Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password BLOB,
            role TEXT
        )
    """)
    # Tokens Table for Stateful Validation (Revocation & Security)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            encrypted_token BLOB,
            expires_at REAL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------- Routes ----------
@app.route('/')
def home():
    return "Secure API Server is running"

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(force=True)

    username = data['username']
    password = data['password']
    role = data.get('role', 'USER')

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, hashed_pw, role)
        )
        conn.commit()
        return jsonify({"message": "User registered successfully"})
    except:
        return jsonify({"error": "User already exists"}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(force=True, silent=True)

    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Username and password required"}), 400

    username = data['username']
    password = data['password']

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, password FROM users WHERE username=?", (username,))
    user = cur.fetchone()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    user_id, hashed_pw = user

    if bcrypt.checkpw(password.encode(), hashed_pw):
        otp = random.randint(100000, 999999)
        otp_expiry = int(time.time()) + 300  # 5 minutes expiry
        otp_store[user_id] = (otp, otp_expiry)
        print(f"OTP for user {user_id}: {otp} (Expires in 5 mins)")
        return jsonify({"message": "OTP sent", "user_id": user_id})

    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json(force=True, silent=True)

    # 1️⃣ Validate JSON first
    if not data or 'user_id' not in data or 'otp' not in data:
        return jsonify({"error": "Invalid or missing JSON"}), 400

    user_id = data['user_id']
    otp = int(data['otp'])

    # 2️⃣ Check OTP and Expiry
    stored_data = otp_store.get(user_id)
    
    if not stored_data:
        return jsonify({"error": "No OTP request found"}), 400

    stored_otp, expiry = stored_data

    if int(time.time()) > expiry:
        otp_store.pop(user_id, None)
        return jsonify({"error": "OTP has expired"}), 401
        
    if stored_otp != otp:
        return jsonify({"error": "Invalid OTP"}), 401

    # 3️⃣ Fetch role
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    result = cur.fetchone()

    if not result:
        return jsonify({"error": "User not found"}), 404

    role = result[0]

    # 4️⃣ Generate token
    token, signature = generate_token(user_id, role)

    # 5️⃣ Remove OTP
    otp_store.pop(user_id, None)

    return jsonify({
        "message": "OTP verified, Login Successful",
        "token": token,
        "signature": signature
    })

# ---------- Decorators ----------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        signature = request.headers.get('X-Signature') # Expecting signature in custom header for now

        if not token or not signature:
             # Support Bearer token if signature is embedded or standard format, but keeping to current custom format:
             # Client must send "Authorization: <token>" and "X-Signature: <sig>"
            return jsonify({'message': 'Token and Signature are missing!'}), 401

        role = verify_token(token, signature)
        if not role:
            return jsonify({'message': 'Invalid or Expired Token!'}), 401
        
        # Determine user_id from token (simple parse again or Refactor verify_token to return more info)
        # For this simple RBAC, we just need the role which verify_token returns.
        return f(role, *args, **kwargs)

    return decorated

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(current_user_role, *args, **kwargs):
            if current_user_role != required_role:
                 return jsonify({'message': 'Permission Denied: You do not have access!'}), 403
            return f(current_user_role, *args, **kwargs)
        return decorated_function
    return decorator

# ---------- Protected Routes ----------
@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard(role):
    return jsonify({"message": f"Welcome strictly authenticated user! Your role is {role}"})

@app.route('/developer_resource', methods=['GET'])
@token_required
@role_required("DEVELOPER")
def developer_panel(role):
    return jsonify({"message": "Welcome Developer! Access granted to API docs and sandboxes."})

@app.route('/consumer_resource', methods=['GET'])
@token_required
@role_required("CONSUMER")
def consumer_dashboard(role):
    return jsonify({"message": "Welcome Consumer! Here is your usage data."})

@app.route('/admin', methods=['GET'])
@token_required
@role_required("ADMIN")
def admin_panel(role):
    return jsonify({"message": "Welcome to the Admin Panel! You have full control."})

@app.route('/logout', methods=['POST'])
def logout():
    # User sends token to logout
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"message": "Token missing"}), 400
        
    # We find and delete this token from DB
    # Since we store encrypted tokens, we have to find which one it is.
    # Optimization: In real world, we might store a hash of the token for lookup, 
    # but here we iterate for demonstration of "Decryption" requirement.
    
    # Needs user_id to narrow down search or search all? 
    # Let's decode token to get user_id first (insecure decode is fine for lookup logic)
    try:
        decoded_bytes = base64.b64decode(token)
        decoded_str = decoded_bytes.decode()
        user_id = decoded_str.split("|")[0]
    except:
        return jsonify({"message": "Invalid token format"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, encrypted_token FROM tokens WHERE user_id = ?", (user_id,))
    rows = cur.fetchall()
    
    token_id_to_delete = None
    for row_id, enc_tok in rows:
        try:
            if cipher_suite.decrypt(enc_tok).decode() == token:
                token_id_to_delete = row_id
                break
        except:
            continue
            
    if token_id_to_delete:
        cur.execute("DELETE FROM tokens WHERE id = ?", (token_id_to_delete,))
        conn.commit()
        conn.close()
        return jsonify({"message": "Logged out successfully. Token revoked."})
    else:
        conn.close()
        return jsonify({"message": "Token not found or already revoked."}), 400

if __name__ == '__main__':
    app.run(debug=True)
