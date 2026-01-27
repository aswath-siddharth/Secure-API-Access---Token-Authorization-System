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

otp_store = {}  # {user_id: (otp, expiry_time)}
SECRET_KEY = os.environ.get('SECRET_KEY', 'supersecretkey').encode()
def generate_token(user_id, role):
    payload = f"{user_id}|{role}|{int(time.time())}|{int(time.time())+3600}"
    encoded = base64.b64encode(payload.encode())
    signature = hmac.new(SECRET_KEY, encoded, hashlib.sha256).hexdigest()
    return encoded.decode(), signature

def verify_token(token, signature):
    encoded = token.encode()
    expected_sig = hmac.new(SECRET_KEY, encoded, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, signature):
        return None

    decoded = base64.b64decode(encoded).decode()
    user_id, role, issued, expiry = decoded.split("|")

    if int(time.time()) > int(expiry):
        return None

    return role


app = Flask(__name__)

# ---------- Database ----------
def get_db():
    return sqlite3.connect("users.db")

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password BLOB,
            role TEXT
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

@app.route('/admin', methods=['GET'])
@token_required
@role_required("ADMIN")
def admin_panel(role):
    return jsonify({"message": "Welcome to the Admin Panel! You have full control."})

if __name__ == '__main__':
    app.run(debug=True)
