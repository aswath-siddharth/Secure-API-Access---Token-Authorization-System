from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import random
import base64
import hmac
import hashlib
import time

otp_store = {}
SECRET_KEY = b'supersecretkey'
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
    data = request.json
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
    data = request.json
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
        otp_store[user_id] = otp
        print("OTP:", otp)

        return jsonify({"message": "OTP sent"})
    else:
        return jsonify({"error": "Invalid credentials"}), 401
    

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.json
    user_id = data['user_id']
    otp = int(data['otp'])

    # 1️⃣ Check OTP
    if otp_store.get(user_id) != otp:
        return jsonify({"error": "Invalid OTP"}), 401

    # 2️⃣ Fetch role from database
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    result = cur.fetchone()

    if not result:
        return jsonify({"error": "User not found"}), 404

    role = result[0]

    # 3️⃣ Generate token
    token, signature = generate_token(user_id, role)

    # 4️⃣ (Optional) Remove OTP after use
    otp_store.pop(user_id, None)

    # 5️⃣ Return token
    return jsonify({
        "message": "OTP verified",
        "token": token,
        "signature": signature
    })

@app.route('/admin', methods=['GET'])
def admin():
    token = request.headers.get("Token")
    signature = request.headers.get("Signature")

    role = verify_token(token, signature)
    if role != "ADMIN":
        return jsonify({"error": "Access denied"}), 403

    return jsonify({"message": "Welcome Admin"})


if __name__ == '__main__':
    app.run(debug=True)
