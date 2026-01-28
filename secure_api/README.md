# Secure API Access & Token Authorization System

## 1. System Overview
This project is a secure backend API built with Flask that implements industry-grade security mechanisms for authentication and authorization. It features:
- **Multi-Factor Authentication (MFA)**: Password + OTP.
- **Role-Based Access Control (RBAC)**: Admin, Developer, Consumer roles.
- **Confidentiality**: Database encryption for API tokens (Fernet/AES).
- **Integrity & Authenticity**: HMAC-SHA256 signatures for tokens.
- **Revocation**: Stateful token validation allowing logout/revocation.
- **Secure Storage**: Bcrypt hashing for passwords.

## 2. Setup & Installation
### Prerequisites
- Python 3.x
- pip

### Steps
1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```
2. **Run the Application**
   ```bash
   python app.py
   ```
   The server will start on `http://127.0.0.1:5000`.

## 3. Security Architecture

### Authentication (NIST SP 800-63-2)
- **Level**: Implementation aligns with AAL2 (Authenticator Assurance Level 2).
- **Factor 1**: Knowledge (Password) - Stored as `bcrypt` hash (salted).
- **Factor 2**: Possession (OTP) - Simulated OTP sent to console, valid for 5 minutes.
- **Login Flow**:
  1. POST `/login` -> Validates password -> Returns `user_id`, Generates OTP.
  2. POST `/verify-otp` -> Validates OTP -> Issues Token.

### Token Security
- **Token Structure**: `Base64(User|Role|Issued|Expires)`
- **Integrity**: HMAC-SHA256 signature appended to token checks for tampering.
- **Confidentiality**: The issued token string is **encrypted** (Fernet/AES) before storage in the SQLite database.
- **Validation (Stateful)**:
  1. **Signature Check**: Is the token tampered with?
  2. **Expiry Check**: Is it expired?
  3. **Revocation Check**: The system searches the encrypted database for the token. If not found (or deleted via Logout), access is denied.

### Authorization (RBAC)
- **Roles**:
  - `ADMIN`: Access to `/admin`
  - `DEVELOPER`: Access to `/developer_resource`
  - `CONSUMER`: Access to `/consumer_resource`
- **Enforcement**: Decorators `@token_required` and `@role_required(ROLE)` ensure strict permission checks.

## 4. API Endpoints

### Public
- `POST /register`: Register a new user (`username`, `password`, `role`).
- `POST /login`: Login to receive OTP.
- `POST /verify-otp`: Exchange OTP for Access Token.

### Secure (Requires Headers: `Authorization: <token>`, `X-Signature: <sig>`)
- `POST /logout`: Revoke the current token.
- `GET /dashboard`: Accessible by any valid authenticated user.
- `GET /admin`: Admin only.
- `GET /developer_resource`: Developer only.
- `GET /consumer_resource`: Consumer only.

## 5. Threat Model & Countermeasures

| Attack | Countermeasure |
|--------|----------------|
| **Brute Force** | Passwords are hashed with `bcrypt` (slow hashing) to resist rainbow tables and brute force. |
| **Token Tampering** | HMAC-SHA256 signature verification ensures any change to the token payload is detected. |
| **Token Replay / Stolen Token** | Tokens have a hard expiry (1 hour). Stateful validation allows immediate revocation via `/logout` if compromised. |
| **Database Leak** | Passwords are hashed. Tokens are **encrypted** in the database, so even a DB dump does not reveal active session tokens. |
| **Man-in-the-Middle (MITM)** | In a real deployment, HTTPS (TLS) would be strictly enforced to prevent interception of tokens during transmission. |

## 6. Deliverables Checklist
- [x] MFA (Password + OTP)
- [x] RBAC (3 Roles)
- [x] Token Encryption (Fernet in DB)
- [x] Hashing (Bcrypt for Passwords)
- [x] Digital Signatures (HMAC)
- [x] Token Revocation (Logout)
