# Secure API System - Verification & Walkthrough

## 1. Verification Results
Automated tests confirmed the security and functionality of the system.

### Test Summary
- **Total Tests**: 1 (Comprehensive Flow)
- **Result**: `passed`
- **Execution Time**: ~0.8s

### Feature Validation
| Feature | Requirement | Logic Implemented | Verified? |
|---------|-------------|-------------------|-----------|
| **MFA** | Password + OTP | `verify_otp` checks random 6-digit code linked to user. | ✅ |
| **RBAC** | 3 Roles | Decorator checks `role` before access. | ✅ |
| **Integrity** | Hash Signatures | HMAC-SHA256 signature verification. | ✅ |
| **Confidentiality** | Encrypted DB | `Fernet` (AES) encryption of tokens in `tokens` table. | ✅ |
| **Revocation** | Logout | Deletion of encrypted token from DB + Stateful check. | ✅ |

## 2. Code Walkthrough (Viva Prep)
Use these points to explain the system during your evaluation.

### Q: How do you secure the token?
**A:** We use a Defense-in-Depth approach:
1. **Transmission**: The token string is Base64 encoded for safe HTTP header transport.
2. **Integrity**: We sign the token with `HMAC-SHA256` using a secret key. This prevents users from modifying their role in the payload.
3. **Storage (At Rest)**: We **encrypt** the token using `Fernet` (AES-128) before storing it in the SQLite database. If the DB is stolen, attacker cannot use the tokens.

### Q: Why do you store tokens? Isn't JWT stateless?
**A:** JWT is typically stateless, but that makes *Revocation* (Logout) difficult without short expiry windows. We implemented a **Hybrid Stateful System**. The token has all the info (stateless-like format), but we validate it against the DB (stateful) to allow for immediate **Logout security** and **Audit trails**.

### Q: How does different roles work?
**A:** We use the `@role_required` Python decorator. It intercepts the request *after* authentication but *before* the function runs. If `current_user_role != required_role`, it returns 403 Forbidden immediately.

## 3. How to Run
1. **Start Server**:
   ```bash
   python app.py
   ```
2. **Run Tests**:
   ```bash
   python tests.py
   ```
