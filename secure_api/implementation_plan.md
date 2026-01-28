# Secure API Access & Token Authorization System - Implementation Plan

## Goal
Enhance the existing Flask application to meet strict security requirements: Token encryption in DB, RBAC with 3 roles, and comprehensive documentation.

## User Review Required
> [!IMPORTANT]
> **Token Storage Strategy**: I will implement stateful token validation. Tokens issued to users will also be encrypted (AES/Fernet) and stored in a `tokens` table. Validation will require both a valid HMAC signature AND the presence of the token in the database (decrypted for verification). This allows for **Token Revocation**.

## Proposed Changes

### Dependencies
#### [MODIFY] [requirements.txt](file:///c:/Users/aswat/Desktop/FOCS%20LAB%20EVAL/Secure-API-Access---Token-Authorization-System/secure_api/requirements.txt)
- Add `cryptography` for AES encryption.

### Database
#### [MODIFY] [app.py](file:///c:/Users/aswat/Desktop/FOCS%20LAB%20EVAL/Secure-API-Access---Token-Authorization-System/secure_api/app.py)
- Update `init_db`:
    - Create `tokens` table: `id`, `user_id`, `encrypted_token`, `expires_at`.

### Core Security Logic
#### [MODIFY] [app.py](file:///c:/Users/aswat/Desktop/FOCS%20LAB%20EVAL/Secure-API-Access---Token-Authorization-System/secure_api/app.py)
- **Key Management**: Use `cryptography.fernet` for token encryption key.
- **Token Generation**:
    - After generating the HMAC signed token, encrypt the *entire token string* using Fernet.
    - Insert into `tokens` table.
- **Token Verification**:
    - Decrypt stored tokens for the user to find a match.
    - Use `hmac.compare_digest` for the signature check (existing).
    - Check expiration.
- **Token Revocation**:
    - Add `/logout` endpoint to delete the token from the DB.

### Authorization & Roles
#### [MODIFY] [app.py](file:///c:/Users/aswat/Desktop/FOCS%20LAB%20EVAL/Secure-API-Access---Token-Authorization-System/secure_api/app.py)
- Ensure Registration supports explicitly setting `role` (Admin, Developer, Consumer).
- Add Protected Routes:
    - `/developer_resource` (Role: DEVELOPER)
    - `/consumer_resource` (Role: CONSUMER)

### Documentation
#### [NEW] [README.md](file:///c:/Users/aswat/Desktop/FOCS%20LAB%20EVAL/Secure-API-Access---Token-Authorization-System/secure_api/README.md)
- Complete system documentation.
- **Security Levels**: Analysis of attacks (Replay, MITM) and countermeasures.
- **Setup**: key generation, installation.

## Verification Plan

### Automated Tests
- I will run a script `verify_system.py` that:
    1. Registers 3 users (one for each role).
    2. Logs them in (Simulate MFA/OTP).
    3. Verifies they get a token.
    4. Checks if the token is present *encrypted* in the sqlite DB.
    5. Attempts to access protected routes (Valid/Invalid roles).
    6. Logs out and confirms token is revoked.

### Manual Verification
- Review the `users.db` to ensure passwords are hashed and tokens are encrypted.
