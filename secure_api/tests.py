import unittest
import json
import sqlite3
import time
import base64
from app import app, otp_store, get_db, init_db, cipher_suite

class SecureAPITests(unittest.TestCase):
    def setUp(self):
        # Configure app for testing
        app.config['TESTING'] = True
        self.app = app.test_client()
        
        # Reset DB
        init_db()
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM users")
        cur.execute("DELETE FROM tokens")
        conn.commit()
        conn.close()
        
        # Clear OTP store
        otp_store.clear()

    def register_user(self, username, password, role):
        return self.app.post('/register', 
                             data=json.dumps({'username': username, 'password': password, 'role': role}),
                             content_type='application/json')

    def login_and_get_token(self, username, password):
        # 1. Login
        resp = self.app.post('/login', 
                             data=json.dumps({'username': username, 'password': password}),
                             content_type='application/json')
        data = json.loads(resp.data)
        user_id = data.get('user_id')
        
        # 2. Get OTP (Hack: read from global store for test)
        otp, _ = otp_store[user_id]
        
        # 3. Verify OTP
        resp = self.app.post('/verify-otp',
                             data=json.dumps({'user_id': user_id, 'otp': otp}),
                             content_type='application/json')
        data = json.loads(resp.data)
        return data['token'], data['signature']

    def test_full_security_flow(self):
        print("\n--- Testing Full Security Flow ---")
        
        # 1. Registration
        print("[1] Registering users...")
        self.register_user('admin', 'pass123', 'ADMIN')
        self.register_user('dev', 'pass123', 'DEVELOPER')
        self.register_user('consumer', 'pass123', 'CONSUMER')
        
        # 2. MFA Implementation Check
        print("[2] Testing MFA (Login + OTP)...")
        token, signature = self.login_and_get_token('admin', 'pass123')
        self.assertTrue(token)
        self.assertTrue(signature)
        print("    > Token Issued Successfully")

        # 3. RBAC Enforcement
        print("[3] Testing RBAC...")
        headers = {'Authorization': token, 'X-Signature': signature}
        
        # Admin accessing Admin route -> ALLOW
        resp = self.app.get('/admin', headers=headers)
        self.assertEqual(resp.status_code, 200)
        print("    > Admin accessed Admin route: OK")
        
        # Admin accessing Developer route -> DENY (Strict RBAC? Or assumes hierarchy? existing code is strict equality)
        # Check code: code checks `if current_user_role != required_role`. Strict.
        resp = self.app.get('/developer_resource', headers=headers)
        self.assertEqual(resp.status_code, 403)
        print("    > Admin accessed Dev route: DENIED (Strict RBAC verified)")
        
        # 4. Token Storage Encryption Check
        print("[4] Verifying Token Encryption in DB...")
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT encrypted_token FROM tokens")
        enc_token = cur.fetchone()[0]
        conn.close()
        
        # Verify it is NOT the clear token
        self.assertNotEqual(enc_token, token.encode())
        # Verify we can decrypt it to match
        decrypted = cipher_suite.decrypt(enc_token).decode()
        self.assertEqual(decrypted, token)
        print("    > Token stored ENCRYPTED in DB: Verified")
        
        # 5. Integrity Check (Tampering)
        print("[5] Testing Token Tampering...")
        fake_sig = "a" * 64
        headers_tampered = {'Authorization': token, 'X-Signature': fake_sig}
        resp = self.app.get('/dashboard', headers=headers_tampered)
        self.assertEqual(resp.status_code, 401)
        print("    > Tampered signature rejected: Verified")
        
        # 6. Revocation (Logout)
        print("[6] Testing Logout & Revocation...")
        resp = self.app.post('/logout', headers=headers)
        self.assertEqual(resp.status_code, 200)
        
        # Try to access again
        resp = self.app.get('/dashboard', headers=headers)
        self.assertEqual(resp.status_code, 401) # Should fail as token is gone from DB
        print("    > Revoked token access denied: Verified")

if __name__ == '__main__':
    unittest.main()
