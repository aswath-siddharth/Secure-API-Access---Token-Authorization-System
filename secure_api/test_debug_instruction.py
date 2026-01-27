import requests
import time

BASE_URL = "http://127.0.0.1:5000"

def run_flow():
    session = requests.Session()
    username = f"test_user_{int(time.time())}"
    password = "secure_password"

    print(f"--- 1. Registering user '{username}' ---")
    resp = session.post(f"{BASE_URL}/register", json={"username": username, "password": password})
    print(f"Response: {resp.status_code} - {resp.text}")

    print(f"\n--- 2. Logging in ---")
    resp = session.post(f"{BASE_URL}/login", json={"username": username, "password": password})
    print(f"Response: {resp.status_code} - {resp.text}")
    
    if resp.status_code != 200:
        print("Login failed, stopping.")
        return

    user_id = resp.json().get('user_id')
    
    print("\n[!] Automated testing of OTP flow is blocked because I cannot see the server's stdout for the OTP.")
    print("However, the issue with your Postman request is clear:")
    print("You are sending 'token' and 'signature' in the JSON BODY.")
    print("The server expects them in the HEADERS.")

if __name__ == "__main__":
    print("To fix your Postman request:")
    print("1. Click on the 'Headers' tab (next to 'Params' and 'Auth').")
    print("2. Add a new key 'Authorization' with your token value.")
    print("3. Add a new key 'X-Signature' with your signature value.")
    print("4. Remove the JSON body or keep it empty.")
    print("5. Send the request.")
