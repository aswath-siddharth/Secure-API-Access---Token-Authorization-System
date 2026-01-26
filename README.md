# Secure API Access - Token Authorization System

This repository contains a secure API implementation demonstrating token-based authorization with Role-Based Access Control (RBAC) and Two-Factor Authentication (OTP).

## Overview

The application is built using **Flask** and implements a custom security mechanism involving:
- **User Registration** with bcrypt password hashing.
- **Login** with simulated OTP (One-Time Password) generation.
- **Token Generation** using HMAC-SHA256 signatures.
- **Role-Based Access Control** (RBAC) protecting specific endpoints.

## Project Structure

The core logic resides in the `secure_api` directory:
- `app.py`: The main Flask application containing routes and security logic.
- `users.db`: SQLite database file (created automatically if missing) storing user data.
- `requirements.txt`: List of Python dependencies.

## Prerequisites

- Python 3.x installed.

## Installation

1. Clone the repository and navigate to the project directory:
   ```bash
   cd Secure-API-Access---Token-Authorization-System
   ```

2. Navigate to the `secure_api` folder:
   ```bash
   cd secure_api
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Start the Flask server:
   ```bash
   python app.py
   ```
   The server will start on `http://127.0.0.1:5000/`.

2. Use an API client like Postman or `curl` to interact with the endpoints.

## API Endpoints

### 1. Register User
Create a new user account.
- **URL**: `/register`
- **Method**: `POST`
- **Headers**: `Content-Type: application/json`
- **Body**:
  ```json
  {
    "username": "your_username",
    "password": "your_password",
    "role": "ADMIN" 
  }
  ```
  *(Note: `role` is optional and defaults to `USER` if not specified. Use `ADMIN` to test protected routes.)*

### 2. Login
Authenticate with credentials to trigger an OTP.
- **URL**: `/login`
- **Method**: `POST`
- **Headers**: `Content-Type: application/json`
- **Body**:
  ```json
  {
    "username": "your_username",
    "password": "your_password"
  }
  ```
- **Response**: `{"message": "OTP sent"}`
- **Note**: The OTP is printed to the **server console** (terminal) where the app is running.

### 3. Verify OTP & Get Token
Verify the OTP to receive an access token.
- **URL**: `/verify-otp`
- **Method**: `POST`
- **Headers**: `Content-Type: application/json`
- **Body**:
  ```json
  {
    "user_id": 1, 
    "otp": 123456
  }
  ```
  *(Note: You currently need to know the `user_id` from the database or infer it since the login endpoint does not return it in this version.)*
- **Response**:
  ```json
  {
    "message": "OTP verified",
    "token": "...",
    "signature": "..."
  }
  ```

### 4. Admin Access
Access a protected route requiring `ADMIN` role.
- **URL**: `/admin`
- **Method**: `GET`
- **Headers**:
  - `Token`: `<your_token_from_verify_otp>`
  - `Signature`: `<your_signature_from_verify_otp>`
- **Response**: 
  - If authorized: `{"message": "Welcome Admin"}`
  - If unauthorized: `{"error": "Access denied"}`

## Security Mechanisms

- **Password Storage**: Uses `bcrypt` to hash passwords before storing them in the SQLite database.
- **Token Integrity**: Uses HMAC (Hash-based Message Authentication Code) with SHA256 to sign tokens, preventing tampering.
- **Replay Protection**: Tokens include timestamps and expiry validation.

## Troubleshooting

- **Database Errors**: If you encounter issues, try deleting `users.db` and restarting the application to re-initialize the database.
- **Invalid Credentials**: Ensure you are using the correct username and password.
- **OTP Issues**: Check the server console output for the generated OTP.
