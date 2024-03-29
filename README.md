# Password Manager System README

## Overview
This Password Manager System provides a secure and convenient solution for managing passwords. It includes features such as registration, login, 2FA setup, password storage, and more.

## Features

### Registration
- Users can register with their email and password.
- Password requirements:
  - Combination of capital and lowercase letters, symbols, and numbers.
  - Userword confirmation.
  - Validation checks will be performed.
- Clicking the "Submit" button takes users to the next page for setting up 2FA using Google Authenticator.
  - OTP (One-Time Password) needs to be entered once for verification.
- Passwords will be securely hashed before saving to the database.

### Login
- Users can log in using their registered email and password.
- Validation checks against the database.
- After login, users are prompted to input the OTP generated from the Google Authenticator app for additional security.

### Forgot Password
- Users can reset their password by entering their email.
- A password reset link will be sent to the provided email address.
- Users can then log in using the new password.

### Dashboard
- Requires login for access.
- Allows users to manage their passwords (add, edit, delete).
- Stored passwords are encrypted using AES-256 encryption for enhanced security.
- Passwords are generated with strong, random-length (>8 characters) to enhance security.
- Tests password strength and provides alerts if necessary.
- Only allows copying passwords (no reveal) to prevent unauthorized access.
- Logout option available for secure session management.

## Security Measures
- Passwords are securely hashed before saving to the database.
- Two-Factor Authentication (2FA) using Google Authenticator adds an extra layer of security during login.
- Passwords stored in the database are encrypted using AES-256 encryption.
- Password strength is tested and alerts are provided to ensure strong passwords are used.
- Secure session management with the option to logout.

## Usage
1. **Registration**: Users can register with their email and password.
2. **Login**: Registered users can log in using their email and password.
3. **2FA Setup**: After login, users are prompted to set up 2FA using Google Authenticator.
4. **Forgot Password**: Users can reset their password if forgotten by providing their email.
5. **Dashboard**: After login, users can access the dashboard to manage their passwords securely.
6. **Logout**: Users can logout for secure session management.

## Disclaimer
This Password Manager System is provided as-is and should be used for educational or personal use only. While efforts have been made to ensure security, it's recommended to review and customize the system according to specific security requirements.
