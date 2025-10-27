# Secure-File-Storage-System-with-AES
🔒 SecureFileVaultPro

SecureFileVaultPro is a professional file encryption and decryption application built with Python, PyQt5, and Cryptography.
It allows users to securely store, encrypt, decrypt, and manage files locally using AES-256 encryption with key derivation via PBKDF2.

📘 Project Overview

In the digital age, protecting sensitive data is a critical requirement.
SecureFileVaultPro ensures confidentiality, integrity, and usability by combining strong encryption with a simple, intuitive GUI.
It’s designed for individuals and organizations seeking reliable local file protection.

screenshots of the project GUI: 
<img width="900" height="597" alt="image" src="https://github.com/user-attachments/assets/e5abaa47-cbd7-47af-88a7-057bcd2f0b5b" />
<img width="896" height="582" alt="image" src="https://github.com/user-attachments/assets/c3203566-494b-411b-a82d-dc220964ddc0" />
<img width="895" height="580" alt="image" src="https://github.com/user-attachments/assets/d0aec9f5-0d9e-4ed8-9667-77e7a24161d1" />
<img width="893" height="581" alt="image" src="https://github.com/user-attachments/assets/6fa64cc0-07fe-41a6-8cf1-d802ac8a1c6e" />



🚀 Features

AES-256 (CTR Mode) encryption for top-level data security

PBKDF2-based key derivation using a master password

HMAC-SHA256 integrity verification

Professional PyQt5 GUI with progress tracking

File Viewer for encrypted/decrypted content

Activity logs for tracking operations

Tamper detection via integrity checks

🛠️ Tools & Technologies

Programming Language: Python 3.x

Libraries:

PyQt5 – GUI development

cryptography – AES encryption/decryption & HMAC

json, os, base64 – File handling and encoding

IDE: Visual Studio Code / PyCharm

Storage: Local file system

🧩 Project Structure
SecureFileVaultPro/
│
├── app.py                # Main GUI application
├── crypto_backend.py     # AES encryption/decryption logic
├── utils.py              # Logging, metadata, and helper functions
├── assets/               # Icons, images, or resources
├── logs/                 # Encrypted/decrypted file logs
└── README.md             # Project documentation

⚙️ Installation
1. Clone the repository
git clone https://github.com/<your-username>/SecureFileVaultPro.git
cd SecureFileVaultPro

2. Install dependencies
pip install pyqt5 cryptography

3. Run the application
python app.py

🔐 How It Works

Launch the application.

Set or enter your master password.

Choose a file to encrypt or decrypt.

View logs and metadata of previous operations.

Optionally open encrypted/decrypted files directly from the app.

🧠 Core Concepts

AES-256 (CTR Mode): Provides strong, symmetric encryption.

PBKDF2 with SHA-256: Derives keys from passwords with random salt.

HMAC-SHA256: Ensures data has not been tampered with.

🧪 Testing

The system has been tested with:

Text, image, and PDF files for correctness

Integrity checks using intentionally modified data

GUI validation for smooth user experience

📄 Future Enhancements

Cloud synchronization support

Biometric authentication

Password recovery mechanisms

File shredding (secure deletion)

👨‍💻 Developer

Vishal
Internship Project at Elevate Labs

