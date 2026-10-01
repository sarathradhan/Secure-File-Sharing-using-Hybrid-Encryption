# Secure File Sharing using Hybrid Encryption

A local Flask project for a Cryptography and Network Security course. Files are encrypted with AES-256-GCM, and each random AES key is protected with the receiver's RSA-2048 public key using RSA-OAEP with SHA-256.

## Current workflow

1. Open `/send`, choose a file, and encrypt it. The `.sfs` package contains the ciphertext, GCM nonce and tag, and RSA-encrypted AES key.
2. Transfer the `.sfs` package to the receiver.
3. Open `/receive` and upload the package. The receiver's private key unwraps the AES key, then AES-GCM authenticates and decrypts the file.
4. Download the decrypted file from the receiver page.

The plaintext AES key is held in memory only and is never stored. RSA private keys remain in `keys/` and are not exposed through the web pages. SHA-256 file digests, digital signatures, and network transfer are not implemented yet.

## Requirements

- Python 3.10 or newer
- pip

## Install and run

From this project directory, create and activate a virtual environment, install dependencies, and start Flask:

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

### Windows Command Prompt

```bat
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000 in your browser. Stop the development server with Ctrl+C.

This project uses Flask's development server and is intended for local coursework demonstrations, not production deployment.
