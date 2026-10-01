import base64
import json
from pathlib import Path
from uuid import uuid4

from flask import Flask, render_template, request, send_from_directory, url_for
from werkzeug.utils import secure_filename

from crypto import (
    AES_GCM_NONCE_SIZE,
    AES_GCM_TAG_SIZE,
    KEYS_DIR,
    decrypt_aes_key_rsa,
    decrypt_file_aes,
    encrypt_aes_key_rsa,
    encrypt_file_aes,
    ensure_rsa_keypairs,
    generate_aes_key,
    load_private_key,
    load_public_key,
)

app = Flask(__name__)
PROJECT_DIR = Path(__file__).resolve().parent
ENCRYPTED_DIR = PROJECT_DIR / "encrypted"
DECRYPTED_DIR = PROJECT_DIR / "decrypted"
ensure_rsa_keypairs()


@app.route("/")
def home():
    return render_template(
        "index.html",
        sender_public_available=(KEYS_DIR / "sender_public.pem").is_file(),
        receiver_public_available=(KEYS_DIR / "receiver_public.pem").is_file(),
    )


def _decode_package_field(package, field_name):
    value = package.get(field_name)
    if not isinstance(value, str):
        raise ValueError("Invalid encrypted package")
    return base64.b64decode(value, validate=True)


def _decrypt_package(package_data):
    package = json.loads(package_data)
    if (
        not isinstance(package, dict)
        or package.get("format") != "sfs-package-v1"
        or package.get("file_encryption") != "AES-256-GCM"
        or package.get("key_encryption") != "RSA-OAEP-SHA256"
    ):
        raise ValueError("Unsupported encrypted package")

    original_filename = package.get("file_name")
    if not isinstance(original_filename, str):
        raise ValueError("Invalid encrypted package filename")
    original_filename = secure_filename(original_filename)
    if not original_filename:
        raise ValueError("Invalid encrypted package filename")

    ciphertext = _decode_package_field(package, "ciphertext")
    nonce = _decode_package_field(package, "nonce")
    tag = _decode_package_field(package, "tag")
    encrypted_aes_key = _decode_package_field(package, "encrypted_aes_key")
    if len(nonce) != AES_GCM_NONCE_SIZE or len(tag) != AES_GCM_TAG_SIZE:
        raise ValueError("Invalid AES-GCM parameters")

    receiver_private_key = load_private_key(KEYS_DIR / "receiver_private.pem")
    aes_key = decrypt_aes_key_rsa(encrypted_aes_key, receiver_private_key)
    decrypted_data = decrypt_file_aes(ciphertext, aes_key, nonce, tag)
    del aes_key
    return original_filename, decrypted_data


@app.route("/send", methods=["GET", "POST"])
def send_file():
    error = None
    if request.method == "POST":
        uploaded_file = request.files.get("file")
        if uploaded_file is None or not uploaded_file.filename:
            error = "Select a file to encrypt."
        else:
            original_filename = secure_filename(uploaded_file.filename)
            if not original_filename:
                error = "The selected filename is not valid."
            else:
                file_data = uploaded_file.read()
                aes_key = generate_aes_key()
                ciphertext, nonce, tag = encrypt_file_aes(file_data, aes_key)
                receiver_public_key = load_public_key(KEYS_DIR / "receiver_public.pem")
                encrypted_aes_key = encrypt_aes_key_rsa(aes_key, receiver_public_key)
                del aes_key
                package = {
                    "format": "sfs-package-v1",
                    "file_name": original_filename,
                    "file_encryption": "AES-256-GCM",
                    "key_encryption": "RSA-OAEP-SHA256",
                    "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                    "nonce": base64.b64encode(nonce).decode("ascii"),
                    "tag": base64.b64encode(tag).decode("ascii"),
                    "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode("ascii"),
                }

                ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)
                output_filename = f"{uuid4().hex}.sfs"
                output_path = ENCRYPTED_DIR / output_filename
                output_path.write_text(
                    json.dumps(package, separators=(",", ":")),
                    encoding="utf-8",
                )
                return render_template(
                    "send.html",
                    encrypted_filename=output_filename,
                    download_url=url_for("download_encrypted_package", filename=output_filename),
                )

    return render_template("send.html", error=error)


@app.route("/receive", methods=["GET", "POST"])
def receive_file():
    error = None
    if request.method == "POST":
        uploaded_package = request.files.get("package")
        if uploaded_package is None or not uploaded_package.filename:
            error = "Select an encrypted package to decrypt."
        else:
            try:
                original_filename, decrypted_data = _decrypt_package(uploaded_package.read())
                DECRYPTED_DIR.mkdir(parents=True, exist_ok=True)
                decrypted_filename = f"{uuid4().hex}_{original_filename}"
                (DECRYPTED_DIR / decrypted_filename).write_bytes(decrypted_data)
                return render_template(
                    "receive.html",
                    decrypted_filename=decrypted_filename,
                    original_filename=original_filename,
                )
            except (ValueError, TypeError):
                error = "Could not decrypt this package. Verify it is intact and intended for this receiver."

    return render_template("receive.html", error=error)


@app.route("/encrypted/<path:filename>")
def download_encrypted_package(filename):
    return send_from_directory(ENCRYPTED_DIR, filename, as_attachment=True)


@app.route("/decrypted/<path:filename>")
def download_decrypted_file(filename):
    return send_from_directory(DECRYPTED_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
