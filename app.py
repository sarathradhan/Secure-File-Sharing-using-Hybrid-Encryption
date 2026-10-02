import base64
import json
from pathlib import Path
from uuid import uuid4
from threading import Lock
import time

from flask import Flask, jsonify, render_template, request, send_from_directory, url_for
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

# These legacy routes remain available for comparison/testing. The new browser-to-browser
# workflow does not use the server-side private keys for file encryption/decryption.
ensure_rsa_keypairs()

PEERS = {}
PEER_MESSAGES = {}
PEER_TRANSFERS = {}
PEER_LOCK = Lock()
MAX_PACKAGE_SIZE = 35 * 1024 * 1024
PEER_TTL_SECONDS = 8
DEFAULT_DISPLAY_NAME = "Unnamed browser"
MAX_DISPLAY_NAME_LENGTH = 32

app.config["MAX_CONTENT_LENGTH"] = MAX_PACKAGE_SIZE


def _remove_stale_peers(now=None):
    now = time.time() if now is None else now
    stale_ids = [
        client_id
        for client_id, peer in PEERS.items()
        if now - peer.get("last_seen", peer["registered_at"]) > PEER_TTL_SECONDS
    ]
    for client_id in stale_ids:
        PEERS.pop(client_id, None)
        PEER_MESSAGES.pop(client_id, None)
        PEER_TRANSFERS.pop(client_id, None)


def _peer_payload(peer):
    return {
        "client_id": peer["client_id"],
        "display_name": peer.get("display_name", DEFAULT_DISPLAY_NAME),
        "public_keys": peer["public_keys"],
        "registered_at": peer["registered_at"],
        "last_seen": peer.get("last_seen", peer["registered_at"]),
    }


def _package_metadata(package):
    """Return non-secret package information suitable for the UI."""
    ciphertext = package.get("ciphertext", "")
    encrypted_aes_key = package.get("encrypted_aes_key", "")
    signature = package.get("signature", "")
    nonce = package.get("nonce", "")
    tag = package.get("tag", "")
    return {
        "format": package.get("format"),
        "file_name": package.get("file_name"),
        "file_size": package.get("file_size"),
        "sender_id": package.get("sender_id"),
        "recipient_id": package.get("recipient_id"),
        "file_encryption": package.get("file_encryption"),
        "key_encryption": package.get("key_encryption"),
        "hash_algorithm": package.get("hash_algorithm"),
        "signature_algorithm": package.get("signature_algorithm"),
        "ciphertext_size": package.get("ciphertext_size", max(0, len(ciphertext) * 3 // 4)),
        "nonce_size": package.get("nonce_size", max(0, len(nonce) * 3 // 4)),
        "tag_size": package.get("tag_size", max(0, len(tag) * 3 // 4)),
        "encrypted_aes_key_size": package.get("encrypted_aes_key_size", max(0, len(encrypted_aes_key) * 3 // 4)),
        "signature_size": package.get("signature_size", max(0, len(signature) * 3 // 4)),
        "sha256": package.get("sha256"),
    }


def _validate_secure_package(package):
    if not isinstance(package, dict):
        raise ValueError("Invalid secure package")

    required = (
        "format",
        "file_name",
        "file_size",
        "sender_id",
        "recipient_id",
        "file_encryption",
        "key_encryption",
        "hash_algorithm",
        "signature_algorithm",
        "ciphertext",
        "nonce",
        "tag",
        "encrypted_aes_key",
        "sha256",
        "signature",
    )
    if any(field not in package for field in required):
        raise ValueError("Incomplete secure package")

    if package["format"] != "sfs-package-v2":
        raise ValueError("Unsupported secure package format")
    if package["file_encryption"] != "AES-256-GCM":
        raise ValueError("Unsupported file encryption")
    if package["key_encryption"] != "RSA-OAEP-SHA256":
        raise ValueError("Unsupported key encryption")
    if package["hash_algorithm"] != "SHA-256":
        raise ValueError("Unsupported hash algorithm")
    if package["signature_algorithm"] != "RSA-PSS-SHA256":
        raise ValueError("Unsupported signature algorithm")

    filename = secure_filename(package["file_name"])
    if not filename:
        raise ValueError("Invalid package filename")
    package["file_name"] = filename

    for field in ("sender_id", "recipient_id", "sha256"):
        if not isinstance(package[field], str) or not package[field]:
            raise ValueError(f"Invalid package field: {field}")

    if not isinstance(package["file_size"], int) or package["file_size"] < 0:
        raise ValueError("Invalid package file size")

    for field in ("ciphertext", "nonce", "tag", "encrypted_aes_key", "signature"):
        if not isinstance(package[field], str):
            raise ValueError(f"Invalid package field: {field}")
        try:
            base64.b64decode(package[field], validate=True)
        except Exception as exc:
            raise ValueError(f"Invalid base64 package field: {field}") from exc

    try:
        if len(base64.b64decode(package["nonce"], validate=True)) != 12:
            raise ValueError("Invalid AES-GCM nonce")
        if len(base64.b64decode(package["tag"], validate=True)) != 16:
            raise ValueError("Invalid AES-GCM tag")
    except Exception as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("Invalid AES-GCM"):
            raise
        raise ValueError("Invalid AES-GCM parameters") from exc


@app.route("/")
def home():
    return render_template("index.html")


@app.post("/api/register")
def register_peer():
    data = request.get_json(silent=True) or {}
    client_id = data.get("client_id")
    display_name = data.get("display_name", "").strip()
    public_keys = data.get("public_keys")

    if not isinstance(client_id, str) or not client_id or len(client_id) > 128:
        return jsonify({"error": "Invalid client ID."}), 400

    if not display_name:
        display_name = DEFAULT_DISPLAY_NAME
    if len(display_name) > MAX_DISPLAY_NAME_LENGTH:
        return jsonify({
            "error": f"Display name must be {MAX_DISPLAY_NAME_LENGTH} characters or fewer."
        }), 400

    if not isinstance(public_keys, dict):
        return jsonify({"error": "RSA public keys are required."}), 400
    if not all(
        isinstance(public_keys.get(name), dict)
        and public_keys[name].get("kty") == "RSA"
        for name in ("signing", "encryption")
    ):
        return jsonify({"error": "Both RSA public keys are required."}), 400

    with PEER_LOCK:
        now = time.time()
        previous_peer = PEERS.get(client_id, {})
        PEERS[client_id] = {
            "client_id": client_id,
            "display_name": display_name,
            "public_keys": public_keys,
            "registered_at": previous_peer.get("registered_at", now),
            "last_seen": now,
        }
        PEER_MESSAGES.setdefault(client_id, [])
        PEER_TRANSFERS.setdefault(client_id, [])
        peers = [
            _peer_payload(peer)
            for peer_id, peer in PEERS.items()
            if peer_id != client_id
        ]

    return jsonify({"client_id": client_id, "peers": peers})


@app.get("/api/peers")
def list_peers():
    client_id = request.args.get("client_id", "")
    if not client_id:
        return jsonify({"error": "client_id is required."}), 400

    with PEER_LOCK:
        _remove_stale_peers()
        if client_id not in PEERS:
            return jsonify({"error": "Client is not registered."}), 404
        PEERS[client_id]["last_seen"] = time.time()
        peers = [
            _peer_payload(peer)
            for peer_id, peer in PEERS.items()
            if peer_id != client_id
        ]

    return jsonify({"peers": peers})


@app.post("/api/messages")
def send_message():
    data = request.get_json(silent=True) or {}
    sender_id = data.get("sender_id")
    recipient_id = data.get("recipient_id")
    message = data.get("message")

    if not all(isinstance(value, str) and value for value in (sender_id, recipient_id, message)):
        return jsonify({"error": "sender_id, recipient_id and message are required."}), 400
    if len(message) > 4096:
        return jsonify({"error": "Test message is too large."}), 400

    with PEER_LOCK:
        _remove_stale_peers()
        if sender_id not in PEERS or recipient_id not in PEERS:
            return jsonify({"error": "Both clients must be registered."}), 404
        PEERS[sender_id]["last_seen"] = time.time()
        PEER_MESSAGES.setdefault(recipient_id, []).append(
            {
                "message_id": uuid4().hex,
                "sender_id": sender_id,
                "message": message,
            }
        )

    return jsonify({"status": "queued"})


@app.get("/api/messages")
def receive_messages():
    client_id = request.args.get("client_id", "")
    if not client_id:
        return jsonify({"error": "client_id is required."}), 400

    with PEER_LOCK:
        _remove_stale_peers()
        if client_id not in PEERS:
            return jsonify({"error": "Client is not registered."}), 404
        PEERS[client_id]["last_seen"] = time.time()
        messages = PEER_MESSAGES.setdefault(client_id, [])
        PEER_MESSAGES[client_id] = []

    return jsonify({"messages": messages})


@app.post("/api/transfers")
def queue_secure_transfer():
    """Queue an already-encrypted browser package without decrypting it on Flask."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON secure package is required."}), 400

    try:
        _validate_secure_package(data)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    sender_id = data["sender_id"]
    recipient_id = data["recipient_id"]
    if sender_id == recipient_id:
        return jsonify({"error": "Sender and recipient must be different browsers."}), 400

    with PEER_LOCK:
        _remove_stale_peers()
        if sender_id not in PEERS or recipient_id not in PEERS:
            return jsonify({"error": "Both browsers must be connected before sending a file."}), 404

        registered_recipient_keys = PEERS[recipient_id]["public_keys"]
        if data.get("recipient_encryption_key_fingerprint") and data["recipient_encryption_key_fingerprint"] != registered_recipient_keys.get("encryption_fingerprint"):
            return jsonify({"error": "Recipient key identity changed."}), 409

        PEERS[sender_id]["last_seen"] = time.time()
        transfer_id = uuid4().hex
        package_json = json.dumps(data, separators=(",", ":"))
        PEER_TRANSFERS.setdefault(recipient_id, []).append(
            {
                "transfer_id": transfer_id,
                "sender_id": sender_id,
                "filename": data["file_name"],
                "size": data["file_size"],
                "package": data,
                "package_size": len(package_json.encode("utf-8")),
                "metadata": _package_metadata(data),
            }
        )

    return jsonify(
        {
            "status": "queued",
            "transfer_id": transfer_id,
            "filename": data["file_name"],
            "package_size": len(package_json.encode("utf-8")),
        }
    )


@app.get("/api/transfers")
def list_secure_transfers():
    client_id = request.args.get("client_id", "")
    if not client_id:
        return jsonify({"error": "client_id is required."}), 400

    with PEER_LOCK:
        _remove_stale_peers()
        if client_id not in PEERS:
            return jsonify({"error": "Client is not registered."}), 404
        PEERS[client_id]["last_seen"] = time.time()
        transfers = [
            {
                "transfer_id": item["transfer_id"],
                "sender_id": item["sender_id"],
                "sender_name": PEERS.get(item["sender_id"], {}).get(
                    "display_name", DEFAULT_DISPLAY_NAME
                ),
                "filename": item["filename"],
                "size": item["size"],
                "package_size": item["package_size"],
                "metadata": item["metadata"],
            }
            for item in PEER_TRANSFERS.setdefault(client_id, [])
        ]

    return jsonify({"transfers": transfers})


@app.get("/api/transfers/<transfer_id>/raw")
def download_raw_secure_transfer(transfer_id):
    """Download the exact JSON secure package without consuming the queued transfer."""
    client_id = request.args.get("client_id", "")
    if not client_id:
        return jsonify({"error": "client_id is required."}), 400

    with PEER_LOCK:
        _remove_stale_peers()
        if client_id not in PEERS:
            return jsonify({"error": "Client is not registered."}), 404
        PEERS[client_id]["last_seen"] = time.time()
        transfers = PEER_TRANSFERS.setdefault(client_id, [])
        item = next((entry for entry in transfers if entry["transfer_id"] == transfer_id), None)
        if item is None:
            return jsonify({"error": "Transfer not found."}), 404
        package_json = json.dumps(item["package"], indent=2)
        filename = secure_filename(item["filename"]) or "file"

    response = app.response_class(
        package_json,
        mimetype="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}.sfs.json"'
        },
    )
    return response


@app.get("/api/transfers/<transfer_id>")
def download_secure_transfer(transfer_id):
    client_id = request.args.get("client_id", "")
    if not client_id:
        return jsonify({"error": "client_id is required."}), 400

    with PEER_LOCK:
        _remove_stale_peers()
        if client_id not in PEERS:
            return jsonify({"error": "Client is not registered."}), 404
        PEERS[client_id]["last_seen"] = time.time()
        transfers = PEER_TRANSFERS.setdefault(client_id, [])
        item = next((entry for entry in transfers if entry["transfer_id"] == transfer_id), None)
        if item is None:
            return jsonify({"error": "Transfer not found."}), 404
        transfers.remove(item)

    return jsonify(item["package"])


# ---------------------------------------------------------------------------
# Legacy local encryption/decryption pages. These are retained so the existing
# coursework implementation remains available, but the new LAN workflow above
# performs cryptography in the browser endpoints instead.
# ---------------------------------------------------------------------------


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
                output_path.write_text(json.dumps(package, separators=(",", ":")), encoding="utf-8")
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


@app.errorhandler(413)
def request_entity_too_large(_error):
    return jsonify({"error": "The secure package is too large for this demo server."}), 413


if __name__ == "__main__":
    # HTTPS is required for browser Web Crypto on non-localhost LAN origins.
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context="adhoc")
