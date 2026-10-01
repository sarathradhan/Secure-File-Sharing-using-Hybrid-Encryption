"""RSA key management for the sender and receiver."""

from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


KEYS_DIR = Path(__file__).resolve().parent / "keys"
KEY_ROLES = ("sender", "receiver")
AES_GCM_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16
AES_256_KEY_SIZE = 32
AES_256_KEY_SIZE_ERROR = "AES-256 requires a 32-byte key"


def generate_aes_key() -> bytes:
	return get_random_bytes(32)


def encrypt_file_aes(file_data: bytes, aes_key: bytes) -> tuple[bytes, bytes, bytes]:
	if len(aes_key) != AES_256_KEY_SIZE:
		raise ValueError(AES_256_KEY_SIZE_ERROR)

	cipher = AES.new(
		aes_key,
		AES.MODE_GCM,
		nonce=get_random_bytes(AES_GCM_NONCE_SIZE),
		mac_len=AES_GCM_TAG_SIZE,
	)
	ciphertext, tag = cipher.encrypt_and_digest(file_data)
	return ciphertext, cipher.nonce, tag


def decrypt_file_aes(
	encrypted_data: bytes,
	aes_key: bytes,
	nonce: bytes,
	tag: bytes,
) -> bytes:
	if len(aes_key) != AES_256_KEY_SIZE:
		raise ValueError(AES_256_KEY_SIZE_ERROR)
	if len(nonce) != AES_GCM_NONCE_SIZE or len(tag) != AES_GCM_TAG_SIZE:
		raise ValueError("Invalid AES-GCM nonce or authentication tag length")

	cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=AES_GCM_TAG_SIZE)
	return cipher.decrypt_and_verify(encrypted_data, tag)


def encrypt_aes_key_rsa(aes_key: bytes, receiver_public_key: RSA.RsaKey) -> bytes:
	if len(aes_key) != AES_256_KEY_SIZE:
		raise ValueError(AES_256_KEY_SIZE_ERROR)
	if receiver_public_key.has_private():
		receiver_public_key = receiver_public_key.public_key()

	cipher = PKCS1_OAEP.new(receiver_public_key, hashAlgo=SHA256)
	return cipher.encrypt(aes_key)


def decrypt_aes_key_rsa(
	encrypted_aes_key: bytes,
	receiver_private_key: RSA.RsaKey,
) -> bytes:
	if not receiver_private_key.has_private():
		raise ValueError("A receiver private key is required")

	cipher = PKCS1_OAEP.new(receiver_private_key, hashAlgo=SHA256)
	aes_key = cipher.decrypt(encrypted_aes_key)
	if len(aes_key) != AES_256_KEY_SIZE:
		raise ValueError("The recovered key is not a 256-bit AES key")
	return aes_key


def generate_rsa_keypair(role: str, keys_dir: Path = KEYS_DIR) -> tuple[Path, Path]:
	if role not in KEY_ROLES:
		raise ValueError(f"role must be one of: {', '.join(KEY_ROLES)}")

	keys_dir = Path(keys_dir)
	keys_dir.mkdir(parents=True, exist_ok=True)
	key = RSA.generate(2048)
	private_path = keys_dir / f"{role}_private.pem"
	public_path = keys_dir / f"{role}_public.pem"
	private_path.write_bytes(key.export_key(format="PEM"))
	public_path.write_bytes(key.public_key().export_key(format="PEM"))
	private_path.chmod(0o600)
	return private_path, public_path


def ensure_rsa_keypairs(keys_dir: Path = KEYS_DIR) -> None:
	keys_dir = Path(keys_dir)
	for role in KEY_ROLES:
		private_path = keys_dir / f"{role}_private.pem"
		public_path = keys_dir / f"{role}_public.pem"
		if not private_path.is_file() or not public_path.is_file():
			generate_rsa_keypair(role, keys_dir)


def load_public_key(key_path: str | Path) -> RSA.RsaKey:
	key = RSA.import_key(Path(key_path).read_bytes())
	if key.has_private():
		raise ValueError("A public key file must not contain private key material")
	return key


def load_private_key(key_path: str | Path) -> RSA.RsaKey:
	key = RSA.import_key(Path(key_path).read_bytes())
	if not key.has_private():
		raise ValueError("The provided key file does not contain a private key")
	return key
