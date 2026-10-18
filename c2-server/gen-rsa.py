"""
Generate an RSA public/private key pair and save them as PEM files.

Requires:  pip install cryptography
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def generate_keys(key_size=2048, password=None):
    # 1. Generate the private key (the public key is derived from it)
    private_key = rsa.generate_private_key(
        public_exponent=65537,   # standard, secure choice
        key_size=key_size,       # 2048 minimum; 3072 or 4096 for longer-term use
    )
    public_key = private_key.public_key()

    # 2. Serialize the private key to PEM (optionally encrypted with a password)
    encryption = (
        serialization.BestAvailableEncryption(password.encode())
        if password else serialization.NoEncryption()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    # 3. Serialize the public key to PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # 4. Save to files
    with open("./c2-server/private_key.pem", "wb") as f:
        f.write(private_pem)
    with open("./victim/public_key.rsa", "wb") as f:
        f.write(public_pem)

    return private_key, public_key


def demo(private_key, public_key):
    """Quick check: encrypt with the public key, decrypt with the private key."""
    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    message = b"Hello, RSA!"
    ciphertext = public_key.encrypt(message, oaep)
    plaintext = private_key.decrypt(ciphertext, oaep)
    print("Decrypted:", plaintext.decode())

    # Sign with the private key, verify with the public key
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                      salt_length=padding.PSS.MAX_LENGTH)
    signature = private_key.sign(message, pss, hashes.SHA256())
    public_key.verify(signature, message, pss, hashes.SHA256())  # raises if invalid
    print("Signature verified.")


def load_keys(password=None):
    """Load the keys back from the PEM files."""
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=password.encode() if password else None
        )
    with open("../victim/public_key.rsa", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key


if __name__ == "__main__":
    priv, pub = generate_keys(key_size=2048)
    print("Saved private_key.pem and ../victim/public_key.rsa")
    demo(priv, pub)