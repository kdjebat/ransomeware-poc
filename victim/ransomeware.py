#!/usr/bin/env python3
import argparse
import os
import sys
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CHUNK_SIZE = 64 * 1024


def encrypt_file(in_path, out_path):
    key = os.urandom(32)   # AES-256 key — 32 bytes
    iv  = os.urandom(16)   # AES IV      — 16 bytes

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    padder    = sym_padding.PKCS7(algorithms.AES.block_size).padder()

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        for chunk in iter(lambda: fin.read(CHUNK_SIZE), b""):
            fout.write(encryptor.update(padder.update(chunk)))
        fout.write(encryptor.update(padder.finalize()) + encryptor.finalize())

    return key, iv


def load_public_key(pub_pem_path):
    try:
        with open(pub_pem_path, "rb") as f:
            data = f.read()
    except OSError as e:
        sys.exit(f"Error: can't read public key: {e}")

    try:
        key = serialization.load_pem_public_key(data)
    except ValueError:
        try:
            key = serialization.load_der_public_key(data)
        except ValueError:
            sys.exit("Error: couldn't parse public key (expected PEM or DER).")

    if not isinstance(key, rsa.RSAPublicKey):
        sys.exit("Error: the key is not an RSA public key.")
    return key


def rsa_wrap_key(aes_key, public_key):
    """Encrypt the AES key with the RSA public key using OAEP."""
    return public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def main():
    # single parser — takes both arguments
    parser = argparse.ArgumentParser(description="AES-256-CBC file encrypt + RSA key wrap.")
    parser.add_argument("input",     help="file to encrypt")
    parser.add_argument("--public",  required=True, help="path to RSA public key (.pem)")
    parser.add_argument("-o", "--output", help="output path (default: <input>.enc)")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        sys.exit(f"Error: '{args.input}' is not a file.")

    out_path   = args.output or args.input + ".enc"
    public_key = load_public_key(args.public)

    # step 1 — encrypt file with AES, get plaintext key + IV back
    key, iv = encrypt_file(args.input, out_path)

    # step 2 — print original plaintext key and IV
    print(f"[*] IV  (hex) : {iv.hex()}")
    print(f"[*] Key (hex) : {key.hex()}")

    # step 3 — wrap (encrypt) the AES key with the RSA public key
    rsa_blob = rsa_wrap_key(key, public_key)
    print(f"[*] RSA blob  : {base64.b64encode(rsa_blob).decode()[:512]}...")

    # step 4 — only NOW append IV + RSA blob to bottom of encrypted file
    with open(out_path, "ab") as f:
        f.write(iv)        # 16 bytes  — needed to init AES decryption
        f.write(rsa_blob)  # 512 bytes — AES key locked with RSA public key

    print(f"\n[+] Encrypted : {args.input}")
    print(f"[+] Output    : {out_path}")
    print(f"\n[!] Plaintext key is gone. Only RSA private key can recover it.")


if __name__ == "__main__":
    main()