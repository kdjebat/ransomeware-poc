#!/usr/bin/env python3
import argparse
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CHUNK_SIZE = 64 * 1024
IV_SIZE    = 16    # AES IV always 16 bytes


def load_private_key(priv_pem_path):
    try:
        with open(priv_pem_path, "rb") as f:
            data = f.read()
    except OSError as e:
        sys.exit(f"Error: can't read private key: {e}")

    try:
        key = serialization.load_pem_private_key(data, password=None)
    except ValueError:
        try:
            key = serialization.load_der_private_key(data, password=None)
        except ValueError:
            sys.exit("Error: couldn't parse private key (expected PEM or DER).")

    return key


def get_blob_size(private_key):
    """Derive RSA blob size from the key — RSA-2048 = 256B, RSA-4096 = 512B."""
    return private_key.key_size // 8


def parse_encrypted_file(file_path, rsa_blob_size):
    """
    File layout on disk:
    [ ciphertext ][ IV — 16 bytes ][ RSA blob — N bytes ]

    N depends on RSA key size:
        RSA-2048 = 256 bytes
        RSA-4096 = 512 bytes
    """
    footer_size = IV_SIZE + rsa_blob_size
    file_size   = os.path.getsize(file_path)

    if file_size <= footer_size:
        sys.exit(f"Error: file too small ({file_size} bytes) for expected footer ({footer_size} bytes).")

    with open(file_path, "rb") as f:
        ciphertext = f.read(file_size - footer_size)   # everything before footer
        iv         = f.read(IV_SIZE)                   # next 16 bytes
        rsa_blob   = f.read(rsa_blob_size)             # last N bytes

    return ciphertext, iv, rsa_blob


def unwrap_aes_key(rsa_blob, private_key):
    """Decrypt the RSA blob with the private key to recover the plaintext AES key."""
    try:
        aes_key = private_key.decrypt(
            rsa_blob,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        sys.exit(f"Error: RSA decryption failed — wrong private key? ({e})")
    return aes_key


def decrypt_file(ciphertext, aes_key, iv, out_path):
    """AES-256-CBC decrypt the ciphertext and strip PKCS7 padding."""
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    unpadder  = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()

    with open(out_path, "wb") as fout:
        for i in range(0, len(ciphertext), CHUNK_SIZE):
            chunk = ciphertext[i:i + CHUNK_SIZE]
            fout.write(unpadder.update(decryptor.update(chunk)))
        fout.write(unpadder.update(decryptor.finalize()) + unpadder.finalize())


def main():
    parser = argparse.ArgumentParser(description="Decrypt a ransomware-encrypted file.")
    parser.add_argument("--private", required=True, help="path to RSA private key (.pem)")
    parser.add_argument("--f",       required=True, help="path to encrypted file (.enc)")
    parser.add_argument("-o", "--output", help="output path (default: replaces .enc with .decrypted)")
    args = parser.parse_args()

    if not os.path.isfile(args.f):
        sys.exit(f"Error: '{args.f}' not found.")
    if not os.path.isfile(args.private):
        sys.exit(f"Error: '{args.private}' not found.")

    out_path = args.output or (
        args.f.replace(".enc", ".decrypted") if args.f.endswith(".enc") else args.f + ".decrypted"
    )

    print(f"[*] Target file  : {args.f}")
    print(f"[*] Private key  : {args.private}")

    # step 1 — load private key first so we know the blob size
    print(f"\n[*] Loading private key...")
    private_key   = load_private_key(args.private)
    rsa_blob_size = get_blob_size(private_key)
    print(f"    RSA key size : {private_key.key_size}-bit ({rsa_blob_size} byte blob)")

    # step 2 — parse the file using the correct blob size
    print(f"\n[*] Parsing file layout...")
    ciphertext, iv, rsa_blob = parse_encrypted_file(args.f, rsa_blob_size)
    print(f"    Ciphertext   : {len(ciphertext)} bytes")
    print(f"    IV  (hex)    : {iv.hex()}")
    print(f"    RSA blob     : {len(rsa_blob)} bytes")

    # step 3 — unwrap the AES key using the RSA private key
    print(f"\n[*] Unwrapping AES key with RSA private key...")
    aes_key = unwrap_aes_key(rsa_blob, private_key)
    print(f"    Key (hex)    : {aes_key.hex()}")

    # step 4 — AES-256-CBC decrypt the file
    print(f"\n[*] Decrypting file...")
    decrypt_file(ciphertext, aes_key, iv, out_path)

    print(f"\n[+] Decrypted    : {args.f}")
    print(f"[+] Output       : {out_path}")


if __name__ == "__main__":
    main()