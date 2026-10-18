# ransomeware-poc
This repo is to demonstrate the concept and a POC of how ransomeware works.

# File Encryptor (AES-256 + RSA key wrap)

Encrypts a file with a random AES-256 key, then locks that key with an RSA public key. Only the holder of the matching RSA private key can recover the AES key and decrypt the file.

## Requirements

```bash
pip install cryptography
```

## Usage

```bash
python encrypt.py <input> --publickey <public_key.pem> [-o <output>]
```

- `input` — the file to encrypt
- `--publickey` — path to the RSA public key (PEM or DER)
- `-o, --output` — output path (default: `<input>.enc`)

### Example

```bash
python encrypt.py secret.pdf --publickey public_key.pem
```

## How it works

1. Generates a random AES-256 key and IV.
2. Encrypts the file with AES-256-CBC (PKCS7 padding), streamed in 64 KB chunks.
3. Wraps the AES key with the RSA public key using OAEP (SHA-256).
4. Appends the IV (16 bytes) and the wrapped key to the end of the encrypted file.

## Output layout

```
[ AES-encrypted data ][ IV (16 bytes) ][ RSA-wrapped AES key ]
```

The plaintext AES key is never stored — only the RSA private key can unwrap it.
