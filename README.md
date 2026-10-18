# ransomeware-poc
This repo is to demonstrate the concept and a POC of how ransomeware works.

## How it works

1. Generate an RSA key first. The code wil generate a Public and Private key. The public key will be placed under the victim folder, where as the private key is being held in the c2-server folder.
2. Run the File Encryptor

### Notes
The code uses AES 256 to encrypt files. Once the files are encrypted, the IV and key are then encrypted with the RSA Public key. The result of that, will be appended onto the newly locked file.

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


# Decrypting the Ransomeware
```bash
py .\c2-server\decrypt-ransomeware.py --private .\c2-server\private_key.pem --f .\artefacts\skull.png 
```
