# Passlock

A minimal password manager with simple UI written in rust.

## Why?

Password managers are black boxes. I wanted something:

- simple - single encrypted JSON file, **no cloud, no sync, no browser extension**, simple stuff
- secure - Argon2id + AES-256-GCM, standard algorithms btw
- portable - if I remember my password, I can decrypt with any language that has Argon2 + AES-GCM libs

## Usage

```bash
# Initialize a new password file
passlock --init ~/.passwords.enc

# Open selector UI
passlock ~/.passwords.enc

# Edit in $EDITOR
passlock --edit ~/.passwords.enc

# Or set PASSLOCK_FILE env var
export PASSLOCK_FILE=~/.passwords.enc
passlock
passlock --edit
```

## File Format

Binary file: `[16 bytes salt][12 bytes nonce][ciphertext + auth tag]`

- **KDF**: Argon2id (m=19456, t=2, p=1)
- **Cipher**: AES-256-GCM

## Decrypt Without Passlock

If you lose access to passlock, decrypt with Python:

```python
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

with open("passwords.enc", "rb") as f:
    data = f.read()

salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
password = b"your-master-password"

key = hash_secret_raw(password, salt, time_cost=2, memory_cost=19456,
                      parallelism=1, hash_len=32, type=Type.ID)

print(AESGCM(key).decrypt(nonce, ciphertext, None).decode())
```

Dependencies: `pip install argon2-cffi cryptography`

## JSON Structure

```json
{
  "github.com": [
    {
      "name": "work",
      "fields": {
        "username": "work-user",
        "password": "work-pass",
        "api_token": "ghp_xxxx"
      }
    },
    {
      "name": "personal",
      "fields": {
        "username": "personal-user",
        "password": "personal-pass"
      }
    }
  ],
  "aws": [
    {
      "name": "prod",
      "fields": {
        "access_key": "AKIA...",
        "secret_key": "wJal..."
      }
    }
  ]
}
```

Structure: `site -> accounts[] -> fields{}`. Fields are arbitrary key-value pairs.
