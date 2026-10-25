#!/usr/bin/env python3
"""
Secure Notes Lab - PIN Brute Force Script
==========================================
Target: com.mobilehackinglab.securenotes
Vulnerability: Exported ContentProvider (SecretDataProvider)

How it works:
  1. The APK ships with assets/config.properties containing an AES-encrypted secret.
  2. The ContentProvider decrypts it using a PIN entered by the user.
  3. The decryption key is derived from the PIN via PBKDF2WithHmacSHA1.
  4. Since the PIN is only 4 digits (0000-9999), we can brute force all possibilities locally.
  5. We know decryption succeeded when the output has valid PKCS7 padding + is valid UTF-8.
"""

import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ──────────────────────────────────────────────────────────────────────────────
# Step 1: Values extracted from assets/config.properties inside the APK
#         Run: unzip app.apk assets/config.properties -d /tmp/out
# ──────────────────────────────────────────────────────────────────────────────
ENCRYPTED_SECRET_B64 = "bTjBHijMAVQX+CoyFbDPJXRUSHcTyzGaie3OgVqvK5w="
SALT_B64             = "m2UvPXkvte7fygEeMr0WUg=="
IV_B64               = "L15Je6YfY5owgIckR9R3DQ=="
ITERATION_COUNT      = 10000

# Decode from Base64 to raw bytes
encrypted_secret = base64.b64decode(ENCRYPTED_SECRET_B64)
salt             = base64.b64decode(SALT_B64)
iv               = base64.b64decode(IV_B64)


def derive_key(pin: str) -> bytes:
    """
    Replicates the app's generateKeyFromPin() method.

    The app uses:
      - Algorithm : PBKDF2WithHmacSHA1
      - Key length: 256 bits (0x100 in the smali = bit length, so 32 bytes)
      - Salt      : from config.properties
      - Iterations: from config.properties (10000)
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=32,             # 256-bit AES key
        salt=salt,
        iterations=ITERATION_COUNT,
        backend=default_backend()
    )
    return kdf.derive(pin.encode("utf-8"))


def try_decrypt(pin: str) -> str | None:
    """
    Replicates the app's decryptSecret() method.

    The app uses:
      - Cipher   : AES/CBC/PKCS5Padding
      - Key      : derived by derive_key()
      - IV       : from config.properties

    Returns the decrypted string if the PIN is correct, or None if wrong.
    """
    key = derive_key(pin)

    try:
        cipher    = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_secret) + decryptor.finalize()

        # Remove PKCS7 padding (same as PKCS5 for AES block size)
        pad_len = decrypted_padded[-1]
        if not (1 <= pad_len <= 16):
            return None                          # Invalid padding → wrong PIN

        plaintext_bytes = decrypted_padded[:-pad_len]
        return plaintext_bytes.decode("utf-8")   # Valid UTF-8 → correct PIN!

    except Exception:
        return None                              # Any error = wrong PIN


# ──────────────────────────────────────────────────────────────────────────────
# Step 2: Brute force all 4-digit PINs (0000 → 9999)
# ──────────────────────────────────────────────────────────────────────────────
print("[*] Starting brute force — trying all 4-digit PINs...")
print(f"[*] Encrypted secret : {ENCRYPTED_SECRET_B64}")
print(f"[*] Salt             : {SALT_B64}")
print(f"[*] IV               : {IV_B64}")
print(f"[*] Iterations       : {ITERATION_COUNT}")
print()

for pin_int in range(10000):
    pin    = f"{pin_int:04d}"          # Zero-pad to 4 digits: 0 → "0000"
    secret = try_decrypt(pin)

    if pin_int % 1000 == 0:
        print(f"[~] Trying PIN {pin}...")

    if secret is not None:
        print()
        print(f"[+] ✓ PIN FOUND    : {pin}")
        print(f"[+] ✓ Secret/Flag  : {secret}")
        print()
        print("── Verification ──────────────────────────────────────────────────")
        print(f"adb shell content query \\")
        print(f"  --uri content://com.mobilehackinglab.securenotes.secretprovider/ \\")
        print(f"  --where \"pin={pin}\"")
        break
else:
    print("[-] PIN not found in range 0000-9999")
