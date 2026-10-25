/*
 * Secure Notes Lab — Frida Hook
 * ==============================
 * Target : com.mobilehackinglab.securenotes
 * Purpose: Intercept the ContentProvider at runtime to:
 *   1. See every PIN attempt made against the provider
 *   2. Capture the decrypted secret the moment it is produced
 *   3. Log the AES key material (key, IV) for each attempt
 *
 * Usage:
 *   frida -U -f com.mobilehackinglab.securenotes -l frida_hook_securenotes.js --no-pause
 *
 * Or attach to a running process:
 *   frida -U com.mobilehackinglab.securenotes -l frida_hook_securenotes.js
 */

Java.perform(function () {

    // ─────────────────────────────────────────────────────────────────────────
    // Hook 1: ContentProvider.query()
    // Intercepts every query call to the SecretDataProvider.
    // This shows us the URI and the selection string (which contains the PIN).
    // ─────────────────────────────────────────────────────────────────────────
    var SecretDataProvider = Java.use("com.mobilehackinglab.securenotes.SecretDataProvider");

    SecretDataProvider.query.overload(
        "android.net.Uri",
        "[Ljava.lang.String;",
        "java.lang.String",
        "[Ljava.lang.String;",
        "java.lang.String"
    ).implementation = function (uri, projection, selection, selectionArgs, sortOrder) {

        console.log("\n[query] ─────────────────────────────────────");
        console.log("[query] URI       : " + uri);
        console.log("[query] selection : " + selection);   // e.g. "pin=2580"

        // Extract the PIN from the selection string
        if (selection && selection.startsWith("pin=")) {
            var pin = selection.substring(4);
            console.log("[query] PIN tried : " + pin);
        }

        // Call the original query() and capture the result
        var cursor = this.query(uri, projection, selection, selectionArgs, sortOrder);

        if (cursor != null) {
            console.log("[query] ✓ Query returned a cursor — decryption SUCCEEDED!");
            // Move to first row and read the "Secret" column
            if (cursor.moveToFirst()) {
                var secret = cursor.getString(cursor.getColumnIndex("Secret"));
                console.log("[query] ✓ Secret : " + secret);
            }
            cursor.moveToPosition(-1); // Reset cursor position for the caller
        } else {
            console.log("[query] ✗ No result — wrong PIN or decryption failed.");
        }

        return cursor;
    };

    // ─────────────────────────────────────────────────────────────────────────
    // Hook 2: decryptSecret()
    // This is the private method that does the actual AES decryption.
    // We hook it to see the PIN being used and the plaintext result.
    // ─────────────────────────────────────────────────────────────────────────
    SecretDataProvider.decryptSecret.implementation = function (pin) {
        console.log("\n[decryptSecret] Called with PIN: " + pin);

        var result = this.decryptSecret(pin);   // Call original

        if (result != null) {
            console.log("[decryptSecret] ✓ Decrypted successfully!");
            console.log("[decryptSecret] ✓ Plaintext: " + result);
        } else {
            console.log("[decryptSecret] ✗ Decryption returned null (wrong PIN).");
        }

        return result;
    };

    // ─────────────────────────────────────────────────────────────────────────
    // Hook 3: generateKeyFromPin()
    // This derives the AES key from the PIN using PBKDF2.
    // We log the raw key bytes to show exactly what key material is produced.
    // ─────────────────────────────────────────────────────────────────────────
    SecretDataProvider.generateKeyFromPin.implementation = function (pin) {
        console.log("\n[generateKeyFromPin] Deriving AES key for PIN: " + pin);

        var keyBytes = this.generateKeyFromPin(pin);   // Call original

        // Convert byte array to hex string for display
        var hex = "";
        for (var i = 0; i < keyBytes.length; i++) {
            hex += ("0" + (keyBytes[i] & 0xff).toString(16)).slice(-2);
        }
        console.log("[generateKeyFromPin] Derived key (hex): " + hex);

        return keyBytes;
    };

    // ─────────────────────────────────────────────────────────────────────────
    // Hook 4: Javax Cipher.doFinal()
    // Low-level hook — intercepts the raw AES decryption output.
    // Useful to see the decrypted bytes before padding removal.
    // ─────────────────────────────────────────────────────────────────────────
    var Cipher = Java.use("javax.crypto.Cipher");

    Cipher.doFinal.overload("[B").implementation = function (input) {
        var result = this.doFinal(input);   // Call original

        // Convert to string to check if it looks like our secret
        try {
            var str = Java.use("java.lang.String").$new(result, "UTF-8");
            // Only log if it looks like printable ASCII (not garbage from wrong PINs)
            if (/^[\x20-\x7E\x09\x0A\x0D]+$/.test(str.toString().trim())) {
                console.log("\n[Cipher.doFinal] ✓ Decrypted bytes look printable!");
                console.log("[Cipher.doFinal] Raw output: " + str);
            }
        } catch (e) {
            // Garbled bytes from wrong PIN → ignore
        }

        return result;
    };

    console.log("\n[*] Frida hooks active on com.mobilehackinglab.securenotes");
    console.log("[*] Hooks installed:");
    console.log("    - SecretDataProvider.query()");
    console.log("    - SecretDataProvider.decryptSecret()");
    console.log("    - SecretDataProvider.generateKeyFromPin()");
    console.log("    - javax.crypto.Cipher.doFinal()");
    console.log("[*] Now trigger a query — e.g. via adb:");
    console.log('    adb shell content query --uri content://com.mobilehackinglab.securenotes.secretprovider/ --where "pin=2580"');
    console.log("");
});
