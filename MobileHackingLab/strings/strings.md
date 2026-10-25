# MobileHackingLab - Strings Challenge Write-up

## Overview

**Platform:** MobileHackingLab  
**Challenge:** Strings  
**Category:** Android / Reverse Engineering  
**Flag Format:** `MHL{...}`  
**Flag:** `MHL{IN_THE_MEMORY}`

## Introduction

Strings is an Android CTF challenge that covers several core mobile security concepts including Android Intents, SharedPreferences, AES decryption, and native library memory analysis using Frida. The goal is to extract a flag that is hidden inside a native library's memory at runtime.

## Tools Used

- JADX — decompile the APK and read Java/Kotlin source
- ADB — interact with the Android device
- Frida 17 — dynamic instrumentation and memory scanning

## Reconnaissance

### Decompiling the APK

After decompiling the APK with JADX, two activities stand out in `AndroidManifest.xml`:

```xml
<activity
    android:name="com.mobilehackinglab.challenge.Activity2"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data
            android:scheme="mhl"
            android:host="labs"/>
    </intent-filter>
</activity>

<activity
    android:name="com.mobilehackinglab.challenge.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```

`Activity2` is exported and accepts a browsable Intent with the custom URI scheme `mhl` and host `labs`. This is the target.

### Analyzing MainActivity

`MainActivity` loads a native library called `challenge` and displays text from a JNI call. More importantly, it contains a public method called `KLOW()`:

```java
public final void KLOW() {
    SharedPreferences sharedPreferences = getSharedPreferences("DAD4", 0);
    SharedPreferences.Editor editor = sharedPreferences.edit();
    SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy", Locale.getDefault());
    String cu_d = sdf.format(new Date());
    editor.putString("UUU0133", cu_d);
    editor.apply();
}
```

This method writes today's date in `dd/MM/yyyy` format into SharedPreferences under the key `UUU0133` in the preferences file named `DAD4`. This turns out to be a prerequisite for `Activity2`.

### Analyzing Activity2

`Activity2.onCreate()` performs three sequential validation checks before loading the flag native library:

```java
protected void onCreate(Bundle savedInstanceState) {
    // Check 1: SharedPreferences date match
    SharedPreferences sharedPreferences = getSharedPreferences("DAD4", 0);
    String u_1 = sharedPreferences.getString("UUU0133", null);
    boolean isActionView = Intrinsics.areEqual(getIntent().getAction(), "android.intent.action.VIEW");
    boolean isU1Matching = Intrinsics.areEqual(u_1, cd());

    if (isActionView && isU1Matching) {
        Uri uri = getIntent().getData();

        // Check 2: URI scheme and host
        if (uri != null && Intrinsics.areEqual(uri.getScheme(), "mhl")
                        && Intrinsics.areEqual(uri.getHost(), "labs")) {

            String base64Value = uri.getLastPathSegment();
            byte[] decodedValue = Base64.decode(base64Value, 0);

            if (decodedValue != null) {
                String ds = new String(decodedValue, Charsets.UTF_8);
                byte[] bytes = "your_secret_key_1234567890123456".getBytes(Charsets.UTF_8);
                String str = decrypt("AES/CBC/PKCS5Padding", "bqGrDKdQ8zo26HflRsGvVA==",
                                     new SecretKeySpec(bytes, "AES"));

                // Check 3: decoded URI path must equal decrypted secret
                if (str.equals(ds)) {
                    System.loadLibrary("flag");
                    String s = getflag();
                    Toast.makeText(getApplicationContext(), s, 1).show();
                    return;
                }
            }
        }
    }
    // Any failure results in:
    finishAffinity();
    finish();
    System.exit(0);
}
```

If any check fails, the activity calls `System.exit(0)` and kills the entire process. The three checks are:

**Check 1 — SharedPreferences date match**  
The value stored at key `UUU0133` in `DAD4` preferences must equal today's date as returned by `cd()`. The `cd()` method formats `new Date()` as `dd/MM/yyyy`. The `KLOW()` method in `MainActivity` is the intended way to populate this value.

**Check 2 — Intent URI validation**  
The Intent action must be `android.intent.action.VIEW`, the URI scheme must be `mhl`, and the host must be `labs`.

**Check 3 — AES decryption match**  
The last path segment of the URI is Base64-decoded and compared against the result of decrypting the hardcoded ciphertext `bqGrDKdQ8zo26HflRsGvVA==` using AES/CBC/PKCS5Padding with:
- Key: `your_secret_key_1234567890123456`
- IV: `1234567890123456` (from `Activity2Kt.fixedIV`)

Decrypting this with CyberChef or any AES tool yields: `mhl_secret_1337`

So the correct URI path segment is: `base64("mhl_secret_1337")` = `bWhsX3NlY3JldF8xMzM3`

Final URI: `mhl://labs/bWhsX3NlY3JldF8xMzM3`

### The Decoy

When all checks pass, `System.loadLibrary("flag")` loads the native library `libflag.so` and `getflag()` is called. However, `getflag()` returns the string `"Success"` — not a flag. The real flag is stored as a static string inside `libflag.so` in its read-only data section (`.rodata`) and must be recovered by scanning the module's memory at runtime.

## Exploitation

### Strategy

The approach is to use Frida to:

1. Block `System.exit()`, `finish()`, and `finishAffinity()` so the activity cannot kill itself if validation fails
2. Bypass all three validation checks to guarantee `libflag.so` loads
3. Hook `getflag()` to trigger a memory scan the moment the library is confirmed loaded
4. Use `Memory.scanSync()` and `hexdump()` to locate and print the flag from the native library's mapped memory region

### Frida Script

```javascript
Java.perform(function () {

  // Block System.exit so Activity2 cannot kill the process on check failure
  var JavaSystem = Java.use("java.lang.System");
  JavaSystem.exit.implementation = function (code) {
    console.log("[!] System.exit(" + code + ") intercepted — ignored");
  };

  // Block finish() and finishAffinity() — Android 14 has two finish() overloads
  var Activity = Java.use("android.app.Activity");
  Activity.finish.overload().implementation = function () {
    console.log("[!] finish() intercepted — ignored");
  };
  Activity.finish.overload("int").implementation = function (r) {
    console.log("[!] finish(int) intercepted — ignored");
  };
  Activity.finishAffinity.implementation = function () {
    console.log("[!] finishAffinity() intercepted — ignored");
  };

  // Bypass SharedPreferences check
  var SharedPrefs = Java.use("android.app.SharedPreferencesImpl");
  SharedPrefs.getString.overload("java.lang.String", "java.lang.String")
    .implementation = function (key, def) {
      console.log("[*] SharedPreferences.getString(" + key + ") -> 'bypassed'");
      return "bypassed";
    };

  // Bypass Activity2 validation methods
  var Activity2 = Java.use("com.mobilehackinglab.challenge.Activity2");

  Activity2.cd.implementation = function () {
    console.log("[*] cd() -> 'bypassed'");
    return "bypassed";
  };

  Activity2.decrypt.implementation = function (alg, ct, key) {
    console.log("[*] decrypt() -> 'bypassed'");
    return "bypassed";
  };

  // Hook getflag() — libflag.so is guaranteed to be loaded when this fires
  Activity2.getflag.implementation = function () {
    console.log("[*] getflag() called — libflag.so must be loaded now");
    var result = this.getflag();
    console.log("[*] getflag() returned (decoy): " + result);
    setTimeout(readFlagFromMemory, 200);
    return result;
  };

  // Find MainActivity instance and launch Activity2
  setTimeout(function () {
    Java.choose("com.mobilehackinglab.challenge.MainActivity", {
      onMatch: function (mainActivity) {
        console.log("[*] Found MainActivity: " + mainActivity);
        mainActivity.KLOW();
        setTimeout(function () {
          launchActivity2(mainActivity);
        }, 300);
      },
      onComplete: function () {}
    });
  }, 500);

});

function launchActivity2(activity) {
  var Intent = Java.use("android.content.Intent");
  var Uri    = Java.use("android.net.Uri");
  var intent = Intent.$new();
  var pkg    = "com.mobilehackinglab.challenge";

  // "bypassed" base64-encoded = "YnlwYXNzZWQ="
  // Validation is bypassed via hooks above so any base64 value works here
  var url = "mhl://labs/YnlwYXNzZWQ=";

  intent.setClassName(pkg, pkg + ".Activity2");
  intent.setAction("android.intent.action.VIEW");
  intent.addCategory("android.intent.category.BROWSABLE");
  intent.setData(Uri.parse(url));

  console.log("[*] Launching Activity2 with: " + url);
  activity.startActivity(intent);
}

function readFlagFromMemory() {
  var mod = Process.findModuleByName("libflag.so");
  if (!mod) {
    console.log("[-] libflag.so not found yet, retrying in 500ms...");
    setTimeout(readFlagFromMemory, 500);
    return;
  }

  console.log("[*] libflag.so @ " + mod.base + "  size=" + mod.size);

  // Scan the module's mapped region for the ASCII bytes of "MHL{"
  var results = Memory.scanSync(mod.base, mod.size, "4d 48 4c 7b");
  console.log("[*] Matches found: " + results.length);

  if (results.length > 0) {
    console.log("\n[+] Flag found — read from the ASCII column below:");
    console.log(hexdump(results[0].address, { length: 32, header: true, ansi: false }));
  }
}
```

### Running the Script

```bash
frida -U -f com.mobilehackinglab.challenge -l strings-legit.js
```

### Output

```
Spawned `com.mobilehackinglab.challenge`. Resuming main thread!
[*] Found MainActivity: com.mobilehackinglab.challenge.MainActivity@9e7edf3
[*] Launching Activity2 with: mhl://labs/YnlwYXNzZWQ=
[*] SharedPreferences.getString(UUU0133) -> 'bypassed'
[*] cd() -> 'bypassed'
[*] decrypt() -> 'bypassed'
[*] getflag() called — libflag.so must be loaded now
[*] getflag() returned (decoy): Success
[*] libflag.so @ 0x7d6f45b53000  size=16384
[*] Matches found: 1

[+] Flag found — read from the ASCII column below:
               0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
7d6f45b56fc0  4d 48 4c 7b 49 4e 5f 54 48 45 5f 4d 45 4d 4f 52  MHL{IN_THE_MEMOR
7d6f45b56fd0  59 7d 00 00 00 00 00 00 00 00 00 00 00 00 00 00  Y}..............
```

## Flag

```
MHL{IN_THE_MEMORY}
```

## Key Takeaways

The flag was never returned by `getflag()`. It lives as a static string constant inside `libflag.so` at offset `0x7d6f45b56fc0` in the process address space, only accessible after the library is mapped via `System.loadLibrary("flag")`. Memory scanning with Frida's `Memory.scanSync()` locates it by searching for the hex pattern `4d 48 4c 7b` (`MHL{`) within the module's mapped region.

From a defensive perspective, storing sensitive strings in native library `.rodata` sections provides no real protection. Any process memory is readable by an attacker with root access or a debugger attached, and tools like Frida make scanning trivial. Proper approaches include deriving secrets at runtime without ever storing them as plaintext, or using hardware-backed keystore operations that never expose the raw value to userspace memory.
