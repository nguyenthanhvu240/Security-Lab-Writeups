/**
 * MobileHackingLab - Strings Challenge
 * FINAL SCRIPT — blocks System.exit, bypasses validation, scans memory via getflag() hook
 *
 * Run with:
 *   frida -U -f com.mobilehackinglab.challenge -l strings-legit.js
 */

Java.perform(function () {

  // ── Block System.exit so Activity2 can't kill the process ─────────────────
  var JavaSystem = Java.use("java.lang.System");
  JavaSystem.exit.implementation = function (code) {
    console.log("[!] System.exit(" + code + ") intercepted — ignored");
  };

  // ── Block finish/finishAffinity so Activity2 can't close itself ───────────
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

  // ── Bypass SharedPreferences check ────────────────────────────────────────
  var SharedPrefs = Java.use("android.app.SharedPreferencesImpl");
  SharedPrefs.getString.overload("java.lang.String", "java.lang.String")
    .implementation = function (key, def) {
      console.log("[*] SharedPreferences.getString(" + key + ") -> 'bypassed'");
      return "bypassed";
    };

  // ── Bypass Activity2 validation methods ───────────────────────────────────
  var Activity2 = Java.use("com.mobilehackinglab.challenge.Activity2");

  Activity2.cd.implementation = function () {
    console.log("[*] cd() -> 'bypassed'");
    return "bypassed";
  };

  Activity2.decrypt.implementation = function (alg, ct, key) {
    console.log("[*] decrypt() -> 'bypassed'");
    return "bypassed";
  };

  // ── Hook getflag() — lib IS loaded when this runs, perfect scan trigger ───
  Activity2.getflag.implementation = function () {
    console.log("[*] getflag() called — libflag.so must be loaded now");
    var result = this.getflag();
    console.log("[*] getflag() returned (decoy): " + result);
    // Small delay to ensure module is fully mapped
    setTimeout(readFlagFromMemory, 200);
    return result;
  };

  // ── Wait for MainActivity then launch Activity2 ───────────────────────────
  setTimeout(function () {
    Java.choose("com.mobilehackinglab.challenge.MainActivity", {
      onMatch: function (mainActivity) {
        console.log("[*] Found MainActivity: " + mainActivity);
        mainActivity.KLOW();   // write real date too, just in case
        setTimeout(function () {
          launchActivity2(mainActivity);
        }, 300);
      },
      onComplete: function () {}
    });
  }, 500);

});

// ── Launch Activity2 with bypass URI ─────────────────────────────────────────
function launchActivity2(activity) {
  var Intent = Java.use("android.content.Intent");
  var Uri    = Java.use("android.net.Uri");
  var intent = Intent.$new();

  var pkg = "com.mobilehackinglab.challenge";
  // "bypassed" base64-encoded = "YnlwYXNzZWQ="
  var url = "mhl://labs/YnlwYXNzZWQ=";

  intent.setClassName(pkg, pkg + ".Activity2");
  intent.setAction("android.intent.action.VIEW");
  intent.addCategory("android.intent.category.BROWSABLE");
  intent.setData(Uri.parse(url));

  console.log("[*] Launching Activity2 with: " + url);
  activity.startActivity(intent);
}

// ── Scan libflag.so mapped region for MHL{ ────────────────────────────────────
function readFlagFromMemory() {
  var mod = Process.findModuleByName("libflag.so");
  if (!mod) {
    console.log("[-] libflag.so not found yet, retrying in 500ms...");
    setTimeout(readFlagFromMemory, 500);
    return;
  }

  console.log("[*] libflag.so @ " + mod.base + "  size=" + mod.size);

  // scanSync returns an array immediately — no callback scoping issues
  var results = Memory.scanSync(mod.base, mod.size, "4d 48 4c 7b"); // "MHL{"
  console.log("[*] Matches found: " + results.length);

  if (results.length > 0) {
    console.log("\n[+] Flag found — read from the ASCII column below:");
    // hexdump() is a Frida built-in global — always available, no imports needed
    console.log(hexdump(results[0].address, { length: 32, header: true, ansi: false }));
  }
}
