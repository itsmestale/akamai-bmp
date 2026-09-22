// Frida script: captures pureJsSignal values from the BMP challenge
// and caches them for reuse in your sensor generator.
//
// Usage: frida -U -f com.homeretailgroup.argos.android -l frida-capture-purejs-cache.js
//
// Values are device-stable: same device + same WebView version = same values.
// Re-capture after app or WebView Chrome updates.

Java.perform(function() {
    var u7f = Java.use("u7f");

    u7f.setSignal.implementation = function(signal) {
        var pjsMatch = signal.match(/pureJsSignal=([^#]+)/);
        if (pjsMatch) {
            var pjs = pjsMatch[1];
            var fields = pjs.split(",");

            console.log("\n============================================");
            console.log("  pureJsSignal captured — cache these values");
            console.log("============================================");
            console.log("  raw: " + pjs);
            console.log("");
            console.log("  version:      " + fields[0]);
            console.log("  locale:       " + fields[1]);
            console.log("  wvHeight:     " + fields[2]);
            console.log("  wvWidth:      " + fields[3]);
            console.log("  ua_hash:      " + fields[4]);
            console.log("  (empty):      " + fields[5]);
            console.log("  flag:         " + fields[6]);

            // The last two numeric fields are the hash codes
            // Format may vary by JS version — find the two signed-int-sized values
            var hashCodes = fields.filter(function(f) {
                var n = parseInt(f);
                return !isNaN(n) && (n > 1000000 || n < -1000000);
            });

            if (hashCodes.length >= 2) {
                console.log("  pkgHashCode:  " + hashCodes[hashCodes.length - 2]);
                console.log("  uaHashCode:   " + hashCodes[hashCodes.length - 1]);
            }

            console.log("\n  Python dict:");
            console.log('  PUREJS_CACHE = {');
            console.log('      "pureJsSignal": "' + pjs + '",');
            console.log('      "ua_hash": "' + fields[4] + '",');
            if (hashCodes.length >= 2) {
                console.log('      "pkgHashCode": ' + hashCodes[hashCodes.length - 2] + ',');
                console.log('      "uaHashCode": ' + hashCodes[hashCodes.length - 1] + ',');
            }
            console.log('  }');
            console.log("============================================\n");
        }

        // Also log the full signal for reference
        console.log("FULL_SIGNAL: " + signal);

        this.setSignal(signal);
    };

    console.log("[*] Waiting for BMP challenge signal...");
    console.log("[*] Trigger the challenge by opening/refreshing the app.");
});
