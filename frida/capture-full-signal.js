// Frida script to capture:
// 1. The full signal passed to setSignal (including pureJsSignal)
// 2. The WebView HTML content (to find wrapper JS)
// 3. Any evaluateJavascript calls

Java.perform(function() {
    console.log("[*] Frida hooks active");

    // 1. Hook u7f.setSignal to capture the full signal
    try {
        var u7f = Java.use("u7f");
        u7f.setSignal.implementation = function(signal) {
            console.log("\n=== setSignal CALLED ===");
            console.log("FULL_SIGNAL:" + signal);
            console.log("Signal length: " + signal.length);

            // Parse parts
            var parts = signal.split("#");
            for (var i = 0; i < parts.length; i++) {
                console.log("  PART[" + i + "]: " + parts[i].substring(0, 200));
            }

            // Extract pureJsSignal if present
            for (var i = 0; i < parts.length; i++) {
                if (parts[i].indexOf("pureJsSignal=") === 0) {
                    var pjs = parts[i].replace("pureJsSignal=", "");
                    console.log("\n=== pureJsSignal ===");
                    console.log(pjs);
                    var fields = pjs.split(",");
                    for (var j = 0; j < fields.length; j++) {
                        console.log("  FIELD[" + j + "]: " + fields[j]);
                    }
                }
            }

            // Call original
            this.setSignal(signal);
        };
        console.log("[+] u7f.setSignal hooked");
    } catch(e) {
        console.log("[-] u7f.setSignal hook failed: " + e);
    }

    // 2. Hook WebView.loadData to capture HTML content
    try {
        var WebView = Java.use("android.webkit.WebView");

        WebView.loadData.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(data, mimeType, encoding) {
            console.log("\n=== WebView.loadData ===");
            console.log("mimeType: " + mimeType);
            console.log("encoding: " + encoding);
            console.log("WEBVIEW_HTML_START:" + data.substring(0, 2000));
            if (data.length > 2000) {
                console.log("WEBVIEW_HTML_MID:" + data.substring(data.length/2, data.length/2 + 2000));
                console.log("WEBVIEW_HTML_END:" + data.substring(data.length - 2000));
            }
            console.log("Total HTML length: " + data.length);
            this.loadData(data, mimeType, encoding);
        };

        WebView.loadDataWithBaseURL.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(baseUrl, data, mimeType, encoding, historyUrl) {
            console.log("\n=== WebView.loadDataWithBaseURL ===");
            console.log("baseUrl: " + baseUrl);
            console.log("mimeType: " + mimeType);
            console.log("WEBVIEW_HTML_START:" + data.substring(0, 2000));
            if (data.length > 2000) {
                console.log("WEBVIEW_HTML_MID:" + data.substring(data.length/2, data.length/2 + 2000));
                console.log("WEBVIEW_HTML_END:" + data.substring(data.length - 2000));
            }
            console.log("Total HTML length: " + data.length);
            this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
        };

        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log("\n=== WebView.loadUrl ===");
            console.log("URL: " + url);
            this.loadUrl(url);
        };

        console.log("[+] WebView hooks installed");
    } catch(e) {
        console.log("[-] WebView hook failed: " + e);
    }

    // 3. Hook evaluateJavascript
    try {
        var WebView = Java.use("android.webkit.WebView");
        WebView.evaluateJavascript.implementation = function(script, callback) {
            console.log("\n=== evaluateJavascript ===");
            console.log("JS_EVAL:" + script.substring(0, 500));
            if (script.length > 500) console.log("JS_EVAL_LEN:" + script.length);
            this.evaluateJavascript(script, callback);
        };
        console.log("[+] evaluateJavascript hooked");
    } catch(e) {
        console.log("[-] evaluateJavascript hook failed: " + e);
    }

    // 4. Hook pke.a() to capture the challenge trigger
    try {
        var pke = Java.use("pke");
        pke.a.implementation = function() {
            console.log("\n=== pke.a() called (challenge trigger) ===");
            this.a();
        };
        console.log("[+] pke.a hooked");
    } catch(e) {
        console.log("[-] pke.a hook failed: " + e);
    }

    console.log("[*] All hooks installed. Waiting for challenge...");
});
