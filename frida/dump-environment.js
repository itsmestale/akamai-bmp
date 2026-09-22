// Dump the WebView environment properties directly from Java, no evaluateJavascript needed
Java.perform(function() {
    // Get the WebView's user agent
    var WebSettings = Java.use("android.webkit.WebSettings");
    var WebView = Java.use("android.webkit.WebView");

    WebView.loadData.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(data, mimeType, encoding) {
        console.log("[*] WebView.loadData intercepted");
        console.log("[HTML] " + data.substring(0, 500));

        // Get WebView settings
        var settings = this.getSettings();
        console.log("\n=== WebView Environment ===");
        console.log("[ENV] UserAgent: " + settings.getUserAgentString());
        console.log("[ENV] JavaScriptEnabled: " + settings.getJavaScriptEnabled());
        console.log("[ENV] DomStorageEnabled: " + settings.getDomStorageEnabled());

        // Get display metrics
        var ctx = this.getContext();
        var dm = ctx.getResources().getDisplayMetrics();
        console.log("[ENV] Screen density: " + dm.density);
        console.log("[ENV] Screen densityDpi: " + dm.densityDpi);
        console.log("[ENV] Screen widthPixels: " + dm.widthPixels);
        console.log("[ENV] Screen heightPixels: " + dm.heightPixels);
        console.log("[ENV] Screen xdpi: " + dm.xdpi);
        console.log("[ENV] Screen ydpi: " + dm.ydpi);

        // Get WebView size
        console.log("[ENV] WebView width: " + this.getWidth());
        console.log("[ENV] WebView height: " + this.getHeight());

        // Build info
        var Build = Java.use("android.os.Build");
        console.log("[ENV] Build.MODEL: " + Build.MODEL.value);
        console.log("[ENV] Build.MANUFACTURER: " + Build.MANUFACTURER.value);
        console.log("[ENV] Build.FINGERPRINT: " + Build.FINGERPRINT.value);
        console.log("[ENV] Build.HARDWARE: " + Build.HARDWARE.value);

        // WebView version
        try {
            var PackageInfo = Java.use("android.webkit.WebViewFactory");
            console.log("[ENV] WebView package: " + PackageInfo.getLoadedPackageInfo().packageName);
            console.log("[ENV] WebView version: " + PackageInfo.getLoadedPackageInfo().versionName);
        } catch(e) {}

        // Compute SHA-256 of the UA to check if it matches ua_hash
        try {
            var ua = settings.getUserAgentString();
            var md = Java.use("java.security.MessageDigest").getInstance("SHA-256");
            var bytes = Java.use("java.lang.String").$new(ua).getBytes("UTF-8");
            var digest = md.digest(bytes);
            var hex = "";
            for (var i = 0; i < digest.length; i++) {
                var b = (digest[i] & 0xff).toString(16);
                if (b.length === 1) hex += "0";
                hex += b;
            }
            console.log("[ENV] SHA-256(UA): " + hex);
            console.log("[ENV] Expected ua_hash: 920a650b922995f6c26c190a3e10da6aee3557b9f7753de59d05b820311f5af5");
            console.log("[ENV] Match: " + (hex === "920a650b922995f6c26c190a3e10da6aee3557b9f7753de59d05b820311f5af5"));
        } catch(e) {
            console.log("[ENV] SHA-256 error: " + e);
        }

        this.loadData(data, mimeType, encoding);
    };

    var u7f = Java.use("u7f");
    u7f.setSignal.implementation = function(signal) {
        var pjs = signal.match(/pureJsSignal=([^#]+)/);
        if (pjs) console.log("[SIGNAL] " + pjs[1]);
        this.setSignal(signal);
    };

    console.log("[*] Ready");
});
