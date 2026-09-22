# Dead Ends, Breakthroughs, and Lessons Learned

Reverse engineering Akamai BMP was not a linear process. Every phase of analysis produced at least one wrong assumption that had to be corrected before progress could continue. This chapter catalogues the dead ends, the breakthroughs that followed them, and the meta-lessons that apply to any obfuscated system.

---

## The Seven Dead Ends

### 1. Naive Node.js Evaluation

The first instinct was to load the polymorphic `sdk_challenge.js` into Node.js and call its entry point directly. The code ran silently with no errors but produced no output --- no `setSignal` call after a 5-second timeout. Akamai's challenge JS performs a self-integrity check: it computes MurmurHash3 (seed 88692) over its own source text and derives a value `X` that gates every subsequent string decode. Node.js's `eval` context differs from a browser's, producing a different integrity value and therefore a wrong `X`. With the wrong `X`, every XOR-decoded string in the four pools (`rn`, `GX`, `PX`, `bX`) silently decoded to garbage, and the VM broke without throwing an error.

**Lesson:** Self-integrity checks that derive decryption keys from `toString()` output are environment-coupled by design. Any environment that serialises functions differently --- Node.js, Deno, Bun, or even a different browser engine --- will produce the wrong key. You must either run the code in the exact environment it expects or patch out the integrity gate (which, in this case, is impossible without breaking the gate itself).

### 2. Progressive `window` Mocking with Proxy

After the Node.js failure, the next attempt was to build a mock `window` object using JavaScript `Proxy` traps to intercept and log every property access. The idea was to discover which browser APIs the script touched, then stub them incrementally until it ran to completion. Five iterations followed: adding `navigator`, `document`, `screen`, `location`, `performance`, `crypto`, `atob`, `btoa`, making the proxy recursive, making it callable, handling `Symbol.toPrimitive` and `has` traps. Each fix exposed a new edge case. The code accessed properties through deeply nested chains like `N[...][...][...][...].postMessage(Dh)` where each `[...]` was a decoded property name resolved through the `O` object's 129 decoded members (e.g., `O.rF` decodes to `"JSBridge"`, `O.gN` to `"postMessage"`). When any intermediate step returned `undefined`, the chain silently broke. The Proxy saw intermediate accessor calls, not the final resolved names, making it a whack-a-mole exercise that never converged.

**Lesson:** Proxy-based environment mocking is fundamentally fragile when property names are unpredictable. If the target uses runtime-computed identifiers decoded through VM string pools (as Akamai's per-serve randomisation guarantees), you cannot build a complete mock without first decoding the string tables --- at which point the mock is unnecessary because you already understand the code.

### 3. Hash Pattern Search via grep

To locate the hash function used for `pkgHashCode` and `uaHashCode`, the analysis searched the 54KB source for characteristic constants: `*31` (Java `String.hashCode`), `*33` (DJB2), `<<5`, `5381`, and MurmurHash3 call sites. Nothing was found. The MurmurHash3 function `xg()` was called exactly once in the entire file, and only for the self-integrity check (seed 88692). No `*31` pattern existed anywhere. The hash function turned out to be Java `String.hashCode()` implemented in VM bytecode, where the multiply-by-31 was decomposed across multiple VM opcodes and never appeared as a greppable literal.

**Lesson:** Hash algorithm implementations can be decomposed across VM opcodes in ways that make individual constants invisible to pattern matching. When a VM is involved, you must trace the execution rather than searching the source.

### 4. The 54KB File Assumption

Early analysis assumed `sdk_challenge_latest.js` (54,158 bytes, extracted from the APK) was the complete challenge JS. All 54 order keys (`w1` through `w54`) were probed via the Node.js harness. Every single one produced the same format: `cf-sdk-1-00-0.js#field=value#field=value#...#sha256tail`. Zero contained `pureJsSignal`. Zero contained `mapping_flag`. Zero contained computed hash codes. The `pureJsSignal` computation was simply absent from this file. When the live script was fetched via Frida from `/_sec/sdk_challenge.js`, it came back as 58,173 bytes --- 4KB larger --- with 42 named functions versus 21 in the local copy. The extra 21 functions contained the entire pureJsSignal computation module. The local copy was an older, incomplete build missing the fingerprint pipeline entirely.

**Lesson:** Always verify your source material against the live system. Bundled copies, cached versions, and documentation samples can differ substantially from what the server actually delivers. The "missing 4KB" contained the entire fingerprint computation that was the target of the analysis.

### 5. The Native Code Hypothesis

After exhaustive probing of the 54KB JS proved `pureJsSignal` was absent, the hypothesis shifted: perhaps `libakamaibmp.so` (the 1.9MB native library) computed the pureJsSignal internally. Ghidra analysis definitively refuted this. The string `pureJsSignal` appeared nowhere in the binary --- neither in the encrypted nor decrypted image. Zero MurmurHash3 constants existed (the native library has SHA-256 K-tables at offset `0x2925c0` but no MurmurHash). It exports only 5 JNI methods (`initializeKeyN`, `encryptKeyN`, `decryptN`, `buildN`, and a test stub), all handling sensor *encryption*, not signal assembly. The native library receives the JS signal as an opaque string (pair key `-90` in the `buildN` input), encrypts it, and returns the result. It performs zero parsing or validation of the JS signal content.

**Lesson:** Native libraries in hybrid systems often handle encryption only. The signal computation and the signal protection are deliberately separated across trust boundaries. Do not assume that the most heavily obfuscated component (the native library) is also the most functionally complex.

### 6. MurmurHash3 Brute-Force for `pkgHashCode`

To identify the hash function producing the two 32-bit integers, a brute-force was attempted: testing the known canvas `toDataURL()` calibration value against MurmurHash3 with seeds 0 through 2,000,000. No seed produced a match. The function turned out to be Java's `String.hashCode()` --- `h = 31*h + c` --- implemented entirely in the VM's bytecode without the `*31` pattern appearing as a literal. Applying `java_string_hashcode("data:image/png;base64,FAKE_CONSTANT_CANVAS_FINGERPRINT")` to the CloakBrowser calibration value produced an exact match: `-1793983051`.

**Lesson:** Variable names in decompiled or deobfuscated code are analyst-assigned labels, not ground truth. When a brute-force fails, question the algorithm identification before questioning the implementation. Verify the algorithm by tracing the actual operations, not by trusting the label you gave it.

### 7. Frida Browser-API Tracing

To capture the JS signal assembly in real time, Frida was used to inject JavaScript into the WebView via `evaluateJavascript()`. Multiple approaches were tried: `WebChromeClient` hooks, `logcat` capture, and direct JS injection. The injected code hooked `SensorInterface.setSignal` and called `console.log()` to emit the signal value. The hook executed correctly --- confirmed by the signal being stored in `u7f.b` --- but `console.log` output from the WebView's JavaScript context never reached Frida's message handler. Android WebView's console output goes to `logcat`, not to Frida's `send()` channel. The trace appeared to produce no output, leading to a false conclusion that the hook had failed.

**Lesson:** `console.log` from injected JavaScript in a WebView does not reach Frida's console. Use `Java.use('android.util.Log').d()` for Java-layer logging, or use Frida's `send()` API from the Java side after bridging the value out of the WebView context.

---

## The Eight Breakthroughs

### 1. The `Intl` Requirement

The Node.js harness kept hanging silently until `Intl` was added to the global builtins. The VM's case `qP` (the `getWeekStr` date/timezone computation) calls `Intl.DateTimeFormat()`, and without it the VM throws an uncaught "is not a function" and aborts before any data collection begins. This was not documented anywhere and took multiple iterations to discover. Adding `Intl` broke the first deadlock and allowed the harness to progress to the dual-path bridge discovery.

**Enabled by:** The failure of naive Node.js eval (Dead End 1) forced iterative debugging of the silent failure mode.

### 2. Dual-Path Bridge Discovery

A sub-agent analysing the challenge JS's bridge wiring found two communication paths: an **Android path** using synchronous `JSBridge.method()` calls (triggered via `buildPostDataAndroid`), and an **iOS path** using asynchronous `window.webkit.messageHandlers.jsBridge.postMessage()` followed by a callback via `window.setRes("key=value")`. The iOS path self-started on page load, making it exercisable in Node.js. When the bridge mock was corrected to respond via `setRes` on `setImmediate`, the harness produced its first signal output: `cf-sdk-1-00-0.js#deviceHardwareType=sunfish#kernalOsRelease=4.14.180-perf#cpuInfo=arm64-v8a#6f3c`. This confirmed the VM's SHA-256 implementation was standard (the `6f3c` suffix matched Node's `crypto.createHash('sha256')` independently).

**Enabled by:** The Proxy mocking failure (Dead End 2) demonstrated that single-approach analysis could not proceed without understanding the bridge architecture.

### 3. Frida `WebView.loadData` Hook

After both Node.js and Proxy approaches failed to produce `pureJsSignal`, Frida was used to hook `WebView.loadData` on the real Pixel 4a. This revealed the actual HTML loaded into the hidden WebView: a trivial `<script id="static">` that dynamically creates a `<script>` tag with `src` pointing to `https://api.argos.co.uk/_sec/sdk_challenge.js?os=android&starttime=...&serverSideSignal=...`. The challenge JS was fetched live from Akamai's CDN at every app launch --- not bundled in the APK. The same Frida hook captured the full signal output including `pureJsSignal=8,en-US,851,393,920a650b...,0,956038405,-1088156997`.

**Enabled by:** The native code hypothesis failure (Dead End 5) established that the computation was in JavaScript; Frida revealed *which* JavaScript.

### 4. Fetching the Live Polymorphic JS (58KB vs 54KB)

Using CloakBrowser to fetch the live URL produced a 58,173-byte file --- 4,015 bytes larger than the local 54KB copy. The function names were completely different (`dlIXcSWZBK` vs `dsXEzOjmVs`), the integrity marker was different (seed 90986 vs 88692), and the file contained 42 named functions versus 21 in the local copy. The extra 21 functions contained the pureJsSignal computation code, including the canvas drawing pipeline, the CSS system colour probing, and the Java `String.hashCode()` implementation in VM bytecode.

**Enabled by:** The Frida `WebView.loadData` hook (Breakthrough 3) revealed the live URL; CloakBrowser's stealth browser could fetch it without triggering bot detection.

### 5. CloakBrowser Execution with Real Hash Values

Running the live 58KB JS in CloakBrowser (stealth Chromium, Chrome/146 engine) with a full JSBridge mock and device parameters embedded in the URL query string produced a complete pureJsSignal with real hash values: `8,en-US,1080,1920,e79ca373...,0,533473543,1556626983`. The values differed from the Pixel 4a capture (because CloakBrowser runs a different Chrome engine version on Windows) but the structure was correct. Running the same JS in Node.js produced `pureJsSignal=n,en-US,851,393,-1,null,-1,-1,-1` --- correct structure but placeholder values where hashes should be, because the VM's fingerprinting code tried to call browser APIs that do not exist in Node.js.

**Enabled by:** Fetching the live JS (Breakthrough 4) provided the complete challenge code; CloakBrowser provided the real browser context the VM required.

### 6. Differential Testing Matrix

A systematic differential testing approach was developed: a known-good CloakBrowser baseline was established, then each browser property was overridden individually while holding all others constant. Overriding `canvas.toDataURL()` to return a constant string caused both `pkgHashCode` and `uaHashCode` to collapse to the identical value `-1793983051`, proving they use the same hash function applied to two different canvas renderings. Overriding `getComputedStyle` changed `ua_hash` but not the canvas hashes. Overriding `navigator.userAgent` and `appIdentifier` changed nothing. Overriding `navigator.language` to `fr-FR` changed only the locale field. This mapped every hash to its exact input.

**Enabled by:** The successful CloakBrowser execution (Breakthrough 5) provided the controlled test environment needed for single-variable isolation.

### 7. Java `String.hashCode()` Calibration Match

The CloakBrowser canvas override test produced a known input-output pair: `toDataURL()` returning `"data:image/png;base64,FAKE_CONSTANT_CANVAS_FINGERPRINT"` mapped to hash code `-1793983051`. This calibration value was tested against every candidate 32-bit hash: CRC32, DJB2, FNV-1a, Adler32, MurmurHash3 (seeds 0 through 2,000,000) --- none matched. Java `String.hashCode()` (`h = 31*h + c`, signed 32-bit) produced an exact match. The algorithm was implemented in the obfuscated JS VM without using the `*31` pattern directly --- the multiplication was decomposed across multiple VM opcodes, which is why the earlier static grep (Dead End 3) found nothing.

**Enabled by:** The differential testing matrix (Breakthrough 6) provided the calibration value; the working VM disassembly (from the earlier dispatch analysis mapping case P5=131, J5=55, F5=345) allowed instruction-level tracing that confirmed the algorithm.

### 8. CSS System Colour Capture and ua_hash Match

Frida-injected hooks captured the 38 CSS system colour values (`ActiveBorder`, `ActiveCaption`, ..., `WindowText`) from the real Pixel 4a WebView. These were serialised as a JSON object with `JSON.stringify` using comma-colon separators and no whitespace, then SHA-256 hashed via the VM's case J5 and hex-encoded via case F5. The resulting hash --- `920a650b922995f6c26c190a3e10da6aee3557b9f7753de59d05b820311f5af5` --- was an exact match to the `ua_hash` from the Frida signal capture, confirming the input was CSS system colours (not the user agent string, despite the misleading name).

**Enabled by:** The differential testing matrix (Breakthrough 6) isolated the input as CSS system colours; Frida canvas/CSS hooks provided the raw data for independent verification.

---

## Dead Ends and Breakthroughs: Summary Table

| # | Dead End | Breakthrough That Followed |
|---|----------|---------------------------|
| 1 | Naive Node.js eval (integrity check, wrong X) | `Intl` requirement discovery |
| 2 | Progressive Proxy mocking (unpredictable decoded names) | Dual-path bridge discovery (iOS async vs Android sync) |
| 3 | Hash pattern search via grep (algorithm hidden in VM bytecode) | Java `String.hashCode()` calibration match |
| 4 | 54KB file assumption (local copy missing pureJsSignal module) | Live 58KB fetch revealing the missing 4KB |
| 5 | Native code hypothesis (libakamaibmp.so is encryption-only) | Frida `WebView.loadData` hook revealing live JS URL |
| 6 | MurmurHash3 brute-force (wrong algorithm entirely) | Java `String.hashCode()` identification via calibration |
| 7 | Frida browser-API tracing (`console.log` black hole) | Java-layer JNI hooking via Frida |

---

## The Insight Chain

Each dead end produced a piece of understanding that directly enabled the next breakthrough. The chain is not merely sequential --- it is causal.

1. **Node.js eval fails** silently because the integrity check produces the wrong `X`, proving the script requires a real browser environment.
2. Iterative debugging of the silent failure reveals the **`Intl` requirement**, breaking the first deadlock.
3. With `Intl` added, the harness progresses far enough to expose the **dual-path bridge architecture** (iOS async `postMessage`/`setRes` vs Android sync `JSBridge.method()`).
4. The dual-path bridge enables exhaustive probing of all 54 order keys, proving **pureJsSignal is not in the local 54KB file**.
5. Ghidra analysis proves it is **not in the native library** either --- zero fingerprint strings, zero MurmurHash constants, only encryption JNI exports.
6. APK decompilation shows `u7f.setSignal` is a **passthrough** (`this.b = str; done()`), meaning JS produces the complete signal.
7. **Frida hooks `WebView.loadData`**, revealing the WebView loads JS from a live URL, not from a bundled asset.
8. The live JS is **4KB larger** than the local copy, containing 21 additional functions with the pureJsSignal computation module.
9. **CloakBrowser executes** the live JS successfully, producing pureJsSignal with real hash values.
10. **Differential testing** in CloakBrowser isolates the three fingerprint inputs: CSS system colours for `ua_hash`, canvas `toDataURL()` for `pkgHashCode` and `uaHashCode`.
11. The canvas override calibration value is tested against every candidate hash --- **Java `String.hashCode()`** produces an exact match on `-1793983051`.
12. **CSS colour capture** via Frida on the real device produces an SHA-256 hash that exactly matches `ua_hash`, completing the algorithm identification.
13. The **Frida `console.log` failure** forces a move from WebView-level to Java-layer instrumentation, which captures known-good payloads for final validation.

---

## Meta-Lessons

### Assumptions About Obfuscation Are Dangerous

The most costly assumptions were not about algorithms but about architecture. Assuming the native library computed signals (it did not). Assuming the bundled JS was the complete challenge code (it was not --- 4KB was missing). Assuming a variable named "pkgHashCode" hashed the package name (it hashes a canvas `toDataURL()` output). Assuming MurmurHash3 was used for fingerprint hashes (it is used only for the self-integrity check, seed 88692). Obfuscation does not merely hide what code does --- it hides what code *is*. Treat every architectural assumption as a hypothesis that requires evidence before it can be used as a foundation for further work.

### The Value of Systematic Differential Testing

Single-variable override testing --- changing exactly one browser property per test while holding all others constant --- was the only method that reliably mapped each hash to its input. The canvas override collapsing both hash codes to `-1793983051` was the single most important moment in the analysis: it proved the hash function, proved the input source, and disproved three wrong hypotheses simultaneously. The principle generalises: when the computation is opaque (hidden in VM bytecode), systematic perturbation of inputs is more reliable than static analysis of the code.

### When to Pivot Versus When to Persist

Two of the seven dead ends were tool limitations (Frida `console.log` not reaching the console; grep unable to find hash constants decomposed across VM opcodes), not conceptual errors. The correct response was to change the tool while keeping the approach. The other five were genuine conceptual mistakes (wrong file, wrong algorithm, wrong architecture assumption, wrong component, wrong brute-force target). The correct response was to change the approach entirely. The distinguishing question is: "Does my evidence contradict my assumption, or does it merely show that my tool cannot observe the thing I expect to find?" If evidence contradicts the assumption, pivot. If the tool is blind, try a different tool.

### The "Missing 4KB" Principle

The 54KB-versus-58KB mistake is the most expensive category of error in reverse engineering: working against the wrong artefact. The local 54KB copy was an older build that lacked the entire pureJsSignal computation module --- 21 functions containing the canvas drawing pipeline, the CSS system colour probing, and the Java `String.hashCode()` implementation. It generalises to a principle: **always verify that your source material matches the live system**. Cached copies decay. Bundled resources diverge from server-delivered ones. Before committing to deep analysis of any artefact, confirm --- by hash, by size, by behavioural comparison --- that it is the same artefact the production system actually uses. The cost of verification is minutes. The cost of analysing the wrong file is hours.
