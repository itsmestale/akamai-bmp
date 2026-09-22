# Phases 4-6: The Frida Breakthrough

By the end of Phase 3, we had exhaustively proven two negatives. The local 54KB challenge JS file (`sdk_challenge_latest.js`) did not contain the `pureJsSignal` computation -- all 54 order keys produced the same `cf-sdk-1-00-0.js#field=value#...#sha256tail` format, and none emitted `pureJsSignal`, `mapping_flag`, or any 32-bit hash codes. The native library (`libakamaibmp.so`) did not contain it either -- Ghidra analysis found zero instances of the strings `pureJsSignal`, `pkgHashCode`, `uaHashCode`, or `mapping_flag` in the binary, zero MurmurHash3 constants, and only encryption-related JNI exports. The pureJsSignal had to exist somewhere, and we were running out of places to look.

The answer came from peeling back the layers between the APK's Java bytecode and what actually runs on the device at runtime. Phases 4 through 6 represent the pivot from static analysis to dynamic instrumentation -- the point where the entire investigation changed direction.

---

## Phase 4: APK Decompilation

### 20,991 Java Files

We decompiled the Argos APK (`com.homeretailgroup.argos.android` v5.26.0) using androguard, producing 20,991 Java source files from the DEX bytecode. The goal was to trace how the signal string flows from the challenge JavaScript, through the Java bridge layer, and into the native encryption pipeline.

Two classes were immediately relevant: `u7f` (the `@JavascriptInterface` bridge) and `pke` (the WebView controller).

### u7f.setSignal: A Trivial Passthrough

The `u7f` class exposes 18 device property getters to JavaScript via `@JavascriptInterface` annotations (`deviceHardwareType`, `kernalOsRelease`, `cpuInfo`, `appIdentifier`, and so on) plus the critical `setSignal` method. Here is the decompiled implementation in its entirety:

```java
public void setSignal(String str) {
    this.b = str;
    done();
}
```

It stores the signal string verbatim and calls `done()`. No modification, no assembly, no hashing, no transformation of any kind. Whatever JavaScript passes to `setSignal` is exactly what the native layer receives. This meant the JS must produce the *complete* signal string, including `pureJsSignal` and all its computed hash values.

This was a significant finding. We had considered the possibility that the Java layer or the native library assembled the pureJsSignal from separate components -- perhaps the JS computed individual hash values and the native code stitched them together. The passthrough implementation ruled that out entirely.

### The WebView Loader in pke.java

Class `pke` is the WebView controller. It creates a hidden WebView, injects the `u7f` JavaScript interface as `window.SensorInterface`, and loads an HTML page. The critical detail is *how* it loads the challenge JS.

The assumption until this point had been that the SDK loads `sdk_challenge_latest.js` from the APK's assets directory -- the 54KB file we had been analysing. The decompiled `pke` source told a different story. Rather than loading a static HTML page or a bundled JS file, `pke` uses `WebView.loadData()` to construct an HTML document at runtime. The document contains a single `<script id="static">` element whose sole purpose is to dynamically create another `<script>` tag pointing to a live URL on Akamai's CDN:

```html
<script id="static">
var s_e = document.createElement("script");
s_e.src = "https://api.argos.co.uk/_sec/sdk_challenge.js?os=android&starttime=...&serverSideSignal=...";
document.head.appendChild(s_e);
</script>
```

The HTML page is not a static asset. It is a stub -- a launcher that fetches the real challenge JS from `/_sec/sdk_challenge.js` with device parameters (`os`, `starttime`, `serverSideSignal`, and others) embedded in the URL query string. The challenge JS is fetched live from Akamai's server at every app launch.

This immediately explained why our local 54KB file did not contain the pureJsSignal computation. The file in the APK's assets was either a fallback, a cached older build, or a stripped development artefact. The real challenge JS is served dynamically by Akamai's edge infrastructure on every request.

---

## Phase 5: The Frida Capture

### Hooking WebView.loadData

Knowing that the challenge JS was fetched at runtime, we needed to see exactly what the WebView received. We wrote a Frida script that hooks three methods on the real Pixel 4a device:

- `WebView.loadData` and `WebView.loadDataWithBaseURL` -- to capture the HTML content loaded into the hidden WebView
- `u7f.setSignal` -- to capture the completed signal string that the challenge JS passes back

The script was injected into the running Argos process on the connected Pixel 4a via USB:

```bash
frida -U -f com.homeretailgroup.argos.android -l capture-full-signal.js
```

### The Captured HTML

The `WebView.loadData` hook fired and revealed the complete HTML document:

```html
<script id="static">
var s_e = document.createElement("script");
s_e.src = "https://api.argos.co.uk/_sec/sdk_challenge.js?os=android&starttime=1781690569633&serverSideSignal=AAQAAAAF...";
document.head.appendChild(s_e);
</script>
```

This confirmed the `pke.java` analysis. The HTML is minimal -- no visible content, no embedded logic, just a script tag loader. The `serverSideSignal` parameter is a URL-encoded binary blob (starting with `AAQAAAAF`) that the server uses to bind the challenge response to a specific session. The `starttime` parameter is the Unix timestamp in milliseconds when the SDK initialised.

### The Captured Signal

Seconds later, the `u7f.setSignal` hook fired with the complete signal string. Buried in the `#`-delimited fields was the full pureJsSignal:

```
pureJsSignal=8,en-US,851,393,920a650b922995f6c26c190a3e10da6aee3557b9f7753de59d05b820311f5af5,,0,956038405,-1088156997
```

Every field was populated with real values:

| Index | Field | Value |
|-------|-------|-------|
| 0 | Version tag | `8` |
| 1 | Locale | `en-US` |
| 2 | WebView height | `851` |
| 3 | WebView width | `393` |
| 4 | ua_hash | `920a650b922995f6c26c190a3e10da6aee3557b9f7753de59d05b820311f5af5` |
| 5 | (empty) | |
| 6 | Padding | `0` |
| 7 | pkgHashCode | `956038405` |
| 8 | uaHashCode | `-1088156997` |

This was the breakthrough. We now had ground-truth values for all three computed fingerprints, captured from a genuine device running the genuine SDK against the genuine Akamai infrastructure. These values became the calibration targets for every subsequent analysis phase -- the standard against which we would validate our algorithm identification and standalone computation.

The Frida capture also confirmed something we had suspected but not proven: the `ua_hash` is a 64-character hex string (consistent with SHA-256 output), whilst `pkgHashCode` and `uaHashCode` are signed 32-bit integers (one positive, one negative). This constrained the hash function search space significantly when we reached Phase 9.

---

## Phase 6: The Live Polymorphic JS

### Server-Delivered Code Is Different

With the live URL in hand from the Frida capture, we used CloakBrowser (our stealth Chromium with 58 source-level anti-detection patches) to fetch the current challenge JS from `/_sec/sdk_challenge.js`. The result was immediately and visibly different from the local copy.

**Size comparison:**

| Source | Size | Named Functions |
|--------|------|-----------------|
| Local (`sdk_challenge_latest.js`) | 54,158 bytes | 21 |
| Live (server-served) | 58,173 bytes | 42 |
| **Difference** | **+4,015 bytes** | **+21 functions** |

The live build was 4,015 bytes larger. More importantly, it contained 42 named functions compared to 21 in the local copy. The extra 21 functions were not padding or dead code -- they contained the entire pureJsSignal computation pipeline: the CSS system colour probing, the canvas rendering and `toDataURL()` capture, the hash computation, and the signal assembly logic.

### Polymorphic Builds

Beyond the size difference, the two files were textually unrecognisable as variants of the same programme:

| Property | Local Build | Live Build |
|----------|-------------|------------|
| IIFE function name | `dsXEzOjmVs` | `dlIXcSWZBK` |
| MurmurHash3 integrity seed | 88,692 | 90,986 |
| Integrity marker | `38d466e` | `8a6c3c3` |
| All variable/function names | One random set | A completely different random set |
| XOR string pool key material | Set A | Set B |

Every identifier in the file -- every function name, every variable, every parameter, every case label variable -- was replaced with a fresh random string. The string pool XOR keys were different, producing different encoded byte arrays in the `rn`, `GX`, `PX`, and `bX` pools. The integrity marker and seed were different, meaning the self-integrity value `X` (computed as `embedded_constant - MurmurHash3(function_toString, seed)`) would differ between builds.

Yet beneath the surface randomisation, the algorithms were identical. The same VM dispatch structure, the same SHA-256 implementation, the same canvas drawing pipeline (same colours, same arc parameters, same rectangle dimensions), the same 38 CSS system colour names, and the same `setSignal` call at the end. Akamai's build server generates a new polymorphic variant on every request -- different names, different keys, different integrity seeds, but functionally identical code.

### What the Extra 21 Functions Do

The 21 additional functions in the live build formed a self-contained pureJsSignal module. Through subsequent analysis (covered in detail in the Differential Testing chapter), we determined that these functions implement:

1. **CSS system colour probing** -- creating a hidden `<div>`, iterating through 38 CSS system colour names (`ActiveBorder`, `ActiveCaption`, `ButtonFace`, `Highlight`, etc.), reading each via `getComputedStyle`, and serialising the resulting colour map as JSON
2. **SHA-256 hashing** -- computing the hex digest of the serialised colour map to produce `ua_hash`
3. **Canvas rendering** -- creating two 280x60 canvases, drawing a green rectangle, an orange text string (different per canvas), and a teal semicircular arc on each, then calling `toDataURL()` to serialise the pixel data
4. **Java `String.hashCode`** -- computing `h = 31*h + c` (signed 32-bit) over each `toDataURL()` output string to produce `pkgHashCode` and `uaHashCode`
5. **Signal assembly** -- combining all values into the comma-delimited `8,locale,height,width,ua_hash,,0,pkgHashCode,uaHashCode` format and delivering it via the bridge

The local 54KB file was an older or stripped build that lacked this entire module. It could produce the basic `cf-sdk-1-00-0.js#field=value` device telemetry signals (the 54 order keys we had exhaustively probed), but it could not compute the three browser fingerprint values that constitute pureJsSignal. The pureJsSignal module appears to have been added to the challenge JS in a later SDK iteration, and our locally cached copy predated that addition.

### Why This Architecture Matters

The polymorphic build system has significant implications for reverse engineering:

**Anti-tamper through entropy.** Because every serve produces different variable names and different XOR key material, you cannot patch the challenge JS once and reuse it. The self-integrity check (`X = embedded_constant - MurmurHash3(source_text, seed)`) means any byte-level modification to the source produces a wrong `X` value, which cascades through every string table lookup and produces garbage output. You must either run the unmodified source in a genuine browser environment, or bypass the JS entirely by computing the outputs independently -- which is what we ultimately did.

**Analysis requires live fetches.** Static analysis of a cached copy is insufficient. The local file was missing 4KB of critical logic. Any analysis workflow must include fetching the current build from the live endpoint and comparing it against prior captures to detect structural changes.

**Differential analysis is tractable.** Despite the per-serve randomisation, the underlying algorithms are stable. Two builds served seconds apart will have completely different identifiers but identical control flow, identical case numbers in the VM dispatch, and identical cryptographic constants. This stability makes differential analysis between builds a reliable technique for separating the randomised surface (names, keys) from the invariant core (algorithms, data flow).

---

## What Phases 4-6 Established

These three phases transformed the investigation. Before Phase 4, we had two exhaustively analysed artefacts (the local JS and the native binary) and a missing computation. After Phase 6, we had:

1. **Confirmation** that `setSignal` is a verbatim passthrough -- the JS produces the complete signal
2. **Discovery** that the challenge JS is fetched live from Akamai's CDN, not bundled in the APK
3. **Ground-truth calibration values** for all three pureJsSignal fingerprints, captured from a genuine Pixel 4a
4. **The live polymorphic JS** containing the 21 additional functions that implement the fingerprint computation
5. **Understanding** of Akamai's polymorphic build system -- per-serve randomisation of all identifiers with stable underlying algorithms

The Frida capture on the physical device was the single most important moment in the entire reverse engineering effort. Every subsequent phase -- differential testing in CloakBrowser, hash algorithm identification, canvas operation capture, CSS colour table extraction -- built directly on the foundation established here. Without the ground-truth values from Phase 5, we would have had no calibration targets. Without the live JS from Phase 6, we would have had no code to analyse. The lesson is straightforward: when static analysis exhausts its options, dynamic instrumentation on real hardware is not a fallback -- it is the next required step.
