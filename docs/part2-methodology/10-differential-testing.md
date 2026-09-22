# Phases 7--9: CloakBrowser Differential Testing

The preceding phases established the existence of three computed fingerprint values inside `pureJsSignal` and proved that the challenge JavaScript responsible for computing them is served dynamically from `/_sec/sdk_challenge.js` --- it was never present in the 54KB static capture from the APK. We had the structure, we had the field names (`ua_hash`, `pkgHashCode`, `uaHashCode`), and we knew the computation required real browser APIs that Node.js could not provide. What we did not yet have was any understanding of what those three values actually hash, what inputs they depend on, or which algorithm produces them.

Phases 7 through 9 answered all three questions through systematic experimentation: executing the live challenge JS in a stealth browser, overriding one variable at a time to isolate which inputs drive each fingerprint value, and then brute-forcing the hash function identity against a known calibration output.

---

## Phase 7: CloakBrowser Execution

### The Problem

Node.js had already proved that the live challenge JS was structurally correct. Running it in a Node harness with a mocked `JSBridge` produced a valid `pureJsSignal` scaffold --- but every computed hash came back as `-1`, the VM's fallback when a browser API call fails:

```
pureJsSignal=n,en-US,851,393,-1,null,-1,-1,-1
```

The `-1` placeholders confirmed that the hash computations depend on APIs that only exist in a real browser: `HTMLCanvasElement.prototype.toDataURL()`, `window.getComputedStyle()`, and the Canvas 2D rendering context. Node.js has none of these. We needed a real browser --- one that would not be detected and blocked by Akamai's anti-bot checks before the challenge JS could finish executing.

### Building the Test Page

We created `bmp-live-test.html`, a standalone HTML page that replicates the exact structure Frida had captured from the real device's hidden WebView. The page contains:

1. **Device data object** --- all 20+ fields matching the Pixel 4a's real values (`model: "Pixel 4a"`, `buildId: "TQ3A.230805.001.S2"`, `androidId: "a1b2c3d4e5f6a7b8"`, etc.), drawn directly from the Frida `WebView.loadData` capture.
2. **JSBridge mock** --- `window.JSBridge` with `setSignal()` capturing output to `window._capturedSignal`, and all 18 getter methods returning the device data values.
3. **iOS bridge mock** --- `window.webkit.messageHandlers.jsBridge` with the correct `postMessage`/`setRes` callback chain, because the challenge JS probes for iOS bridge availability before falling back to Android.
4. **Dynamic script injection** --- a `<script>` tag that creates another script element with `src` pointing to the local copy of the live challenge JS, including the full query string with `serverSideSignal`, exactly as the real WebView does.

Getting the mock bridge right took several iterations. The first version omitted the `webkit` bridge entirely, causing the challenge JS to hang waiting for an iOS `postMessage` response. The second version handled `postMessage` but did not implement the asynchronous `setRes` callback pattern --- the JS sends a property name via `postMessage`, expects the Java/native side to call `window.setRes(name + "=" + value)` asynchronously, and blocks until it arrives. The third iteration got this right: short strings matching `/^[a-zA-Z]/` are treated as property queries and routed back through `setRes` after a 10ms `setTimeout`; longer strings are treated as the final signal.

### Results

With CloakBrowser launched (stealth Chromium, Chrome/146 engine, 58 source-level C++ patches for fingerprint evasion) and the test page loaded, the challenge JS executed to completion and produced a full `pureJsSignal` with real hash values:

```
8,en-US,851,393,e79ca373...,0,533473543,1556626983
```

These values differed from the Pixel 4a's Frida capture (`920a650b...`, `956038405`, `-1088156997`) because CloakBrowser runs a Windows Chrome/146 engine, not an Android Chrome/149 WebView. Different browser engine, different GPU, different CSS colour resolution, different canvas rendering --- therefore different fingerprint values. But the structure was correct and all three computed fields contained plausible non-placeholder data.

Node.js, by contrast, continued to produce `-1` placeholders. This confirmed the requirement for real browser APIs and gave us a working baseline environment for the next phase.

---

## Phase 8: Differential Testing Matrix

### Methodology

With a working CloakBrowser baseline, we applied the classical reverse engineering technique of **single-variable override**: change exactly one browser property or API, re-run the challenge JS, and diff the `pureJsSignal` output field by field. Any field that changes reveals a dependency on the overridden property. Any field that stays the same proves independence.

Each test followed the same procedure:

1. Inject the override (e.g., replace `navigator.userAgent` with an Android WebView string) into the page via `browser_evaluate` before the challenge script loads.
2. Navigate CloakBrowser to the test page, wait for `window._capturedSignal` to be populated.
3. Extract and parse the `pureJsSignal` substring.
4. Compare the four output fields (`locale`, `ua_hash`, `pkgHashCode`, `uaHashCode`) against the unmodified baseline.

### Full Test Matrix

| Override Applied | locale | ua_hash | pkgHashCode | uaHashCode |
|-----------------|--------|---------|-------------|------------|
| None (CloakBrowser baseline) | `en-US` | `e79ca373...` | `533473543` | `1556626983` |
| `navigator.userAgent` set to Android WebView string | `en-US` | same | same | same |
| `navigator.language` set to `fr-FR` | **`fr-FR`** | same | same | same |
| `appIdentifier` changed to `com.test.different.app` | `en-US` | same | same | same |
| `HTMLCanvasElement.prototype.toDataURL` returns constant | `en-US` | same | **`-1793983051`** | **`-1793983051`** |
| CSS `getComputedStyle` faked (+ WebGL params) | `en-US` | **`b27504...`** | same | same |
| WebGL `getParameter` overridden alone | `en-US` | same | same | same |

### Key Findings

**1. `appIdentifier` has zero effect on any computed value.**

The field name `pkgHashCode` strongly suggests it hashes the package name. It does not. Changing `appIdentifier` from `com.homeretailgroup.argos.android` to `com.test.different.app` produced no change in any of the three fingerprint values. The names are deliberately misleading --- a deception pattern consistent throughout Akamai's SDK where field names bear no relationship to their actual inputs.

**2. `navigator.userAgent` has zero effect on any computed value.**

The field name `uaHashCode` strongly suggests it hashes the user agent string. It does not. Replacing the UA with a completely different Android WebView string produced no change in any fingerprint field. The `ua_hash` field (the 64-character hex string) is also independent of the UA, despite its name.

**3. Canvas `toDataURL` override makes both hash codes collapse to a single identical value.**

This was the most informative test. When `HTMLCanvasElement.prototype.toDataURL` was overridden to return a constant string (`"data:image/png;base64,FAKE_CONSTANT_CANVAS_FINGERPRINT"`), both `pkgHashCode` and `uaHashCode` changed to the same value: `-1793983051`. Two conclusions follow immediately:

- Both values use the **same hash function** (otherwise they would not produce the same output from the same input).
- They differ only in their **canvas input** --- two different canvas drawing operations, each producing a different `toDataURL()` output, each fed through the same hash.

When the override forces both canvases to return the same constant string, the two hashes become identical.

**4. CSS `getComputedStyle` changes `ua_hash` only.**

Overriding `getComputedStyle` to return faked RGB values changed the `ua_hash` field from `e79ca373...` to `b27504...` while leaving both canvas hash codes untouched. This proved that `ua_hash` is derived from CSS system colour resolution --- specifically, the computed background-colour values for 38 named CSS system colours. The `ua_hash` name is a misnomer: it is a CSS colour fingerprint, not a user agent hash.

**5. WebGL `getParameter` alone has no effect.**

Overriding WebGL parameters without changing `getComputedStyle` produced no change in any field, including `ua_hash`. This ruled out WebGL as a direct input to any of the three fingerprints. The CSS colour override test that changed `ua_hash` had also included WebGL overrides, but isolating WebGL alone showed it was the CSS override that drove the change.

### What the Matrix Proved

The three computed values in `pureJsSignal` are pure browser engine fingerprints:

| Value | Actual Input | Not Dependent On |
|-------|-------------|------------------|
| `ua_hash` | CSS system colour resolution (38 colours) | User agent, app identifier, session data |
| `pkgHashCode` | Canvas 2D rendering (Canvas A `toDataURL()`) | Package name, user agent, session data |
| `uaHashCode` | Canvas 2D rendering (Canvas B `toDataURL()`) | User agent, package name, session data |

None of these values depend on anything that can be spoofed by overriding JavaScript properties alone. They depend on what the browser engine *renders* --- pixel-level output from the GPU and CSS colour resolution from the rendering engine. This is why Akamai chose these fingerprints: they are extremely difficult to fake without replacing the actual rendering pipeline.

---

## Phase 9: Hash Function Identification

### The Calibration Value

The canvas override test gave us a critical piece of data: a known input-output pair. When `toDataURL()` returns the constant string `"data:image/png;base64,FAKE_CONSTANT_CANVAS_FINGERPRINT"`, the hash function produces `-1793983051`. This is a signed 32-bit integer, which narrowed the candidate algorithms to those producing 32-bit output.

The input string is 54 characters long, entirely ASCII, and fully known. Any correct hash algorithm must produce exactly `-1793983051` (or equivalently, `2500984245` unsigned) when applied to this string.

### Algorithm Comparison

We tested every plausible 32-bit hash algorithm against the calibration input:

| Algorithm | Parameters | Result | Match? |
|-----------|-----------|--------|--------|
| CRC32 | Standard polynomial | `3977218610` | No |
| DJB2 | `h = 33*h + c`, seed 5381 | `4265945099` | No |
| FNV-1a | 32-bit, offset basis 2166136261 | `2044440989` | No |
| MurmurHash3 | Seed 0 | `1406115794` | No |
| MurmurHash3 | Seed 88692 (from integrity check) | `-1316227012` | No |
| MurmurHash3 | Seeds 0 through 2,000,000 (exhaustive) | No match found | No |
| Adler32 | Standard | `1951236223` | No |
| ASCII sum (`tG`) | `sum += c if c < 128` | `4441` | No |
| **Java `String.hashCode()`** | **`h = 31*h + c`, signed 32-bit** | **`-1793983051`** | **Yes** |

Only one algorithm matched: Java's `String.hashCode()`.

### The Algorithm

Java's `String.hashCode()` is defined as:

```
h = s[0]*31^(n-1) + s[1]*31^(n-2) + ... + s[n-1]
```

Or equivalently, the iterative form: for each character `c` in the string, `h = 31*h + c`, with arithmetic performed in signed 32-bit integers (overflow wraps).

```python
def java_string_hashcode(s: str) -> int:
    """Java String.hashCode(): h = 31*h + c, signed 32-bit."""
    h = 0
    for c in s:
        h = ((h * 31) + ord(c)) & 0xFFFFFFFF
    return h - 0x100000000 if h >= 0x80000000 else h
```

### Calibration Proof

```python
>>> java_string_hashcode("data:image/png;base64,FAKE_CONSTANT_CANVAS_FINGERPRINT")
-1793983051  # Exact match to CloakBrowser override test
```

### Verification Against Device Captures

With the algorithm identified, we verified it against the real Pixel 4a values by hooking `toDataURL()` via Frida to capture the actual base64 canvas output:

| Canvas | fillText String | toDataURL Length | `java_string_hashcode(toDataURL)` | Frida Capture | Match? |
|--------|----------------|------------------|-----------------------------------|---------------|--------|
| A | `<@nv45. F1n63r,Pr1n71n6!` | 7926 chars | `956038405` | `956038405` | Yes |
| B | `m,Ev!xV67BaU> eh2m<f3AG3@` | 8850 chars | `-1088156997` | `-1088156997` | Yes |

Both values matched exactly. The hash function identification was confirmed.

### Why `*31` Was Invisible in Static Analysis

Earlier static analysis had specifically scanned the challenge JS source for the `*31` pattern and found nothing. This was not an error in the search --- the pattern genuinely does not appear in the source. The challenge JS implements the multiplication inside the VM bytecode, where `31*h` is decomposed into a sequence of lower-level operations:

```
31 * h  =  (h << 5) - h  =  (h << 4) + (h << 3) + (h << 2) + (h << 1) + h - h
```

The VM's instruction set uses shifts, additions, and subtractions rather than a single multiply instruction. When these operations are spread across multiple bytecode case handlers --- each with obfuscated variable names that change per polymorphic serve --- the familiar `h = 31*h + c` pattern is entirely invisible to grep, to manual code review, and even to Ghidra's decompiler (which was analysing the wrong layer anyway, since the hash runs in JS, not native code).

This is a textbook example of why differential testing is indispensable for VM-protected code. Static analysis can tell you *that* a hash function exists; it cannot always tell you *which* hash function it is. A known input-output pair and a lookup table of candidate algorithms will identify it in seconds where static analysis might never converge.

### The `tG` Red Herring

The APK decompilation had revealed a Java function `tG()` that computes an ASCII code-point sum:

```javascript
function tG(str) {
    if (str == null) return -1;
    var sum = 0;
    for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        if (c < 128) sum += c;
    }
    return sum;
}
```

Early analysis hypothesised that `tG` was the hash function behind `pkgHashCode` and `uaHashCode`, with additional encryption layers (`sl()` and `mY()` functions) transforming the raw sum into the final signed 32-bit value. The calibration test disproved this entirely: `tG("data:image/png;base64,FAKE_CONSTANT_CANVAS_FINGERPRINT")` returns `4441`, not `-1793983051`. The `tG` function exists in the codebase but plays no role in the pureJsSignal canvas fingerprint computation.

Similarly, MurmurHash3 --- which *is* present in the challenge JS and *is* used for the self-integrity check --- was exhaustively ruled out. We tested seeds from 0 to 2,000,000 against the calibration input and found no match. MurmurHash3's sole purpose in the challenge JS is gating string table decoding via the integrity seed; it has no involvement in fingerprint hashing.

---

## Summary of Phases 7--9

| Phase | Objective | Method | Key Output |
|-------|-----------|--------|------------|
| 7 | Execute challenge JS with real browser APIs | CloakBrowser + mock JSBridge (`bmp-live-test.html`) | Baseline `pureJsSignal` with real hash values |
| 8 | Isolate which inputs drive each fingerprint | Single-variable override, 7-row test matrix | `ua_hash` = CSS colours; hash codes = canvas rendering; names are lies |
| 9 | Identify the exact hash algorithm | Calibration value `-1793983051` tested against 9 algorithms | Java `String.hashCode()` (`h = 31*h + c`, signed 32-bit) |

The differential testing methodology --- CloakBrowser execution, single-variable isolation, calibration-value brute force --- resolved in a single session what static analysis alone could never have determined. The VM's bytecode-level decomposition of `*31` into bitwise operations made the hash function invisible to every static technique we applied. The moment we had a known input-output pair, identification was trivial.

With the algorithms confirmed, the three pureJsSignal values became fully reproducible: `ua_hash` via SHA-256 of serialised CSS system colours, and `pkgHashCode`/`uaHashCode` via `java_string_hashcode()` of the respective canvas `toDataURL()` outputs. The remaining question --- what exactly the two canvases draw --- was answered by Frida canvas operation capture, documented in the [pureJsSignal specification](../part1-understanding/05-purejs-signal.md).
