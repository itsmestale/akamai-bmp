# Phases 1-3: Static Analysis and the Wrong Turns

Every reverse engineering project has a narrative it tells in retrospect -- clean, logical, each step following from the last. The reality is nothing like that. This chapter documents the first three phases as they actually happened: the parallel attacks, the dead ends, and the critical pivot that only became obvious after the fact.

---

## Phase 1: Static Analysis of the 54KB Challenge JS

The challenge script (`/_sec/sdk_challenge.js`) is roughly 54KB of obfuscated JavaScript that runs inside a hidden Android WebView. It never makes network requests. Its entire purpose is to collect device fingerprint data through a JSBridge interface, compute a signal string, and pass it back to the native SDK via `JSBridge.setSignal()`.

We attacked it with three sub-agents running in parallel, each targeting a different structural layer.

### The String Table Agent

The first agent focused on the string obfuscation system. All meaningful strings in the script -- method names, property keys, format identifiers -- are stored in encoded arrays and decoded at runtime through XOR-based cipher chains.

Four XOR pools were identified:

| Pool | Decode Case | Entry Count | Purpose |
|------|-------------|-------------|---------|
| `rn` | `dV` | 48 | Primary method/property names |
| `GX` | `K7` | 41 | Secondary identifiers |
| `PX` | `g7` | 53 | Bridge method names |
| `bX` | `hY` | 49 | Format strings, delimiters |

Each pool uses a different XOR key derived from intermediate VM state. The decode functions XOR each character code with the pool's key and cache the result in a memoisation object (`O`) for subsequent lookups.

Beyond the XOR pools, the script constructs single digits using JSFuck-style arithmetic:

```javascript
// Digit construction (simplified from the obfuscated form)
+!+[]        // 1
!+[]+!+[]    // 2
+!![] + +!![] + +!![]  // 3
// ... and so on through 9
```

These constructed digits are composed into multi-digit numbers for array indices and case label values. The agent mapped 191 encoded entries across the four pools, producing 129 resolved identifiers including all JSBridge method names, webpack module export names, and SHA-256 round constants.

### The VM Dispatch Agent

The second agent attacked the interpreter structure. The challenge JS uses a switch-based interpreter -- a flattened control-flow graph where each case label represents a virtual instruction:

```javascript
while (true) {
    switch (state) {
        case G5: /* ... */ state = nextCase; break;
        case JR: /* ... */ state = nextCase; break;
        // 130+ additional cases
    }
}
```

Over 130 case handlers were identified. The agent mapped key cases to their functions:

| Case | Function |
|------|----------|
| `G5` | VM entry point, boots orchestrator |
| `JR` | Sets base integer constants |
| `Q5` | Module factory -- defines 7 webpack exports, assigns `window.setRes` |
| `qP` | `getWeekStr` -- timezone/week string via `Intl.DateTimeFormat` |
| `wR` | Bridge selection -- checks for `window.webkit.messageHandlers` |
| `AP` | `buildPostDataAndroid` -- starts Android data collection loop |
| `I5` | Signal submission (primary path) |
| `P5` | Signal string construction |
| `J5` | Pure-JS SHA-256 implementation |
| `m5` | Signal submission (secondary/alternate path) |

Two layers emerged: an outer VM (`En`/`Wk`) handling initialisation and string decoding, and an inner VM (`Hn`/`pn`) handling JSBridge calls and signal computation, connected by a webpack-style module loader (`F0`/`Ch`).

### The Integrity System Discovery

The third sub-agent found the most consequential feature. The `Q()` function computes a MurmurHash3 checksum (`xg`) over the IIFE's `toString()` output -- the script's own source text. This hash is XOR'd with a magic value (`0x38d466e`) to produce a correction factor `X`, determined to be **805** through dynamic extraction.

`X` feeds into every string decode index throughout the VM. Modify the source in any way -- even a single space -- and the MurmurHash3 output changes, `X` changes, and every decoded string becomes garbage. The VM fails silently: no error, no exception, just wrong property names resolving to `undefined`.

This anti-tamper interlock makes the standard "add `console.log` and re-run" approach impossible. We confirmed this by testing: editing even a comment character caused the entire string table to decode incorrectly.

### The Dead End: Searching for Hash Patterns

We spent considerable time identifying the specific hash algorithm. MurmurHash3 was eventually confirmed, but not before searching for other candidates -- the telltale multiplication constants of common non-cryptographic hash functions:

- **`*31`** -- Java `String.hashCode()` / Bernstein variant
- **`*33`** -- DJB2 (Daniel J. Bernstein's hash)
- **`*5381`** -- DJB2 initial value
- **`*16777619`** -- FNV-1a
- **`*2654435761`** -- Knuth's multiplicative hash

None were found. The hash in `Q()` uses MurmurHash3 finaliser constants (`0xcc9e2d51`, `0x1b873593`), which only became apparent after mapping the bitwise operations through the obfuscation layers. The DJB2 search was a complete dead end -- though the web-facing Akamai sensor script (the 500KB one) *does* use DJB2 for a different purpose. The mobile SDK challenge JS does not.

---

## Phase 2: The Node.js Harness

With the static analysis producing a solid architectural map, the next phase was to run the challenge JS outside a WebView. The script cannot be modified (integrity hash), so the approach was a Node.js harness providing the environment the script expects and capturing the signal output. This took four attempts.

### Attempt 1: Naive Eval

Load the script into a Node.js `vm.Script`, provide `window` as the global, and see what happens.

```javascript
const vm = require('vm');
const source = fs.readFileSync('sdk_challenge_latest.js', 'utf8');
const context = vm.createContext({ window: {} });
const script = new vm.Script(source);
script.runInContext(context, { timeout: 5000 });
```

Result: `"Timeout - no setSignal called after 5s"`. The integrity hash computed correctly, but the script hit missing globals and silently aborted. No error, no exception -- the VM's defensive coding swallows everything.

### Attempt 2: Adding Browser Globals

Added the obvious browser objects: `navigator`, `document`, `location`, `screen`, `JSBridge` as simple stubs. The script progressed further -- three device property reads (`deviceHardwareType`, `kernalOsRelease`, `cpuInfo`) -- then silence. No `setSignal`, no error.

### Attempt 3: Proxy Escalation

Replaced simple stubs with recursive Proxy objects to catch every property access and method call:

```javascript
const JSBridge = new Proxy({}, {
    get(target, prop) {
        console.log(`JSBridge.${String(prop)} accessed`);
        if (typeof prop === 'symbol') return undefined;
        if (!target[prop]) {
            // Return a callable proxy for any method
            target[prop] = new Proxy(function() {}, {
                apply(t, thisArg, args) {
                    console.log(`JSBridge.${String(prop)}(${args})`);
                    return '';
                }
            });
        }
        return target[prop];
    },
    has() { return true; }
});
```

This approach -- where every property access returns another callable proxy and every function call is logged -- revealed the script calling `Symbol.toPrimitive` on objects and expecting specific coercion behaviour. More importantly, it was dying at the `getWeekStr` function (case `qP`).

### The Critical Discovery: Intl Is Required

Case `qP` constructs a timezone-aware week string using `Intl.DateTimeFormat()`. Unlike `document` or `navigator`, this requires a real ICU implementation. Node.js has one, but it was not being exposed to the sandboxed context. Adding `Intl` to the sandbox globals was the turning point:

```javascript
const base = {
    String, Array, Number, Math, JSON,
    parseInt, parseFloat, isNaN, isFinite,
    Date, RegExp, Object, Function, Boolean, Symbol,
    Error, TypeError, RangeError, Promise,
    encodeURIComponent, decodeURIComponent,
    Intl,  // <-- THIS was the missing piece
    // ...
};
```

With `Intl` available, the VM progressed past initialisation and into the data collection phase.

### Attempt 4: The Dual-Path Bridge

The final iteration addressed bridge selection at case `wR`. The script checks for `window.webkit.messageHandlers` -- if present, the iOS path is taken; otherwise, the Android path via `window.JSBridge`. The two paths differ fundamentally:

| Aspect | iOS Path | Android Path |
|--------|----------|--------------|
| Trigger | Self-starts on load | Waits for native SDK to call export |
| Communication | `webkit.messageHandlers.*.postMessage()` | `JSBridge.postMessage()` via `document.defaultView` |
| Data flow | Async: script posts method name, native calls `window.setRes("name=value")` | Same async pattern, but initiated by native |
| Entry point | Automatic after `H6()` runs | `buildPostDataAndroid` (webpack export, not global) |

The Android path presented a problem: `buildPostDataAndroid` is a webpack module export, not attached to any global. On a real device, the native SDK calls the export directly. From outside the IIFE, it is unreachable. The solution was to present the webkit message-handler so the script takes the self-starting iOS path, then service the collection loop by echoing method names back through `window.setRes()` with Android device values:

```javascript
// iOS bridge — causes the script to self-start
base.webkit = {
    messageHandlers: new Proxy({}, {
        get() {
            return {
                postMessage: (m) => handlePost(m, 'webkit')
            };
        },
    }),
};

// Echo loop — services each method request
function echoToSetRes(methodName) {
    const value = valueForMethod(methodName);
    setImmediate(() => {
        setResFn(methodName + '=' + value);
    });
}
```

This worked. The iOS path self-started, the VM posted method names one by one (`startTime`, `sdkVersion`, `androidId`, `buildId`, `systemVersion`, `model`, `host`, and the full device fingerprint set), the harness echoed values back, and the script computed and submitted a signal:

```
cf-sdk-1-00-0.js#field=value#field=value#...#sha256tail
```

Each `field=value` pair is a JSBridge method response, and the trailing hex string is the last N characters of SHA-256 over the concatenated field strings. We cross-checked with Node's `crypto.createHash('sha256')` -- the VM's pure-JS SHA-256 matched exactly.

### Probing All 54 Order Keys: Zero Contain pureJsSignal

We systematically probed all 54 order keys (`w1` through `w54`). Each key selects a different subset and ordering of JSBridge methods.

The result was definitive: **none of the 54 order keys produce a field containing `pureJsSignal`**. Every signal contained only standard JSBridge getter responses -- `startTime`, `androidId`, `buildId`, `model` -- hashed together. The `pureJsSignal` value (CSS colour hash, canvas fingerprint hash codes) was absent from all of them.

The pureJsSignal was being computed elsewhere.

---

## Phase 3: The Native Code Hypothesis

The absence of `pureJsSignal` from the challenge JS led to a natural hypothesis: the pureJsSignal computation lives in the native library (`libakamaibmp.so`), the 1.9MB ARM64 shared object. If the JS challenge computes a device-data hash and the native code computes fingerprint hashes separately, the native layer would have direct access to Canvas and CSS APIs without needing a WebView. We opened `libakamaibmp.so` in Ghidra.

### The Ghidra Analysis

Three categories were searched:

**MurmurHash3 constants** (`0xcc9e2d51`, `0x1b873593`, `0xe6546b64`): Ghidra's constant search across all segments returned **zero matches**.

**Signal assembly strings** (`pureJsSignal`, `cf-sdk`, `ua_hash`, `pkgHashCode`, `uaHashCode`): string table search returned **zero matches**.

**JNI exports**: only 5 JNI functions:

| JNI Export | Purpose |
|------------|---------|
| `initializeKeyN` | Crypto context initialisation |
| `encryptKeyN` | RSA key encryption |
| `decryptN` | AES-CBC decryption (for server responses) |
| `buildN` | Sensor plaintext assembly and encryption |
| *(test stub)* | Internal testing entry point |

No JNI function takes fingerprint data as input or returns a signal string. The native library is a pure cryptographic engine.

### The Correction

The Ghidra agent reached the correct conclusion: **pureJsSignal IS computed in JavaScript, just not in this build of the challenge JS**.

Our captured script (`sdk_challenge_latest.js`) was from the Argos app running BMP SDK v4.0.4. This build computes a device-data hash using JSBridge getters (the 54-order-key system we had fully reversed). But the `pureJsSignal` -- CSS colour hash, canvas fingerprints -- is computed by a *different configuration* of the challenge JS served under different conditions.

The evidence:

1. The decoded string table contains `sendChallengeResponseIos` and `sendChallengeResponseAndroid` as separate exports -- different builds exercise different response paths.
2. The `pureJsSignal` format (`8,en-US,851,393,{sha256},{flag},{hashA},{hashB}`) uses canvas and CSS APIs requiring a real rendering engine -- exactly what the hidden WebView provides.
3. The native SDK's Java layer (`u7f.java`) stores the signal's SHA-256 hash in SharedPreferences under `ss_hash`, not the signal itself -- it treats the challenge JS as a black box returning an opaque string.

The pureJsSignal computation was eventually found by capturing a different challenge JS variant served after the initial device-data challenge completes. This discovery only became clear after the Frida breakthrough documented in the next chapter, which allowed us to intercept `setSignal()` on a physical device and observe the full pureJsSignal being computed in real time.

---

## What Phase 1-3 Taught Us

Three phases, roughly 12 hours, and the most important finding was a negative result: the thing we were looking for was not where we were looking. This is not failure -- it is the normal shape of reverse engineering work. The phases produced:

- **A complete architectural map** of the challenge JS VM: the dispatch table, the string decode system, the integrity interlock, the dual iOS/Android bridge paths.
- **A working Node.js harness** (`frida/challenge-harness.js`) that executes the unmodified challenge JS, services the collection loop, and captures the device-data signal. This harness remains useful for testing new builds of the challenge script.
- **The O-method mapping** (`data/O-method-mapping.json`): 241 resolved members of the memoisation object, including all JSBridge method names, format strings, and SHA-256 round constants. This mapping was essential for understanding what the challenge JS actually computes.
- **Confirmation that the native library is a pure crypto engine**, not a fingerprinting engine. This eliminated an entire class of hypotheses about where the pureJsSignal might be assembled.
- **The integrity system understanding** (MurmurHash3, X=805, anti-tamper interlock) that informed every subsequent interaction with the challenge JS -- we knew we could never modify the source, which shaped the Frida instrumentation strategy that ultimately cracked the problem.

The lesson: eliminating a hypothesis narrows the search space. The Frida breakthrough that followed was only possible because we understood exactly what the challenge JS *does* do, which made it immediately obvious when we saw it doing something *different* on a real device.
