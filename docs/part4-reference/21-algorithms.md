# Algorithm Reference

This page documents every algorithm used in the Akamai BMP v4.0.4 sensor pipeline, with Python reference implementations. Each algorithm is presented with its exact specification, its role in the sensor, and a calibration value that can be used to verify correctness.

The algorithms fall into four categories: **fingerprint hashing** (Java `String.hashCode`, SHA-256), **self-integrity** (MurmurHash3), **PRNG verification** (MT19937), **counter encoding** (GF(2) polynomial multiplication), **checksum computation** (CRC triplet), **app fingerprinting** (SHA-256 of installed apps), **string deobfuscation** (XOR cipher), and **API authentication** (MD5 sig). Understanding which algorithm is used where -- and equally importantly, which algorithm is *not* used where -- is critical. The deliberate mislabelling of field names throughout the SDK means that grepping for algorithm names in the source produces nothing useful.

---

## 1. Java String.hashCode

**Role:** Computes `pkgHashCode` and `uaHashCode` in the `pureJsSignal`. Despite the field names, neither value hashes the package name or the user agent. Both hash `canvas.toDataURL()` output from two different canvas renderings (280x60 canvases with different `fillText` strings).

**Algorithm:** The standard Java `String.hashCode` polynomial rolling hash. For each character `c` in the string, the hash accumulates as `h = 31 * h + c`, where all arithmetic is performed in signed 32-bit integer space.

**Specification:**

- Initial value: `h = 0`
- For each character: `h = (31 * h + ord(c))`, reduced modulo 2^32
- Final value: interpreted as a signed 32-bit integer (values >= 2^31 are negative)

**Python implementation:**

```python
def java_string_hashcode(s: str) -> int:
    """
    Java String.hashCode(): h = 31*h + c, signed 32-bit.

    Used for pkgHashCode (canvas A) and uaHashCode (canvas B)
    in the pureJsSignal. NOT used for the package name or user agent.
    """
    h = 0
    for c in s:
        h = ((h * 31) + ord(c)) & 0xFFFFFFFF
    return h - 0x100000000 if h >= 0x80000000 else h
```

**Calibration value:**

```python
>>> java_string_hashcode("data:image/png;base64,FAKE_CONSTANT_CANVAS_FINGERPRINT")
-1793983051
```

This calibration value was discovered during differential testing in CloakBrowser. By overriding `canvas.toDataURL()` to return a constant string across both canvas renderings, both `pkgHashCode` and `uaHashCode` collapsed to the same value: `-1793983051`. Testing that value against every common 32-bit hash function (CRC32, DJB2, FNV-1a, Adler32, MurmurHash3 with seeds 0 through 2,000,000) produced zero matches -- except Java `String.hashCode`, which matched exactly. This was the algorithm identification breakthrough documented in Phase 9 of the [reverse engineering journey](../part2-methodology/07-journey-overview.md).

**How the challenge JS implements it:** The VM does not contain a single `*31` opcode that a static grep would find. Instead, the multiplication is distributed across multiple VM case handlers, with the constant 31 never appearing as a literal in the source. This is why searching the 54KB challenge JS for hash algorithm signatures (`*31`, `*33`, `5381`, `<<5`) found nothing.

**Canvas rendering inputs:** Both canvases are 280x60 pixels. The drawing sequence is identical except for the `fillText` string:

- Canvas A (`pkgHashCode`): `fillText("<@nv45. F1n63r,Pr1n71n6!", 10, 40)`
- Canvas B (`uaHashCode`): `fillText("m,Ev!xV67BaU> eh2m<f3AG3@", 10, 40)`

The hash input is the full `data:image/png;base64,...` string returned by `canvas.toDataURL()`. Because canvas rendering is GPU-dependent, the base64 output differs across devices and OS versions, making the hash a genuine device fingerprint.

---

## 2. SHA-256

**Role:** Two distinct uses in the sensor pipeline.

### 2a. CSS System Colour Fingerprint (ua_hash)

Used in VM case `J5` to compute the `ua_hash` field of the `pureJsSignal`. Despite the name, this has nothing to do with the user agent. The challenge JS creates a hidden `<div>`, iterates through 38 CSS system colour names, sets each as the `background-color`, reads `getComputedStyle().backgroundColor`, serialises the resulting colour map as compact JSON (no spaces after colons or commas), and SHA-256 hashes the result.

**Python implementation:**

```python
import hashlib
import json

CSS_SYSTEM_COLORS = [
    "ActiveBorder", "ActiveCaption", "ActiveText", "AppWorkspace",
    "Background", "ButtonBorder", "ButtonFace", "ButtonHighlight",
    "ButtonShadow", "ButtonText", "Canvas", "CanvasText",
    "CaptionText", "Field", "FieldText", "GrayText",
    "Highlight", "HighlightText", "InactiveBorder", "InactiveCaption",
    "InactiveCaptionText", "InfoBackground", "InfoText", "LinkText",
    "Mark", "MarkText", "Menu", "MenuText", "Scrollbar",
    "ThreeDDarkShadow", "ThreeDFace", "ThreeDHighlight",
    "ThreeDLightShadow", "ThreeDShadow", "VisitedText",
    "Window", "WindowFrame", "WindowText",
]


def css_color_hash(color_map: dict) -> str:
    """
    SHA-256 of CSS system colours, serialised as compact JSON.

    The challenge JS reads getComputedStyle().backgroundColor for each
    of the 38 system colour names and hashes the JSON-serialised map.
    """
    ordered = {name: color_map[name] for name in CSS_SYSTEM_COLORS}
    serialised = json.dumps(ordered, separators=(",", ":"))
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()
```

**Calibration value (Pixel 4a, Android 13, Chrome/149 WebView):**

```python
>>> css_color_hash(ANDROID_13_CHROME149_COLORS)
"920a650b922995f6c26c190a3e10da6aee3557b9f7753de59d05b820311f5af5"
```

The 38 CSS system colours vary by OS, browser engine, and sometimes GPU driver. Android WebView (Chrome 149) returns values like `"rgb(118, 118, 118)"` for `ActiveBorder` and `"rgba(51, 181, 229, 0.4)"` for `Highlight`. The full colour map for the Pixel 4a baseline is stored in `src/purejs_signal.py` as `ANDROID_13_CHROME149_COLORS`.

### 2b. Signal Hash Tail

SHA-256 is also used to compute the last 4 hexadecimal characters appended to the signal string in the format `cf-sdk-1-00-0.js#field=value#...#{sha256_tail}`. This tail acts as an integrity check over the signal content. The implementation uses standard SHA-256 over the signal prefix, with the last 4 hex characters of the digest extracted.

```python
def signal_hash_tail(signal_prefix: str) -> str:
    """Last 4 hex chars of SHA-256, appended to the signal string."""
    digest = hashlib.sha256(signal_prefix.encode("utf-8")).hexdigest()
    return digest[-4:]
```

---

## 3. MurmurHash3 (x86-32)

**Role:** Used **once** for the VM self-integrity check. This is the gate that protects the string table decoding: if the hash does not match the embedded expected value, all string pool lookups decode to garbage and the VM silently fails.

**NOT used for `pkgHashCode` or `uaHashCode`.** This was the most time-consuming dead end in the entire project. After finding MurmurHash3 in the challenge JS (the function labelled `xg` in the obfuscated source), the natural assumption was that it computed the fingerprint hashes. Two million seed values (0 through 2,000,000) were brute-forced against the known hash outputs with zero matches, because the function is Java `String.hashCode`, not MurmurHash3.

**Algorithm:** Standard MurmurHash3 x86-32 with one modification: **whitespace characters (char codes 10, 13, and 32) are skipped** during hashing. This ensures that differences in line endings or trailing whitespace between serves do not change the integrity hash.

**Constants:** `c1 = 0xcc9e2d51`, `c2 = 0x1b873593`.

**Seed:** Embedded in the bytecode as an XOR-obfuscated constant. The seed changes with every polymorphic serve of the challenge JS, but the algorithm and constants are stable.

**Python implementation:**

```python
def murmurhash3_x86_32(data: str, seed: int) -> int:
    """
    MurmurHash3 x86-32 with whitespace skipping (chars 10, 13, 32).

    Used ONCE for the VM self-integrity check. The VM calls toString()
    on its own function, hashes the result, and compares against an
    XOR-obfuscated expected value embedded in the bytecode.
    """
    # Strip whitespace chars (LF, CR, space) from input
    filtered = "".join(c for c in data if ord(c) not in (10, 13, 32))
    key = filtered.encode("utf-8")

    h = seed & 0xFFFFFFFF
    length = len(key)
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    # Process 4-byte blocks
    nblocks = length // 4
    for i in range(nblocks):
        k = int.from_bytes(key[i * 4:(i + 1) * 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF

    # Process remaining bytes
    tail = key[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h ^= k1

    # Finalisation mix
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16

    return h
```

**How the integrity check works:** On VM boot, the dispatcher calls `toString()` on its own function body, strips whitespace, computes MurmurHash3 with the serve-specific seed, and compares the result against an XOR-obfuscated expected hash embedded in the bytecode. If the values match, the string table decode key is derived correctly and the VM proceeds. If they do not match -- because the script was modified, because `toString()` behaves differently outside a real browser, or because the seed was extracted incorrectly -- the decode key is wrong and every string pool lookup returns garbage. The VM does not throw an error; it simply produces nonsensical output, which makes debugging extremely difficult.

---

## 4. MT19937 (Mersenne Twister)

**Role:** Generates PRNG verification proofs in sensor fields `-172` and `-170`. The server seeds its own MT19937 identically and verifies that the submitted values are mathematically valid outputs for that seed. This is one of the strongest anti-forgery checks in Tier 2 validation: a generator that does not implement MT19937 correctly produces values that are mathematically impossible.

**Seed:** The current timestamp in milliseconds, masked to 32 bits: `seed = int(time.time() * 1000) & 0xFFFFFFFF`.

**Python implementation:**

```python
class MT19937:
    """Standard Mersenne Twister (MT19937) PRNG, timestamp-seeded."""

    def __init__(self, seed=None):
        if seed is None:
            seed = int(time.time() * 1000) & 0xFFFFFFFF
        self.mt = [0] * 624
        self.mt[0] = seed
        for i in range(1, 624):
            self.mt[i] = (
                1812433253 * (self.mt[i - 1] ^ (self.mt[i - 1] >> 30)) + i
            ) & 0xFFFFFFFF
        self.idx = 624

    def extract(self):
        """Extract a 32-bit unsigned integer from the generator state."""
        if self.idx >= 624:
            for i in range(624):
                y = (self.mt[i] & 0x80000000) + (
                    self.mt[(i + 1) % 624] & 0x7FFFFFFF
                )
                self.mt[i] = self.mt[(i + 397) % 624] ^ (y >> 1)
                if y % 2:
                    self.mt[i] ^= 2567483615
            self.idx = 0
        y = self.mt[self.idx]
        y ^= y >> 11
        y ^= (y << 7) & 2636928640
        y ^= (y << 15) & 4022730752
        y ^= y >> 18
        self.idx += 1
        return y & 0xFFFFFFFF

    def rand_range(self, lo, hi):
        """Return a value in [lo, hi] inclusive."""
        return lo + (self.extract() % (hi - lo + 1))
```

### Field -172: Simple Verification

Four values, each computed as `extract() % 4096`. The server reproduces these by seeding its own MT19937 with the same timestamp and checking the first four outputs modulo 4096.

```python
def mt19937_verify_simple():
    """Field -172: 4 values via MT19937 extract() % 4096."""
    rng = MT19937()
    vals = [rng.extract() % 4096 for _ in range(4)]
    return ",".join(str(v) for v in vals)
```

### Field -170: Cascade Verification

Four values computed through a multiply-and-XOR chain using `rand_range(1, 1000)`. Each value depends on the previous through XOR, creating a cascade where a single incorrect PRNG output invalidates all subsequent values.

```python
def mt19937_verify_cascade():
    """
    Field -170: cascade multiply + XOR.

    val1 = 7 * RandRange(1, 1000)
    val2 = (8 * RandRange(1, 1000)) XOR val1
    val3 = (9 * RandRange(1, 1000)) XOR val2
    val4 = (5 * RandRange(1, 1000)) XOR val3

    Results are signed 32-bit integers.
    """
    rng = MT19937()
    r1 = rng.rand_range(1, 1000)
    r2 = rng.rand_range(1, 1000)
    r3 = rng.rand_range(1, 1000)
    r4 = rng.rand_range(1, 1000)

    val1 = 7 * r1
    val2 = (8 * r2) ^ val1
    val3 = (9 * r3) ^ val2
    val4 = (5 * r4) ^ val3

    def to_signed(v):
        v &= 0xFFFFFFFF
        return v if v < 0x80000000 else v - 0x100000000

    return ",".join(str(to_signed(v)) for v in [val1, val2, val3, val4])
```

**Multipliers:** `7, 8, 9, 5`. These are constants from the native library (`libakamaibmp.so`), not the challenge JS. The cascade verification is computed by `buildN()` in native code, not by the WebView.

**Time sensitivity:** Both fields use the current millisecond timestamp as the seed. The server must know (or be able to infer) this timestamp to verify the PRNG output. This creates a tight timing window -- the sensor must reach the server within a window where the seed can be recovered from the sensor's own timestamp fields.

---

## 5. GF(2) Polynomial Multiplication (counter_large)

**Role:** Encodes the `counter_large` value in field `-115` sub-position 13. This is a carry-less (GF(2)) polynomial multiplication of the touch count by a fixed constant, reduced modulo a degree-64 irreducible polynomial. The output is a large integer in the observed range 10^14 to 10^17.

**Status:** Fully reversed. Verified against all 47 captured `(c5, counter_large)` pairs from 51 real sensor captures with a 100% match rate.

**Algorithm:**

```
counter_large(c5) = CLMUL(c5, 0x6DB60000DB6D) mod (x^64 + x^33 + x^1)
```

Where:

- `CLMUL` = carry-less multiplication (XOR instead of addition at each step)
- `MAGIC = 0x6DB60000DB6D` (120628451531629)
- `MODULUS = 0x10000000300000002` (x^64 + x^33 + x^1)
- Input `c5` = cumulative touch/interaction count for the session (field `-115` sub-position 5)
- Output is a **pure deterministic function of `c5` alone** -- there is no elapsed time dependency, no key schedule, and no per-session randomness

**Python implementation:**

```python
_CLMUL_MAGIC = 0x6DB60000DB6D
_CLMUL_MODULUS = 0x10000000300000002


def compute_counter_large(touch_count):
    """
    GF(2) polynomial multiply for field -115 counter_large.

    Carry-less multiplication of touch_count by a fixed constant,
    reduced modulo x^64 + x^33 + x^1.
    """
    result = 0
    a, b = _CLMUL_MAGIC, touch_count
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        b >>= 1

    # GF(2) polynomial reduction mod MODULUS
    p_deg = _CLMUL_MODULUS.bit_length() - 1  # 64
    while result.bit_length() > p_deg:
        shift = result.bit_length() - _CLMUL_MODULUS.bit_length()
        result ^= _CLMUL_MODULUS << shift

    return result
```

**Calibration values:**

```python
>>> compute_counter_large(0)
0
>>> compute_counter_large(1)
120628451531629
>>> compute_counter_large(955443)
3583004347266257603
```

**How it was reversed:** Static analysis of `libakamaibmp.so` was blocked by OLLVM control-flow flattening and encrypted JNI function bodies. Instead, `counter_large` values were extracted from 51 real sensor captures and analysed mathematically. Three properties were discovered: (1) it is a pure function of `c5` -- identical `c5` always gives identical `counter_large` across all sessions, (2) it is XOR-linear: `CL(a XOR b) = CL(a) XOR CL(b)`, and (3) it is shift-linear: `CL(c5 << 1) = CL(c5) << 1`. These three properties uniquely identify carry-less multiplication by a constant. The constant `0x6DB60000DB6D` was recovered as `CL(1)`. The modulus `0x10000000300000002` was found by GF(2)-dividing the discrepancy for the largest captured test case.

**Corrections to previous documentation:** Earlier versions of this document described this algorithm as "a 16-round balanced Feistel network" with "input pair `(0, touchCount)`" and "key derived from elapsed milliseconds since SDK initialisation." All of this was incorrect. The algorithm is not a Feistel cipher -- it has no rounds, no key schedule, and no time dependency. The confusion arose because the algorithm is implemented in `libakamaibmp.so` behind OLLVM obfuscation, and its output superficially resembled Feistel cipher output (large integers with apparent randomness). The mathematical analysis of captured values was ultimately more productive than attempting to fight through the obfuscated binary.

---

## 6. CRC Triplet (Field -100)

**Role:** Three checksum values appended to the device fingerprint string in field `-100`. The server recomputes `crc1` from the other fields and rejects sensors where it does not match. This is a Tier 2 cross-validation check.

**Python implementation:**

```python
def compute_crc_triplet(device_fingerprint: str, ts_ms: int) -> tuple:
    """
    Compute the three CRC values for field -100.

    Args:
        device_fingerprint: The raw device fingerprint string
            (everything before the CRC values).
        ts_ms: Current timestamp in milliseconds.

    Returns:
        (crc1, crc2, crc3) tuple.
    """
    # crc1: ASCII ordinal sum of the fingerprint string.
    # Only characters with ordinal < 128 are included.
    crc1 = sum(ord(c) for c in device_fingerprint if ord(c) < 128)

    # crc2: Random signed 32-bit integer.
    # In the real SDK this may be a JVM hash, but the server does
    # not appear to validate it tightly.
    import random
    crc2 = random.randint(-2147483648, 2147483647)

    # crc3: Current timestamp in milliseconds, integer-divided by 2.
    crc3 = ts_ms // 2

    return crc1, crc2, crc3
```

**Assembly into field -100:**

```python
dfp_raw = f"-1,uaend,-1,{screen_h},{screen_w},..."  # device fingerprint
crc1, crc2, crc3 = compute_crc_triplet(dfp_raw, ts_ms)
device_fp = f"{dfp_raw},{crc1},{crc2},{crc3}"
```

**Validation behaviour:**

- **crc1** is strictly validated. The server recomputes the ASCII sum from the declared device properties and rejects mismatches. Getting any field in the device fingerprint wrong cascades into a `crc1` mismatch even if the sum computation itself is correct. This is what makes the CRC triplet an effective anti-forgery measure -- it binds the checksum to the content.
- **crc2** appears to be loosely validated or not validated at all. In our testing, random signed 32-bit integers passed consistently. The real SDK may compute this from a JVM-specific hash, but the server tolerance is wide.
- **crc3** is the timestamp divided by two, providing a coarse temporal anchor. The server likely validates that `crc3` is consistent with the sensor's other timestamp fields.

---

## 7. MD5 Sig Parameter

**Role:** Authenticates API requests to the Argos mobile backend. The `sig` query parameter is appended to every API URL (e.g., `/basket/items/count?sig={value}`). This is not part of the BMP sensor itself -- it is an application-level authentication mechanism independent of Akamai's bot detection.

**Algorithm:** Standard MD5 hash of the concatenation: `api_key + api_secret + unix_timestamp`.

**Python implementation:**

```python
import hashlib
import time


def compute_sig() -> str:
    """
    Compute the sig query parameter for Argos API requests.

    Formula: MD5(api_key + api_secret + unix_timestamp)

    The api_key and api_secret are constants extracted from the
    Argos Android APK (decompiled Java source).
    """
    ts = int(time.time())
    payload = f"tfjmpuwm366xnuj7mhcsaea2s9gqt8cCUq{ts}"
    return hashlib.md5(payload.encode()).hexdigest()
```

**Constants:** The API key (`tfjmpuwm366xnuj7mhcsaea2s9gqt8c`) and API secret (`CUq`) are concatenated without any separator, followed by the Unix timestamp as a decimal integer string. These values were extracted from the decompiled Argos Android APK.

**Usage:**

```python
sig = compute_sig()
url = f"https://api.argos.co.uk/api/basket-argos-apps-gateway/apps/gateway/basket/items/count?sig={sig}"
```

The server validates that the `sig` parameter matches the expected MD5 for the current timestamp (with a tolerance window of a few seconds to account for clock skew and network latency). Requests without a valid `sig` are rejected at the application layer before the BMP sensor is even evaluated.

---

## 8. App Fingerprint Hash (Field -166)

**Role:** Computes the `ua_hash` field in position 24 (field `-166`). Despite the misleading name, this does not hash the user agent. It is SHA-256 of the installed non-system Android app package names -- a tracking fingerprint that distinguishes devices by their installed software rather than their hardware.

**Algorithm:**

1. `PackageManager.getInstalledApplications(0)` -- enumerate all installed applications
2. Filter to `(applicationInfo.flags & 1) == 0` -- non-system apps only (excludes pre-installed system apps)
3. Join the remaining package names with `#` as the separator
4. SHA-256 hash the joined string
5. Return as a 64-character lowercase hexadecimal string

**Python implementation:**

```python
import hashlib


def compute_app_fingerprint(installed_apps: list) -> str:
    """
    Compute the -166 'ua_hash' field.

    Despite the name, this is SHA-256 of non-system app package names
    joined with '#'. Computed by rl5.c() -> xg8.b() in the Java SDK.
    """
    apps_str = "#".join(installed_apps)
    return hashlib.sha256(apps_str.encode("utf-8")).hexdigest()
```

**Source chain:** Java SDK classes `rl5.c()` (line 100--113) enumerates apps via `PackageManager`, filters to non-system, joins with `#`, then passes to `xg8.b()` (line 45--64) which calls `MessageDigest.getInstance("SHA-256")`. The `"SHA-256"` string constant is itself obfuscated via `CircleProgressBar.a("JM^\"...")` -- decoded at runtime by the XOR cipher documented in section 9.

**No native code involvement.** The `-166` field is assembled entirely by the Java layer and passed to `buildN()` as one of the 28 Java-side key-value pairs. The native library does not modify it.

**Generator usage:** The generator can produce this value synthetically for any device profile by providing a plausible list of Android app package names. The server cannot cross-validate this against the real device's installed apps -- it is a fingerprint for tracking consistency across sessions, not a verifiable attestation.

**Why the name is misleading:** Like the `pureJsSignal` field names, `ua_hash` is a deliberate misnomer. A reverse engineer who takes the name at face value will attempt to find a hash function that matches `SHA-256(navigator.userAgent)` and fail, because the input is not the user agent at all. This misdirection was confirmed when `frida/dump-environment.js` showed that `SHA-256(UA)` does not match the captured `ua_hash` value.

---

## 9. CircleProgressBar.a() String Deobfuscation

**Role:** Decodes obfuscated string constants throughout the Akamai BMP Java SDK. Despite the innocuous class name -- chosen to blend in with UI utility code -- `CircleProgressBar.java` is the SDK's primary string deobfuscation function. Every sensitive string in the Java layer (algorithm names, shell commands, bridge method names) is stored as an encoded constant and decoded at runtime through this function.

**Algorithm:** XOR each character with a byte from a rolling 17-byte key. The key is applied cyclically: character at position `i` is XORed with `key[i % 17]`.

**Key array:** `[25, 5, 31, 15, 45, 41, 44, 43, 34, 33, 32, 31, 6, 36, 34, 35, 42]` (17 bytes).

**Python implementation:**

```python
_CPB_KEY = [25, 5, 31, 15, 45, 41, 44, 43, 34, 33, 32, 31, 6, 36, 34, 35, 42]


def circleprogressbar_decode(encoded: str) -> str:
    """
    Decode a string obfuscated by CircleProgressBar.a().

    XOR each character with the corresponding byte from a 17-byte
    rolling key. Used throughout the Akamai BMP Java SDK for all
    sensitive string constants.
    """
    return "".join(
        chr(ord(c) ^ _CPB_KEY[i % 17])
        for i, c in enumerate(encoded)
    )
```

**Known decoded strings:**

| Encoded Input | Decoded Output | Used By | Purpose |
|---------------|---------------|---------|---------|
| `"JM^\"..."` | `"SHA-256"` | `xg8.b()` | MessageDigest algorithm name for app fingerprint hash |
| `"zdk/..."` | `"cat /proc/cpuinfo"` | `a8f.a()` | Shell command for CPU architecture detection (field `-104`) |
| `"xw\|g..."` | `"architecture"` | `a8f.a()` | Search marker in cpuinfo output |
| `"xw\|g...<..."` | `"architecture: "` | `a8f.a()` | Split delimiter (with colon and space) for extracting the value |
| `"SV]}DMKN"` | `"JSBridge"` | Bridge setup | Android JavaScript bridge object name |

**How it was reversed:** The key was recovered via a known-plaintext XOR attack. The encoded string for `a8f.i` was hypothesised to decode to `"cat /proc/cpuinfo"` (17 characters, matching the encoded length). XORing the hypothesis against the encoded bytes yielded the per-position key, which was then validated by successfully decoding all four encoded strings from `a8f.java` and `zu5.java` to produce sensible output.

---

## Algorithm-to-Field Mapping

| Algorithm | Field | Akamai Name | What It Actually Computes |
|-----------|-------|-------------|--------------------------|
| Java `String.hashCode` | `-90` (pureJsSignal) | `pkgHashCode` | Canvas A `toDataURL()` output |
| Java `String.hashCode` | `-90` (pureJsSignal) | `uaHashCode` | Canvas B `toDataURL()` output |
| SHA-256 | `-90` (pureJsSignal) | `ua_hash` | 38 CSS system colour values (JSON) |
| SHA-256 | `-166` | `ua_hash` (misnomer) | Installed non-system app package names joined with `#` |
| SHA-256 | signal tail | -- | Signal string integrity check |
| MurmurHash3 x86-32 | VM internal | -- | `toString()` of VM function body |
| MT19937 | `-172` | -- | 4 values, `extract() % 4096` |
| MT19937 | `-170` | -- | 4 values, cascade multiply + XOR |
| GF(2) CLMUL | `-115` | `counter_large` | `CLMUL(c5, constant)` mod irreducible poly |
| ASCII sum | `-100` | `crc1` | Device fingerprint string |
| Random int32 | `-100` | `crc2` | N/A (random or JVM hash) |
| Timestamp / 2 | `-100` | `crc3` | Current timestamp |
| XOR cipher | Java SDK | `CircleProgressBar.a()` | Obfuscated SDK string constants |
| MD5 | `sig` param | -- | API key + secret + timestamp |

---

## Common Pitfalls

**Assuming field names describe their contents.** Every `pureJsSignal` field name is deliberately misleading. `ua_hash` does not hash the user agent. `pkgHashCode` does not hash the package name. `uaHashCode` does not hash the user agent either. This misdirection is intentional and specifically targets reverse engineers who work by name association.

**Assuming MurmurHash3 computes the fingerprint hashes.** MurmurHash3 appears in the challenge JS source and is the obvious candidate for the fingerprint hashes. It is used exactly once, for the self-integrity check, and nowhere else. The fingerprint hashes use Java `String.hashCode`, which is implemented across multiple VM opcodes and is invisible to static pattern matching.

**Using unsigned integers for Java `String.hashCode`.** The hash must be returned as a signed 32-bit integer. The real SDK returns negative values for roughly half of all inputs. Returning unsigned values (e.g., `2501010645` instead of `-1793956651`) will fail server-side verification.

**Seeding MT19937 with seconds instead of milliseconds.** The PRNG seed is `int(time.time() * 1000)`, not `int(time.time())`. Using seconds produces an entirely different PRNG sequence that will fail the Tier 2 mathematical verification.

**Assuming `counter_large` is a Feistel cipher.** Earlier analysis (including earlier versions of this document) described the `-115` counter as a "16-round Feistel network with elapsed time as key." This was wrong on every count. The algorithm is GF(2) polynomial multiplication -- a carry-less multiply by a fixed constant with no rounds, no key schedule, and no time dependency. The confusion arose from the output superficially resembling Feistel output and from the difficulty of static analysis through OLLVM-obfuscated native code. The correct algorithm was identified through mathematical analysis of captured values, not through binary reverse engineering.

**Assuming `ua_hash` in field `-166` hashes the user agent.** The field name `ua_hash` is a misnomer. The value is SHA-256 of installed non-system app package names joined with `#`, computed entirely in Java by `rl5.c()` → `xg8.b()`. Attempting to reproduce the captured value by hashing `navigator.userAgent` or the WebView UA string will always fail -- it does not hash any user agent string at all.
