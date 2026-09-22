# Sensor Format & Envelope Structure

The `x-acf-sensor-data` HTTP header carries every piece of information the BMP SDK has collected about the device, the session, and the user. Understanding its structure -- from the outer encrypted envelope down to individual field positions -- is essential before attempting generation or server-side analysis.

This page documents the format as implemented in BMP SDK v4.0.4 on Android, verified against 189 captured `buildN` inputs from a Pixel 4a running Argos 5.26.0.

---

## The Outer Envelope

A complete sensor header looks like this:

```
6,a,{RSA_AES},{RSA_HMAC}${AES_CBC_PAYLOAD}${T1},{T2},{T3}$$${DEVICE_ATTESTATION}
```

The dollar sign `$` acts as the primary segment delimiter, splitting the header into four parts. The triple-dollar `$$$` before the attestation blob is a distinct separator -- it marks the boundary between the cryptographic payload (produced by native code) and the device integrity proof (appended by the Java layer).

### Envelope Segment Table

| Segment | Contents | Source |
|---------|----------|--------|
| `6,a,{RSA_AES},{RSA_HMAC}` | Protocol version (`6`), sub-version (`a`), Base64 RSA-PKCS1v15-encrypted AES-128 key, Base64 RSA-PKCS1v15-encrypted HMAC-SHA256 key. | Native SDK. RSA public key is a 1024-bit PKCS#1 key embedded in `libakamaibmp.so`. AES key (16 bytes) and HMAC key (32 bytes) are generated fresh per `CryptoContext` but stable within a session. |
| `{AES_CBC_PAYLOAD}` | Base64 encoding of `IV (16 bytes) ‖ AES-128-CBC(PKCS7(plaintext)) ‖ HMAC-SHA256(IV ‖ ciphertext)`. The HMAC covers the IV concatenated with the ciphertext, providing authenticated encryption. | Native `encryptKeyN` / `buildN` JNI exports. The IV is random per sensor. |
| `{T1},{T2},{T3}` | Three comma-separated integers representing timing metadata. T1 = total encryption duration in milliseconds (observed range 80--300). T2 = RSA key-wrapping time (25--45 ms). T3 = AES encryption time (27--50 ms). | Computed by the native SDK around the encryption calls. |
| `{DEVICE_ATTESTATION}` | URL-encoded binary attestation blob, appended after the `$$$` delimiter. Starts with `AAQAAAAF` (header with version byte and flags). Typically 372 characters for a Pixel 4a. | Java SDK layer (`b.java:2382-2385`). NOT part of the native `buildN` output. Captured once per device session. |

!!! warning "Attestation is mandatory"
    Sensors missing the `$$$` + attestation suffix are structurally incomplete and trigger instant rejection (scoring research places this as the single highest-impact field -- sensors without it score 70+, well into the automatic block tier).

---

## Annotated Example

Below is a real sensor with each segment labelled. Line breaks are added for readability; the actual header is a single unbroken string.

```text
6,a,                                          ← protocol version, sub-version
kJ2Qr8x...base64...Yw==,                     ← RSA(AES-128 key), 172 chars
mF4Lp3v...base64...Ag==                       ← RSA(HMAC-SHA256 key), 172 chars
$                                             ← segment delimiter
V7nB2kQ...base64...Rw==                       ← IV ‖ AES-CBC(plaintext) ‖ HMAC
$                                             ← segment delimiter
187,34,41                                     ← T1=187ms, T2=34ms, T3=41ms
$$$                                           ← attestation delimiter
AAQAAAAF%2f%2f%2f%2f%2f5T2X...%3d             ← URL-encoded device attestation
```

When the server receives this header, it performs the following steps in order:

1. Split on `$$$` to separate the cryptographic payload from the attestation blob.
2. Split the cryptographic portion on `$` to obtain the header, ciphertext, and timing segments.
3. Parse the header to extract the protocol version and the two RSA-encrypted keys.
4. Decrypt the AES key and HMAC key using the server's RSA private key (PKCS1v15).
5. Verify the HMAC-SHA256 tag over `IV ‖ ciphertext`.
6. Decrypt the AES-128-CBC ciphertext using the recovered key and the 16-byte IV prefix.
7. Remove PKCS7 padding to recover the plaintext.

---

## Plaintext Structure

After decryption, the plaintext is a flat string of 30 fields separated by the delimiter `-1,2,-94,`. The delimiter is unusual -- it resembles a negative field ID, which is deliberate obfuscation to complicate naive parsing.

```
4.0.4-1,2,-94,-90,screenHeight=2138#screenWidth=...#mapping_flag=1-1,2,-94,-70,-1,2,-94,...
```

### First Field: Bare SDK Version

The first field (position 0) is the bare SDK version string with **no field ID prefix**. It appears immediately at the start of the plaintext:

```
4.0.4
```

### All Subsequent Fields: ID-Prefixed

Every field from position 1 onwards is prefixed with its numeric field ID followed by a comma:

```
-90,screenHeight=2138#screenWidth=1080#startTime=...
```

The field IDs are negative integers (e.g., `-90`, `-70`, `-100`). They are not sequential -- the numbering is sparse and grouped by functional category. There are 30 fields at positions 0 through 29, ordered identically across all 189 captured traces.

### Field Summary

| Position | Field ID | Brief Description |
|----------|----------|-------------------|
| 0 | *(none)* | SDK version (`4.0.4`) |
| 1 | -90 | Challenge JS signal (pureJsSignal, serverSideSignal) |
| 2 | -70 | Reserved (empty) |
| 3 | -80 | Reserved (empty) |
| 4 | -121 | Reserved (empty) |
| 5 | -100 | Device fingerprint (build props, screen, checksums) |
| 6 | -101 | Sensor capability flags (`do_dis,dm_dis,t_en`) |
| 7 | -102 | SDK state code (`-1`) |
| 8 | -103 | Activity lifecycle events |
| 9 | -104 | CPU architecture data (SDK constant + `/proc/cpuinfo` architecture level) |
| 10 | -108 | Text input events (empty when unused) |
| 11 | -112 | Performance metrics (9 values) |
| 12 | -115 | Rolling counters: GF(2) CLMUL-encoded counter, current timestamp, 17 values |
| 13 | -117 | Touch/motion trail (empty when unused) |
| 14 | -120 | Touch detail window |
| 15 | -144 | Orientation queue detail (empty) |
| 16 | -160 | Orientation aggregate (empty) |
| 17 | -142 | Orientation detail (empty) |
| 18 | -145 | Motion queue detail (empty) |
| 19 | -161 | Motion aggregate (empty) |
| 20 | -143 | Motion detail (empty) |
| 21 | -150 | Capture control flags (`1,1` or `0,1`) |
| 22 | -163 | App identity (cert SHA-1, version, timestamps) |
| 23 | -165 | OS info (Android version, locale, IP) |
| 24 | -166 | Android build info (build ID, baseband, ABIs, app fingerprint hash, WebView UA) |
| 25 | -171 | API endpoint URL |
| 26 | -240 | Control flag (`0`) |
| 27 | -172 | MT19937 verification -- simple (4 values mod 4096) |
| 28 | -164 | Security patch date (native-added) |
| 29 | -170 | MT19937 verification -- cascade (multiply+XOR chain) |

---

## Fields Added by Java vs Native Code

Of the 30 fields, **28 are assembled by the Java layer** and passed to the native `buildN` JNI function as key-value pairs (positions 0--27). The native code then appends **2 additional fields** before encrypting the complete plaintext:

| Added by | Fields | Evidence |
|----------|--------|----------|
| **Java** (28 pairs) | Positions 0--27: SDK version, -90, -70, -80, -121, -100, -101, -102, -103, -104, -108, -112, -115, -117, -120, -144, -160, -142, -145, -161, -143, -150, -163, -165, -166, -171, -240, -172 | All 189 Java `buildN` input traces contain exactly 28 pairs. |
| **Native** (2 fields) | Position 28: **-164** (security patch date) -- Ghidra analysis at `0x0019d85c` shows `buildN` calling `GetStaticFieldID("SECURITY_PATCH")` on `android.os.Build$VERSION`. Position 29: **-170** (MT19937 cascade) -- cascade multiply+XOR algorithm implemented in native code. | Ghidra disassembly of `libakamaibmp.so`, confirmed by the absence of these two fields from the Java-side pair list. |

---

## Session Stability Categories

Not all fields change at the same rate. Understanding stability is critical for generation: re-rolling a device-stable field on every call is as suspicious as freezing a per-call dynamic field across a session.

### Stability Summary Table

| Category | Fields | Behaviour |
|----------|--------|-----------|
| **Immutable** | -70, -80, -121, -108, -117, -144, -160, -142, -145, -161, -143, -240 | Always empty or constant zero. These fields represent sensor channels that are disabled or unused on the baseline device profile (orientation disabled, motion disabled, no text input). They never change regardless of session or device. |
| **Device-stable** | -101, -102, -104, -165, -166, -171, -164, SDK version | Set once by the device and app configuration. Field -104 is a hardcoded SDK constant plus the CPU architecture level from `/proc/cpuinfo` (e.g. `8` for ARMv8). Identical across all sessions on the same device running the same app version. Changing any of these mid-session is a clear fabrication signal. |
| **Session-stable** | -90, -112, -163, -150 (after first call), attestation blob | Set at SDK initialisation and reused for the lifetime of the session. The -112 performance metrics are measured once at startup; the -163 timestamps are recorded once; the -90 challenge signal is computed once per WebView load. Vary across sessions but are constant within one. |
| **Per-call dynamic** | -100, -103, -115, -172, -170, -150 (first call only) | Change on every sensor generation. Field -100 includes a random CRC and a timestamp-derived value. Field -115 contains rolling counters and the current Unix timestamp. Fields -172 and -170 are freshly seeded MT19937 outputs. Field -150 has value `1,1` on the first call and `0,1` thereafter, making the first-call variant dynamic and all subsequent calls session-stable. |

!!! note "First-call behaviour"
    Field -150 and field -103 exhibit split behaviour. On the first sensor in a session, -150 is `1,1` and -103 contains lifecycle event timestamps. On all subsequent sensors, -150 is `0,1` and -103 is empty. The server uses this asymmetry to verify that the first sensor in a new session is genuinely the first.

---

## Putting It Together

A generator must respect all four layers of this format:

1. **Envelope**: Produce the `6,a,...$...$T1,T2,T3$$$...` structure with valid RSA key wrapping, AES-CBC encryption, HMAC integrity, and a real attestation blob.
2. **Plaintext assembly**: Join exactly 30 fields with the `-1,2,-94,` delimiter, starting with the bare SDK version.
3. **Field correctness**: Each field must contain values consistent with its source (device profile, session state, or fresh computation).
4. **Stability discipline**: Immutable fields stay empty, device-stable fields stay locked to the profile, session-stable fields stay locked to the session, and per-call fields vary naturally on every generation.

Getting the envelope right is necessary but not sufficient. Getting individual fields right is necessary but not sufficient. The server validates the *relationships* between fields -- a correct -166 app fingerprint hash that does not match the declared package identity, or a -115 timestamp that predates the -163 init timestamp, will fail cross-validation even though each field is individually well-formed.
