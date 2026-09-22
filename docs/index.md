# Akamai BMP Mobile SDK -- Reverse Engineering Documentation

Akamai Bot Manager Premier is the mobile SDK that sits inside apps like Argos, silently spinning up a hidden WebView, running a polymorphic JavaScript VM, fingerprinting the device through deliberately misnamed algorithms, encrypting everything with RSA-wrapped AES, and shipping the result as an HTTP header on every API request. It is one of the most sophisticated mobile anti-bot systems in production.

We cracked it. Every algorithm. Every field. Every validation tier -- with [six known gaps](part4-reference/19-field-reference.md#known-gaps) documented in the field reference.

!!! success "Proof: 80/80"
    **80 consecutive HTTP 200 responses** over 2 minutes at 1 request/second against the live Argos API, using only generated sensors -- zero real devices at runtime, zero blocks.

---

## What We Found

Akamai BMP v4.0.4 uses a hidden WebView inside mobile apps to run a polymorphic JavaScript VM that fingerprints the device through three algorithms. Their internal names are **deliberately misleading by design** -- none of them hash what the name suggests:

| Fingerprint | Akamai's Name | What It Actually Is |
|-------------|---------------|---------------------|
| CSS system colour hash | `ua_hash` | SHA-256 of 38 CSS `getComputedStyle` colour values (not the user agent) |
| Canvas rendering hash A | `pkgHashCode` | Java `String.hashCode` of canvas `toDataURL()` output (not the package name) |
| Canvas rendering hash B | `uaHashCode` | Java `String.hashCode` of a second canvas rendering (not the user agent) |

The sensor payload -- 30 fields, AES-128-CBC encrypted with RSA-1024 key wrapping and HMAC-SHA256 integrity -- was fully reversed through static analysis of 54–58KB of obfuscated JavaScript, Frida instrumentation on a physical Pixel 4a, Ghidra binary analysis of `libakamaibmp.so`, and systematic differential testing in a stealth browser.

---

## Key Results

Three numbers summarise ~12 hours of continuous analysis:

- **3 algorithms cracked** -- SHA-256 CSS colour hashing (`ua_hash`), Java `String.hashCode` canvas fingerprinting (`pkgHashCode` and `uaHashCode`), and the MurmurHash3 self-integrity gate (seed 88692) that protects the VM's string tables. Each was identified through differential testing, not guessing.
- **30-field sensor format reversed** -- Every field in the `x-acf-sensor-data` plaintext mapped to its source: device telemetry from 18 `@JavascriptInterface` getters, JS-computed fingerprints, behavioural event buffers, timing data, and PRNG verification values. The complete field reference is in [Part 4](part4-reference/19-field-reference.md).
- **4-tier server validation model mapped** -- From IP/TLS fingerprinting at the network edge (Tier 0) through RSA key recovery and HMAC integrity (Tier 1), CRC cross-validation and PRNG proofs (Tier 2), to behavioural analysis and attestation checking (Tier 3). Understanding the tiers meant understanding what could be faked and what had to be correct.

---

## Documentation Structure

This documentation is organised in four parts across 24 pages.

### [Part 1: Understanding Akamai BMP](part1-understanding/01-overview.md)

How the system works. Architecture, data flow, sensor format, the polymorphic JS VM, `pureJsSignal` fingerprinting, and server-side validation tiers.

| Page | Topic |
|------|-------|
| [01 -- System Overview](part1-understanding/01-overview.md) | SDK architecture, component roles, the hidden WebView, `libakamaibmp.so` |
| [02 -- Data Flow](part1-understanding/02-data-flow.md) | End-to-end sensor pipeline from app init to server verdict |
| [03 -- Sensor Format](part1-understanding/03-sensor-format.md) | Envelope structure, 30-field plaintext layout, encryption layers |
| [04 -- Challenge JS VM](part1-understanding/04-challenge-js.md) | Polymorphic webpack VM, bytecode interpreter, XOR string tables, self-integrity |
| [05 -- pureJsSignal](part1-understanding/05-purejs-signal.md) | The three fingerprint algorithms and why their names lie |
| [06 -- Server Validation](part1-understanding/06-server-validation.md) | Four-tier validation model from network to behavioural |

### [Part 2: Reverse Engineering Methodology](part2-methodology/07-journey-overview.md)

How we cracked it. Eleven phases from initial static analysis through the Frida breakthrough, CloakBrowser differential testing, and algorithm identification. Every dead end is documented alongside what it taught us.

| Page | Topic |
|------|-------|
| [07 -- Journey Overview](part2-methodology/07-journey-overview.md) | Phase timeline, tooling decisions, pivotal moments |
| [08 -- Static Analysis](part2-methodology/08-static-analysis.md) | Decompiling 20,991 Java files, mapping the SDK layer, reading the JS VM |
| [09 -- Frida Breakthrough](part2-methodology/09-frida-breakthrough.md) | Hooking `setSignal`, capturing plaintext sensors, the moment it clicked |
| [10 -- Differential Testing](part2-methodology/10-differential-testing.md) | CloakBrowser-driven A/B testing to isolate algorithm inputs |
| [11 -- Final Verification](part2-methodology/11-final-verification.md) | The 80/80 proof run and what it validated |
| [12 -- Lessons Learned](part2-methodology/12-lessons-learned.md) | What worked, what wasted time, what transfers to other targets |

### [Part 3: The Generator](part3-generator/13-quickstart.md)

How to use the tools. Quick start, generator internals, HTTP sensor server, API client integration, Frida capture scripts, and device profile customisation.

| Page | Topic |
|------|-------|
| [13 -- Quick Start](part3-generator/13-quickstart.md) | From zero to valid sensors in five commands |
| [14 -- Generator Internals](part3-generator/14-generator-internals.md) | How `bmp_generator.py` assembles and encrypts sensors |
| [15 -- Sensor Server](part3-generator/15-sensor-server.md) | HTTP server for on-demand sensor generation |
| [16 -- API Client](part3-generator/16-api-client.md) | TLS fingerprinting, cookie policy, header ordering |
| [17 -- Frida Scripts](part3-generator/17-frida-scripts.md) | One-shot signal capture, canvas interception, environment dumping |
| [18 -- Device Profiles](part3-generator/18-device-profiles.md) | Creating and customising device fingerprint profiles |

### [Part 4: Reference](part4-reference/19-field-reference.md)

Field-by-field reference for all 30 sensor fields, encryption specification, algorithm implementations, cookie and TLS policy, version resilience guide, and glossary.

| Page | Topic |
|------|-------|
| [19 -- Field Reference](part4-reference/19-field-reference.md) | All 30 sensor fields with types, sources, and validation rules |
| [20 -- Encryption](part4-reference/20-encryption.md) | AES-128-CBC, RSA-1024, HMAC-SHA256: complete specification |
| [21 -- Algorithms](part4-reference/21-algorithms.md) | SHA-256 CSS hash, Java `String.hashCode`, MurmurHash3 self-integrity |
| [22 -- Cookie & TLS](part4-reference/22-cookie-policy.md) | `ak_bmsc`, `akavpau_*` cookie handling; JA3 and `okhttp4_android_13` TLS profile |
| [23 -- Version Resilience](part4-reference/23-version-resilience.md) | What changes between SDK versions and what stays stable |
| [24 -- Glossary](part4-reference/24-glossary.md) | Terms, abbreviations, and Akamai-specific nomenclature |

---

## Quick Start

```bash
# 1. Capture device data (one-time, requires physical device with target app)
frida -U -f com.homeretailgroup.argos.android -l frida/capture-signal.js

# 2. Start the sensor server
python src/sensor_server.py --port 8787

# 3. Verify health
curl http://localhost:8787/health
# {"ok": true, "count": 0, "signal_len": 662, "token_len": 372}

# 4. Fetch a sensor
curl http://localhost:8787/sensor
# 6,a,{RSA_AES},{RSA_HMAC}${AES_CBC_PAYLOAD}${T1},{T2},{T3}$$${DEVICE_ATTESTATION}

# 5. Use in any HTTP client
# Set x-acf-sensor-data header to the sensor value
# Use okhttp4_android_13 TLS profile
# Forward only ak_bmsc and akavpau_vpc_api_retail cookies
```

Step 1 runs once per device profile. Steps 2--5 run without a device -- the generator produces valid sensors from the captured profile data indefinitely.

For the full walkthrough, see [Quick Start](part3-generator/13-quickstart.md).

---

## Target

| Property | Value |
|----------|-------|
| App | Argos Android v5.26.0 (`com.homeretailgroup.argos.android`) |
| SDK | Akamai BMP v4.0.4 |
| Device baseline | Google Pixel 4a (sunfish), Android 13, Chrome/149 WebView |
| Native library | `libakamaibmp.so` (CyberFend, ARM64, 1.9MB decrypted) |
| Challenge JS | `/_sec/sdk_challenge.js` (~54--58KB, polymorphic per-serve) |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| **Frida** | Dynamic instrumentation on physical Pixel 4a (Android 13) |
| **Ghidra** | Static analysis of `libakamaibmp.so` (CyberFend native library) |
| **CloakBrowser** | Stealth Chromium (58 C++ patches) for differential testing |
| **androguard / JADX** | APK decompilation (20,991 Java files) |
| **Node.js VM harness** | Challenge JS execution with mock `@JavascriptInterface` |

---

## Sensor Format at a Glance

The `x-acf-sensor-data` header follows this envelope structure:

```
6,a,{RSA(AES_key)},{RSA(HMAC_key)}${b64(IV||ciphertext||HMAC)}${T1,T2,T3}$$${attestation}
```

Inside the encrypted payload: 30 fields delimited by `-1,2,-94,`, containing device telemetry, JS fingerprints, behavioural buffers, and PRNG proofs. The encryption is AES-128-CBC with HMAC-SHA256 integrity and RSA-1024-PKCS1v15 key wrapping -- AES and HMAC keys are generated once per session (per `CryptoContext`), with only the IV fresh per sensor.

For the complete field-by-field breakdown, see [Sensor Format](part1-understanding/03-sensor-format.md) and [Field Reference](part4-reference/19-field-reference.md).

---

!!! note "Disclaimer"
    This documentation is published for educational and security research purposes only. It documents how a specific anti-bot system works at a technical level. Use this knowledge responsibly and in compliance with applicable laws and terms of service.
