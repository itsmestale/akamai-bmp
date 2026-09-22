# Version Resilience & Maintenance

A sensor generator is a living system. It works today because the SDK version, RSA key, device attestation, and field format all match the version of Akamai BMP currently deployed in the target app. Any of these can change independently, at any time, without notice. This page documents the three layers of change that affect sensor generation, the detection vectors that exploit staleness, and the maintenance checklist that keeps the generator operational across updates.

---

## Three Layers of Change

Changes to the Akamai BMP ecosystem fall into three distinct categories, each with different frequency, different detection risk, and different remediation cost. Understanding which layer has changed is the first step in any maintenance response.

### Layer 1: Per-Serve Polymorphism (Challenge JS)

Every HTTP request to `/_sec/sdk_challenge.js` returns a textually unique build. The Akamai transpiler randomises cosmetic elements while preserving all functional behaviour. This polymorphism is by design --- it defeats naive static analysis tools --- but it is irrelevant to sensor generation because the generator does not execute or parse the challenge JS at runtime.

#### Per-Serve Change Table

| Element | Changes Per Serve | Stable Across Serves | Impact on Generator |
|---------|-------------------|----------------------|---------------------|
| IIFE wrapper function name | Yes --- e.g. `dsXEzOjmVs` vs `dlIXcSWZBK` | No | None. Generator does not execute challenge JS. |
| All variable and function names | Yes --- 100% randomised, zero overlap between builds | No | None |
| Integrity marker (hex constant) | Yes --- e.g. `38d466e` vs `8a6c3c3` | No | None |
| MurmurHash3 seed | Yes --- e.g. 88692 vs 90986 | No | None |
| X (integrity result) | Yes --- derived from marker minus hash | No | None |
| Canvas `fillText` strings | Yes --- per-build random text | No | None. Canvas hashes are pre-captured from a real device, not computed at generation time. |
| XOR pool raw key material | Yes --- key bytes change because X changes | No | None |
| SHA-256 implementation | No | Yes --- all 64 round constants and 8 initial hash values identical | N/A |
| MurmurHash3 algorithm | No | Yes --- standard x86-32 variant | N/A |
| VM dispatch structure | No | Yes --- case numbers (P5=131, J5=55, F5=345) derive from JSFuck digit computation, not randomisation | N/A |
| Canvas drawing pipeline | No | Yes --- same colours (`rgb(102, 204, 0)`, `#f60`, `rgb(120, 186, 176)`), same dimensions (280x60), same shapes. Only `fillText` text varies. | N/A |
| 38 CSS system colour names | No | Yes --- same 38 names in the same order | N/A |
| Java `String.hashCode` algorithm | No | Yes --- `h = 31*h + charCode`, signed 32-bit | N/A |
| Signal field layout | No | Yes --- `8,locale,height,width,ua_hash,,0,pkgHashCode,uaHashCode` | N/A |
| Bootstrap table (`pk`) | No | Yes --- same 8 plaintext strings | N/A |

**Key insight:** Per-serve polymorphism is purely cosmetic. The generator consumes pre-captured fingerprint hashes and does not interact with the challenge JS at runtime. No maintenance action is required when a new polymorphic build is observed --- the underlying algorithms and output format remain identical.

### Layer 2: Per-App-Update Changes (SDK and APK)

When the target app (Argos) releases a new version, or when Akamai updates the BMP SDK embedded within it, several hard-coded values inside the generator may become stale. These changes are infrequent (weeks to months between updates) but require active remediation when they occur. A stale SDK version string or an outdated RSA key will cause every generated sensor to fail validation.

#### Update-Required Fields Table

| Field | Current Value | How to Detect Change | Remediation |
|-------|---------------|----------------------|-------------|
| `SDK_VERSION` | `4.0.4` | Compare `sdkVersion()` output via Frida hook on `u7f.java`. If the returned string differs from the hardcoded value, the SDK has been updated. | Update the version string in `DeviceProfile` and in the `-100` field assembly. |
| `RSA_PEM` | 1024-bit RSA public key | Decompile the new APK with JADX or androguard. Search the `com.cyberfend.cyfsecurity` namespace for the PEM-encoded public key. Compare against the key hardcoded in `CryptoContext`. | Replace the RSA public key constant. If Akamai upgrades to RSA-2048, the entire key-wrapping logic must be updated. |
| `app_version` | `5.26.0` | Read from APK manifest (`AndroidManifest.xml`): `android:versionName`. | Update in `DeviceProfile.app_version`. |
| `app_version_code` | `2042300` | Read from APK manifest: `android:versionCode`. | Update in `DeviceProfile.app_version_code` and in the User-Agent string template. |
| `sig_sha1` | SHA-1 of APK signing certificate | Run `keytool -printcert -jarfile argos.apk` or extract via `apksigner verify --print-certs`. | Update in `DeviceProfile.sig_sha1`. This value appears in the `-100` device fingerprint field. |
| `sensor_hash` | `s5-0.5-10252351` | Frida capture of the `-100` field from a real sensor. The `sensor_hash` is a **compile-time constant** baked into the Java SDK layer at Akamai's build time --- it is not computed at runtime by native code. Format: `s{format_version}-{sub_version}-{build_number}`. | Update the hardcoded value in `build_payload()`. |
| Field order | 30 fields in captured sequence | Diff a new plaintext capture (via Frida `buildN()` hook) against the current field template. Any reordering, addition, or removal of `-1,2,-94,` delimited fields indicates a format change. | Rebuild `build_payload()` to match the new field sequence. |
| `device_attestation` | Captured 254-byte blob | Frida hook on the `$$$` suffix of the assembled header. If the blob format, length, or encoding changes, the attestation layer has been updated. | Recapture from a real device. If Akamai migrates from SafetyNet to Play Integrity (or changes the attestation challenge), the capture methodology may need updating. |

**Detection lag matters.** The most dangerous scenario is a silent SDK update embedded in a routine app release. The app version changes visibly on the Play Store, but the SDK version change is invisible without Frida instrumentation or APK decompilation. A monitoring routine that checks the Play Store for new Argos releases and triggers an automated Frida capture on update is the most reliable defence against detection lag.

### Layer 3: Per-Device Differences

When the generator is extended to support devices beyond the baseline Pixel 4a, every device-dependent value in the sensor must be updated to match the new hardware. These are not "changes" in the version-update sense --- they are configuration differences that must be consistent within a single sensor.

| Value Category | Examples | Source |
|----------------|----------|--------|
| Screen dimensions | `screen_w`, `screen_h`, `density`, `density_scale` | `WindowManager.getDefaultDisplay()` via Frida, or from device specifications |
| Build identity | `Build.MODEL`, `Build.DEVICE`, `Build.BOARD`, `Build.HARDWARE`, `Build.PRODUCT`, `Build.FINGERPRINT`, `Build.ID` | `adb shell getprop` or Frida `Java.use('android.os.Build')` |
| GPU and WebView values | WebView version string, GPU renderer, GPU vendor | `navigator.userAgent` from the WebView, `GLES20.glGetString()` via Frida |
| User-Agent string | `Argos/2042300(phone-v2; Android 13; Scale/2.75)` | Constructed from app version code, Android version, and display density scale |
| Baseband and kernel | `Build.getRadioVersion()`, kernel timestamp | `adb shell getprop gsm.version.baseband`, `/proc/version` timestamp |
| pureJsSignal hashes | `ua_hash`, `pkgHashCode`, `uaHashCode` | The `ua_hash` (CSS colour hash) can be computed synthetically from a lookup table indexed by `(android_version, dark_mode, chrome_webview_major)` --- 33 of the 38 CSS system colour values are identical across all tested versions, with variation concentrated in `Highlight` (Android's Holo Blue vs Material You accent) and a handful of deprecated-colour remappings. The canvas hashes (`pkgHashCode`, `uaHashCode`) depend on GPU rendering and cannot be predicted, but the per-build polymorphism of the `fillText` strings means the server cannot maintain a static lookup of expected per-device hashes. |

**Revised constraint:** The `ua_hash` CSS colour fingerprint is synthetically generable from a small lookup table. Canvas hashes remain GPU-dependent but the server's ability to validate them exactly is limited by the per-serve polymorphism of the challenge JS `fillText` strings. Captured values from any real device of the same GPU family are sufficient.

---

## Detection Vectors

Akamai's server-side validation can detect a stale or misconfigured generator through six primary vectors. Each vector targets a different layer of the change model.

### 1. Internal Consistency

The sensor contains dozens of cross-referencing fields. The `Build.MODEL` in `-100` must be consistent with the GPU renderer string, the WebView User-Agent, the screen dimensions, and the pureJsSignal hashes. A generator that claims to be a Pixel 8 but submits Pixel 4a canvas hashes is internally inconsistent. The CRC triplet in `-100` (particularly `crc1`, the ASCII ordinal checksum) will also fail if field values change without recomputing the checksums.

### 2. Known Device Databases

Akamai maintains databases of valid device configurations. A `Build.MODEL` of `"Pixel 4a"` paired with `Build.DEVICE` of `"shiba"` (which belongs to the Pixel 8) does not exist in any real Android build. Similarly, a `Build.FINGERPRINT` that does not match the format `google/{device}/{device}:{version}/{build_id}/...` for the claimed manufacturer will be flagged.

### 3. Canvas Stability

The three pureJsSignal hashes are deterministic for a given device, WebView version, and OS version. Akamai can maintain a lookup table mapping device configurations to expected hash ranges. A sensor from a "Pixel 4a, Android 13, Chrome/149 WebView" that submits canvas hashes outside the known range for that configuration is flagged. Conversely, hashes that exactly match a different device configuration reveal that the generator is using mismatched profile data.

### 4. Temporal Plausibility

The `sensor_hash` value (`s5-0.5-10252351`) is a compile-time constant baked into the Java SDK at Akamai's build time (confirmed via Ghidra analysis --- the value is not present anywhere in `libakamaibmp.so` and is passed from Java to `buildN` as part of the pre-assembled `-100` field). If Akamai updates the SDK, the new build will embed a different `sensor_hash`, and any sensor still submitting the old value is provably running outdated code. Similarly, the `SDK_VERSION` string is validated against the server's knowledge of which SDK versions are currently deployed in production apps.

### 5. Attestation Validity

The `$$$` attestation blob is session-bound and time-limited. A blob captured weeks ago may still pass validation (our testing showed extended validity windows), but it will eventually expire. More importantly, if Akamai migrates the attestation mechanism --- from SafetyNet to Play Integrity, or from a simple challenge-response to a bound key attestation --- old blobs will fail structurally, not just temporally.

### 6. Rate and Volume

This is not strictly a staleness vector, but it interacts with all the others. A generator submitting sensors at 1 request per second from a single IP will exhaust the IP trust budget faster than a real user browsing naturally. When combined with any of the above staleness signals, elevated rate accelerates detection. A stale `sensor_hash` at 1 request per minute might survive for hours; the same stale value at 10 requests per second will trigger a block within minutes.

---

## 7-Step Maintenance Checklist

When a new version of the target app is released, or when generated sensors begin receiving unexpected 403 or 400 responses, run through this checklist in order. Each step is designed to identify or rule out a specific category of breakage.

### Step 1: Capture a Fresh Real Sensor via Frida

Connect Frida to the updated app on a physical device and capture a complete sensor submission. Hook `u7f.setSignal()` for the JS signal, `buildN()` for the plaintext, and the final `x-acf-sensor-data` header for the encrypted envelope. Diff every field of the new plaintext against the current generator output, position by position. Any field that differs identifies a change that needs investigation.

```bash
frida -U -f com.homeretailgroup.argos.android -l frida/capture-signal.js
```

This is the single most informative maintenance action. A field-by-field diff between a real sensor and a generated sensor will reveal every discrepancy in a single pass.

### Step 2: Check SDK Version

Compare the `sdkVersion()` output from the Frida capture against the hardcoded value in `DeviceProfile`. If it has changed (e.g. from `4.0.4` to `4.1.0`), update the generator and investigate whether the version bump includes structural changes (new fields, changed field order, new encryption parameters).

```bash
# In the Frida capture output, look for:
# sdkVersion() -> "4.0.4"
# If the value differs, update DeviceProfile.sdk_version
```

### Step 3: Check RSA Key

Decompile the new APK and search for the RSA public key in the `com.cyberfend.cyfsecurity` namespace. Compare the PEM-encoded key against the one hardcoded in `CryptoContext`. An RSA key change is catastrophic --- every sensor encrypted with the old key will fail Tier 1 validation immediately.

```bash
# Extract and decompile APK
jadx -d output/ argos-new.apk
# Search for RSA key material
grep -r "MIGfMA0GCSqGSIb3" output/sources/com/cyberfend/
```

### Step 4: Check Device Attestation Freshness

If sensors are being rejected despite correct field values and valid encryption, the attestation blob may have expired. Recapture it from a fresh SDK initialisation session on the physical device. Hook the `$$$` suffix assembly point and extract the new blob.

```bash
# Hook the attestation capture point
frida -U -f com.homeretailgroup.argos.android -l frida/capture-attestation.js
```

Note the attestation blob format: if its length or encoding has changed (e.g. from URL-encoded binary to base64, or from 254 bytes to a different length), the attestation mechanism itself has been updated and deeper investigation is required.

### Step 5: Check Challenge JS Structure

Fetch a fresh copy of `/_sec/sdk_challenge.js` from the live server. While per-serve polymorphism changes variable names and integrity seeds, structural changes --- new case handlers in the dispatch table, additional fingerprint computations, new bridge methods --- indicate a significant update to the challenge JS. Compare the file size, the number of case handlers, and the pureJsSignal field layout against the documented baseline.

```bash
# Fetch live challenge JS
curl -s "https://api.argos.co.uk/_sec/sdk_challenge.js" -o challenge-new.js
wc -c challenge-new.js
# Compare size against baseline (~54-58KB for mobile-only, ~521KB for combined)
```

If the pureJsSignal format has changed (e.g. additional hash fields, different delimiter, new positional layout), the signal assembly in `build_payload()` must be updated to match.

### Step 6: Check Field -100 Format

The `-100` device fingerprint field is the most complex single field in the sensor. It contains hardware identifiers, build metadata, the `sensor_hash`, and three CRC values. Changes to any sub-field --- a new probe value, a reordered component, an additional comma-separated entry --- will cascade into CRC mismatches.

Diff the `-100` field from the fresh Frida capture against the generator's output character by character. Pay particular attention to:

- The `sensor_hash` component (e.g. `s5-0.5-10252351`). If this has changed, the native code has been updated.
- The number and position of `-1` sentinel values. New probe results replacing `-1` placeholders indicate that the SDK is now collecting additional device data.
- The CRC triplet at the end. If the CRC computation algorithm has changed (not just the input values), the `build_payload()` CRC logic must be updated.

### Step 7: Check pureJsSignal Format

Compare the pureJsSignal substring from the fresh capture against the expected format: `8,{locale},{height},{width},{ua_hash},,0,{pkgHashCode},{uaHashCode}`. If additional fields have been appended, if the leading `8` version indicator has changed, or if the delimiter pattern has been modified, the signal assembly must be updated.

If the pureJsSignal hash values themselves have changed for the same device (same Pixel 4a, same WebView version, same OS), it indicates that Akamai has modified the fingerprinting algorithms --- the canvas drawing pipeline, the CSS colour probe list, or the hash function. This is the most severe category of change and requires a full re-analysis of the challenge JS using the differential testing methodology documented in [Phases 7--9](../part2-methodology/10-differential-testing.md).

---

## Maintenance Triage Decision Tree

Not every 403 response indicates a version change. Before running the full checklist, triage the failure:

1. **Single 403 after many 200s** --- likely an IP trust budget issue or rate limiting. Reduce request frequency and retry. Not a version problem.
2. **All requests returning 403 from a new IP** --- likely a Tier 0 issue (TLS fingerprint, IP reputation). Verify the TLS profile and try a residential IP. Not a version problem.
3. **All requests returning 400** --- likely a Tier 1 structural failure. The RSA key may have changed, or the envelope format has been modified. Start at Step 3 (RSA key check).
4. **Intermittent 403s with degrading success rate** --- likely a Tier 2 field-level issue. A stale `sensor_hash`, expired attestation, or drifted CRC computation. Start at Step 1 (fresh capture and diff).
5. **Immediate 403 on every request from any IP** --- likely a fundamental change: new SDK version, new field format, or new encryption parameters. Run the full checklist from Step 1.

---

## Long-Term Resilience Strategy

Three practices reduce the maintenance burden over time:

**Automated monitoring.** A scheduled job that submits a single generated sensor every few hours and alerts on non-200 responses provides early warning of server-side changes. The sooner a breakage is detected, the less traffic is wasted against a blocking rule.

**APK version tracking.** Monitor the Google Play Store for new releases of the target app. When a new version appears, download it immediately, decompile it, and diff the `com.cyberfend.cyfsecurity` namespace against the previous version. Most SDK updates are embedded silently in routine app releases.

**Frida capture archival.** Every time a fresh sensor is captured from a real device, archive the full plaintext alongside the app version, SDK version, and capture timestamp. This archive becomes the ground truth for diffing when future changes occur. A library of captures across multiple SDK versions reveals patterns in how Akamai evolves the sensor format --- which fields are added, which are deprecated, and which remain stable across generations.
