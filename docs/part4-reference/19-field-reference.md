# Complete Sensor Field Reference

The BMP sensor plaintext consists of 30 fields joined by the `-1,2,-94,` delimiter. This page documents every field: its position in the array, its field identifier, its contents, an example value, its stability characteristics across a session, and whether a generator can safely customise it for a different device profile.

Field order was established by diffing decrypted captures from the Argos Android app (v5.26.0, BMP SDK 4.0.4) on a Pixel 4a running Android 13. The order is stable across SDK versions within the 4.x line. The delimiter `-1,2,-94,` is a fixed separator, not a field identifier.

---

## Position 0 --- SDK Version

| Property | Value |
|----------|-------|
| **Field ID** | None (no numeric prefix) |
| **Contents** | The BMP SDK version string, emitted verbatim with no prefix or transformation. |
| **Example** | `4.0.4` |
| **Stability** | Static. Identical across all sensors in all sessions for a given SDK build. Changes only when the app ships a new SDK version. |
| **Customisable** | No. Must match the SDK version embedded in `libakamaibmp.so`. The server cross-references this against the expected version for the app package. |

The only field without a numeric identifier. The server uses it to select the parser for the remaining 29 fields. A mismatch causes Tier 1 rejection.

---

## Position 1 --- Challenge JS Signal

| Property | Value |
|----------|-------|
| **Field ID** | `-90` |
| **Contents** | The `pureJsSignal` string from the WebView challenge JavaScript. Hash-delimited key-value pairs containing `screenHeight`, `screenWidth`, `startTime`, `serverSideSignal`, three computed fingerprint hashes, and `mapping_flag`. |
| **Example** | `screenHeight=2138#screenWidth=1080#startTime=1780499228008#serverSideSignal=AAQAAAAF%2f%2f...#pureJsSignal=8,en-US,851,393,920a650b922995f6c26c190a3e10da6aee3557b9f7753de59d05b820311f5af5,,0,956038405,-1088156997#mapping_flag=1` |
| **Stability** | Session-stable. The `startTime`, `serverSideSignal`, and three fingerprint hashes are set once during SDK initialisation and reused verbatim in every sensor for the session. |
| **Customisable** | Partially. Screen dimensions can be adjusted. The three fingerprint hashes must be captured from a real device --- they depend on the browser engine's CSS and canvas rendering. |

This is the single largest field in the sensor, typically 599--662 characters. The server validates the three fingerprint hashes at Tier 2 by re-executing the same algorithms against the declared device properties. The `serverSideSignal` is a session-bound challenge token issued by the Akamai edge during `get_params` --- reusing it across sessions or devices triggers rejection.

The field names are deliberately misleading. `ua_hash` is a SHA-256 of 38 CSS `getComputedStyle` colour values, not a hash of the user agent. `pkgHashCode` is a Java `String.hashCode` of `canvas.toDataURL()` output, not a package name hash.

---

## Positions 2, 3, 4 --- Reserved

| Position | Field ID | Contents | Example | Stability | Customisable |
|----------|----------|----------|---------|-----------|-------------|
| 2 | `-70` | Empty | (empty after `-70,`) | Static | No |
| 3 | `-80` | Empty | (empty after `-80,`) | Static | No |
| 4 | `-121` | Empty | (empty after `-121,`) | Static | No |

Three reserved fields with no observed content in any BMP 4.0.4 capture. These appear to be structural placeholders maintaining field-count alignment with older or alternative SDK versions. All three must remain empty.

---

## Position 5 --- Device Fingerprint

| Property | Value |
|----------|-------|
| **Field ID** | `-100` |
| **Contents** | Comma-separated device identity and environment string. Screen dimensions, Android version, model, hardware IDs, build metadata, package name, Android ID, build fingerprint, `r_token`, and a CRC triplet. |
| **Example** | `-1,uaend,-1,2138,1080,1,100,1,en,13,0,Pixel%204a,s5-0.5-10252351,sunfish,-1,com.homeretailgroup.argos.android,-1,-1,a1b2c3d4e5f6a7b8,-1,0,1,REL,12655424,33,Google,sunfish,release-keys,user,android-build,TQ3A.230805.001.S2,sunfish,google,sunfish,google/sunfish/sunfish:13/TQ3A.230805.001.S2/12655424:user/release-keys,r-a1b2c3d4e5f6a1b2c3-xk9m,TQ3A.230805.001.S2,48291,-1847362951,891249603500` |
| **Stability** | Changes every call. The CRC triplet values are recomputed per sensor: `crc1` is an ASCII ordinal sum of the fingerprint body, `crc2` is a random signed 32-bit integer, and `crc3` is the current timestamp in milliseconds divided by two. All other sub-fields are device-stable. |
| **Customisable** | Yes, with care. Sub-fields must be internally consistent (Pixel 4a = `sunfish` for device/board/hardware/product, fingerprint must match build ID). The `sensor_hash` (`s5-0.5-10252351`) must match the SDK version. |

The server uses the CRC triplet for Tier 2 cross-validation: `crc1` is recomputed from the fingerprint body and a mismatch causes rejection. `crc2` appears not to be tightly validated. `crc3` is checked against the expected timestamp range. The field begins with the sentinel `-1,uaend,-1,` which marks the boundary between the (absent) user-agent hash prefix and the device metadata.

---

## Position 6 --- Sensor Capability Flags

| Property | Value |
|----------|-------|
| **Field ID** | `-101` |
| **Contents** | Three comma-separated flags: device orientation (`do_dis`/`do_en`), device motion (`dm_dis`/`dm_en`), touch events (`t_dis`/`t_en`). |
| **Example** | `do_dis,dm_dis,t_en` |
| **Stability** | Static. Determined at SDK initialisation by the device's sensor capabilities. Identical across all sensors in a session. |
| **Customisable** | Conditionally. Must match the device's sensor availability. Most Android phones report `do_dis,dm_dis,t_en`. |

When a channel is disabled, its corresponding telemetry fields (positions 13--20) must be empty. Claiming `do_en` but sending empty orientation data creates a detectable mismatch.

---

## Position 7 --- SDK State Code

| Property | Value |
|----------|-------|
| **Field ID** | `-102` |
| **Contents** | A single integer representing the SDK's internal state. Observed value is always `-1`, indicating the default/uninitialised state. |
| **Example** | `-1` |
| **Stability** | Static. Always `-1` in all captured sessions. |
| **Customisable** | No. Must be `-1`. |

A diagnostic value set by the native library during initialisation. Other values may exist for error conditions but none have been captured.

---

## Position 8 --- Activity Lifecycle Events

| Property | Value |
|----------|-------|
| **Field ID** | `-103` |
| **Contents** | Semicolon-separated lifecycle event records. Each record is a type code followed by a timestamp. Type `2` represents `onPause`; type `3` represents `onResume`. |
| **Example** (first sensor) | `3,1780499243008;2,1780499253008;` |
| **Example** (subsequent) | (empty string after `-103,`) |
| **Stability** | First sensor in a session contains lifecycle events recorded during app startup. Subsequent sensors emit this field empty. |
| **Customisable** | Yes. Timestamps must be plausible relative to `startTime`: `onResume` at `+10000--20000ms`, `onPause` at `+20000--25000ms`. |

The lifecycle events capture Android Activity `onResume`/`onPause` transitions during app startup. The server validates that timestamps fall within a plausible window relative to `startTime`. A sensor claiming lifecycle events 500ms after `startTime` is implausible --- the WebView challenge takes several seconds to execute.

---

## Position 9 --- CPU Architecture & SDK Constants

| Property | Value |
|----------|-------|
| **Field ID** | `-104` |
| **Contents** | A hardcoded SDK constant (`-2,3,-50,-301`) followed by the CPU architecture level read from `/proc/cpuinfo`. The Java SDK's `a8f.a()` method executes `cat /proc/cpuinfo`, searches for the line containing `"architecture"`, splits by `"architecture: "`, and extracts the value. The shell command and search strings are obfuscated via `CircleProgressBar.a()` XOR encoding (rolling key with seed 3). |
| **Example** | `-2,3,-50,-301,8` (where `8` = ARMv8 / AArch64) |
| **Stability** | Device-stable. The first four values are SDK constants baked into the Java layer (`zu5.p`), identical across all devices and sessions. Position 4 is determined by the device's CPU architecture: `8` for ARMv8/AArch64 (all modern Android phones since ~2015), `7` for older 32-bit ARMv7 devices. |
| **Customisable** | Yes. Position 4 should be `8` for all modern Android phones (ARMv8). Use `7` only for very old 32-bit-only devices. The first four values must remain `-2,3,-50,-301`. |

Despite earlier documentation labelling this field as "timezone data", it has no relationship to timezone, DST, or locale. The constant prefix `-2,3,-50,-301` is embedded in the obfuscated string `zu5.p` within the Java SDK. The fifth value is the integer from the `architecture:` line of `/proc/cpuinfo`, which reports the ARM instruction set architecture level.

---

## Position 10 --- Text Input Events

| Property | Value |
|----------|-------|
| **Field ID** | `-108` |
| **Contents** | Raw text input event data. Empty when no text input has occurred (typical for API-only sensor submissions). |
| **Example** | (empty string after `-108,`) |
| **Stability** | Dynamic. Populated when the user interacts with text fields. Empty in automated/initial sensors. |
| **Customisable** | Yes, but should remain empty for non-interactive sensor generation. Populating this field without corresponding touch events in the behavioural block creates an inconsistency. |

---

## Position 11 --- Performance Metrics

| Property | Value |
|----------|-------|
| **Field ID** | `-112` |
| **Contents** | Nine comma-separated integers: GC pause, class load time, thread init, native bridge latency, heap size, allocation delta, max heap, GC count, device uptime. |
| **Example** | `15,207,59,519,55000,558,21800,217,26987` |
| **Stability** | Session-stable. Generated once at SDK initialisation and reused verbatim in every sensor for the session. |
| **Customisable** | Yes, within realistic ranges. Pixel 4a observed: GC pause 12--20, class load 180--250, thread init 50--65, bridge latency 480--560, heap `{14700,21800,38000,55000}`, alloc delta 100--600, max heap `{10000,15000,21800}`, GC count 80--250, uptime 25000--40000. |

The server checks that these nine values remain identical across all sensors in a session. A generator that randomises them per sensor will be rejected.

---

## Position 12 --- Rolling Counters

| Property | Value |
|----------|-------|
| **Field ID** | `-115` |
| **Contents** | Seventeen comma-separated values: interaction counters, timer settings, a GF(2) polynomial-encoded counter, and a timestamp. |
| **Example** (first sensor) | `0,0,0,0,0,2847,0,0,0,0,47000,2000,-1,343440710233993963,1780499233008,1,0` |
| **Example** (subsequent) | `0,0,0,0,0,3,0,0,0,0,55000,0,-1,361885353063157,1780499238012,1,0` |
| **Stability** | Partially dynamic. Most values are zero. `c5` (pos 5): 100--3500 first, 1--10 subsequent. CLMUL counter (pos 13): deterministic function of `c5`. Timestamp (pos 14): current ms. |
| **Customisable** | Yes. The CLMUL counter is a pure deterministic function of `c5` --- no randomness or time dependency. |

The 17 values decode as follows:

| Sub-position | Observed Value | Description |
|-------------|---------------|-------------|
| 0--4 | `0` | Interaction counters (mouse, touch, keyboard, orientation, motion) --- all zero on non-interactive sensors |
| 5 | `100--3500` (first), `1--10` (subsequent) | Session interaction counter (`c5`) |
| 6--9 | `0` | Reserved counters |
| 10 | `47000` or `55000` or `30000` | Timer interval value |
| 11 | `2000` (first), `2000` or `0` (subsequent) | Reporting interval |
| 12 | `-1` | Sentinel |
| 13 | `10^14--10^17` | GF(2) polynomial multiplication of `c5`: `CLMUL(c5, 0x6DB60000DB6D) mod (x^64 + x^33 + x^1)`. Pure function of `c5` alone --- same `c5` always produces the same result across all sessions. Verified against all 47 captured pairs with 100% match. |
| 14 | Current timestamp | Millisecond epoch timestamp |
| 15 | `1` | Flag |
| 16 | `0` | Terminal zero |

---

## Positions 13--20 --- Behavioural Telemetry Block

These eight fields form a contiguous block reserved for real-time user interaction telemetry. In non-interactive sensor submissions (automated API calls, initial page loads), all eight are empty. They are populated only when the user physically interacts with the app --- tapping buttons, scrolling lists, typing text.

| Position | Field ID | Channel | Contents | Stability |
|----------|----------|---------|----------|-----------|
| 13 | `-117` | Touch | Touch event coordinate data | Dynamic |
| 14 | `-120` | Touch | Touch event timing data | Dynamic |
| 15 | `-144` | Orientation | Device orientation readings (alpha, beta, gamma) | Dynamic |
| 16 | `-160` | Orientation | Orientation event timing data | Dynamic |
| 17 | `-142` | Orientation | Additional orientation metadata | Dynamic |
| 18 | `-145` | Motion | Accelerometer and gyroscope readings | Dynamic |
| 19 | `-161` | Motion | Device motion event timing data | Dynamic |
| 20 | `-143` | Motion | Additional device motion metadata | Dynamic |

All eight fields are empty in non-interactive sensor submissions. They are populated only when the user physically interacts with the app. Each example value is an empty string after the field identifier (e.g., the plaintext contains `-117,` with nothing following the comma). All eight are customisable in principle but must be internally consistent if populated.

The eight fields group into three channels: touch (`-117`, `-120`), orientation (`-144`, `-160`, `-142`), and motion (`-145`, `-161`, `-143`). The capability flags in field `-101` declare which channels are active. When a channel is disabled, its fields must be empty. When enabled, the server expects plausible data: touch coordinates within screen bounds, orientation values in valid ranges (alpha 0--360, beta -180--180, gamma -90--90), and physically possible acceleration values.

For a generator that does not simulate user interaction, all eight fields should remain empty with capability flags set to `do_dis,dm_dis,t_en`. The `t_en` flag indicates touch capture is enabled but no events have been recorded --- matching a fresh app launch before the user has touched the screen.

---

## Position 21 --- Capture Control Flags

| Property | Value |
|----------|-------|
| **Field ID** | `-150` |
| **Contents** | Two comma-separated integers. The first indicates whether this is the first sensor in the session (`1`) or a subsequent one (`0`). The second is always `1`. |
| **Example** (first sensor) | `1,1` |
| **Example** (subsequent) | `0,1` |
| **Stability** | Semi-static. The first value changes from `1` to `0` after the initial sensor. The second value is always `1`. |
| **Customisable** | Yes. Must match whether this is the first sensor. Server cross-checks against `-103` and `-115`. |

Setting this to `1` on a sensor without lifecycle events in `-103`, or to `0` on one that contains them, creates a Tier 2 inconsistency.

---

## Position 22 --- App Identity

| Property | Value |
|----------|-------|
| **Field ID** | `-163` |
| **Contents** | Comma-separated values: a leading empty segment, the app's signing certificate SHA-1 hash, the app version string with version code, a zero flag, the internal SDK init timestamp, and the SDK init timestamp. |
| **Example** | `,6eb92aec7419cc1b0df0a13bb300ca72dd089f6b,5.26.0 2042300,0,1780499233013,1780499233008` |
| **Stability** | Session-stable. The `sig_sha1`, version, and timestamps are set once at SDK initialisation and reused in every sensor. |
| **Customisable** | Partially. `sig_sha1` must match the APK's certificate. Timestamps must satisfy `sdk_init_ts < init_ts` and be plausible relative to `startTime`. |

The `sig_sha1` is the strongest binding between the sensor and the app binary. Akamai maintains a mapping of package names to expected certificate hashes, so the wrong value causes Tier 2 rejection.

---

## Position 23 --- OS Info

| Property | Value |
|----------|-------|
| **Field ID** | `-165` |
| **Contents** | URL-encoded Android version string, locale code, two flags, and the device's local IP address. |
| **Example** | `Android%20REL%2013%20API%2033,enUS,0,-1,172.20.10.14` |
| **Stability** | Session-stable. The OS version, locale, and IP are set once and reused. The IP reflects the device's network interface address at the time of SDK initialisation. |
| **Customisable** | Yes. Android version, locale, and IP must match the device profile. |

The `REL` between `Android` and the version number is `Build.VERSION.CODENAME`, which reads `REL` on release builds. The `-1` in position 4 is a placeholder for a value not available in this SDK version.

---

## Position 24 --- Android Build Info

| Property | Value |
|----------|-------|
| **Field ID** | `-166` |
| **Contents** | Twenty `-1` sentinels followed by: build ID, baseband, ABI strings, kernel timestamp, security patch, refresh rate, boolean flags, app fingerprint hash, URL-encoded WebView UA. |
| **Example** | `-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,TQ3A.230805.001.S2,g7150-00112-230505-B-10075601,-1,armeabi-v7a#armeabi,armeabi-v7a#armeabi,1731578876000,0,2023-08-05,1.0,true,true,1.0,0,0,-1,-1,0,6cb2e9fe9eec45877b2daa76b36a124d8e91d4818389b0ea5493d652e171ab42,Mozilla%2F5.0%20(Linux%3B%20Android%2013%3B%20Pixel%204a%20Build%2FTQ3A.230805.001.S2%3B%20wv)%20AppleWebKit%2F537.36%20(KHTML%2C%20like%20Gecko)%20Version%2F4.0%20Chrome%2F149.0.7827.91%20Mobile%20Safari%2F537.36` |
| **Stability** | Device-stable. All values are determined by the device hardware and installed software. Identical across all sensors and sessions on the same device unless the system is updated. |
| **Customisable** | Yes. The app fingerprint hash can be generated synthetically from any plausible list of Android app package names. The URL-encoded UA must match the WebView's actual user agent. |

The 20 leading `-1` values are uniformly `-1` in all Pixel 4a / Argos 5.26.0 captures. Other apps or newer SDK versions may populate some positions with device probe results (battery level, charging state, accessibility services).

The hexadecimal hash near the end (labelled `ua_hash` in the SDK's internal naming, continuing Akamai's pattern of deliberate mislabelling) is **not** a hash of the user-agent string. It is computed entirely in the Java layer by `rl5.c()` → `xg8.b()`: the code calls `PackageManager.getInstalledApplications(0)`, filters to non-system apps (`(flags & 1) == 0`), joins the package names with `#`, and SHA-256 hashes the result. The `xg8.a` constant (decoded from `CircleProgressBar.a("JM^\"\x1f\x1c\x1a")`) is the string `"SHA-256"`. This value can be generated synthetically for any device profile without Frida capture.

---

## Position 25 --- API Endpoint

| Property | Value |
|----------|-------|
| **Field ID** | `-171` |
| **Contents** | The base URL of the API endpoint that the app is configured to protect. |
| **Example** | `https://api.argos.co.uk` |
| **Stability** | Static. Determined by the app's SDK configuration. Identical across all sensors and sessions. |
| **Customisable** | Yes, but must match the actual API endpoint the sensor is being submitted for. The server validates that this field matches the domain receiving the request. |

A sensor claiming one domain but submitted to a different Akamai-protected domain will be rejected.

---

## Position 26 --- Control Flag

| Property | Value |
|----------|-------|
| **Field ID** | `-240` |
| **Contents** | A single integer control flag. Observed value is always `0`. |
| **Example** | `0` |
| **Stability** | Static. Always `0` in all observed captures. |
| **Customisable** | No. Must be `0`. |

Purpose undetermined. May be a feature toggle or diagnostic indicator. Always `0` in BMP 4.0.4 captures.

---

## Position 27 --- MT19937 Simple Verification

| Property | Value |
|----------|-------|
| **Field ID** | `-172` |
| **Contents** | Four comma-separated integers, each produced by `MT19937.extract() % 4096`. The PRNG is seeded with the current millisecond timestamp. |
| **Example** | `3847,291,1024,3612` |
| **Stability** | Changes every call. A fresh MT19937 is instantiated per sensor generation, seeded from `Date.now()`. |
| **Customisable** | No. Must be mathematically correct MT19937 output for the declared seed. The server instantiates its own MT19937 with the same seed and verifies that the four values match. Fabricated or random values are rejected at Tier 2. |

The server seeds its own MT19937 identically and verifies the four values match. A generator with an incorrect Mersenne Twister implementation or different seeding strategy produces mathematically impossible output. Values are constrained to 0--4095 by the modulo operation. The seed is `int(time.time() * 1000) & 0xFFFFFFFF`.

---

## Position 28 --- Security Patch Date

| Property | Value |
|----------|-------|
| **Field ID** | `-164` |
| **Contents** | The Android security patch level date string, as reported by `Build.VERSION.SECURITY_PATCH`. Added by the native library during `buildN()`. |
| **Example** | `2023-08-05` |
| **Stability** | Device-stable. Changes only when a system security update is applied. |
| **Customisable** | Yes. Must match the device's actual security patch level. The server cross-references this against the build ID and Android version for plausibility. |

Appended by `libakamaibmp.so` rather than the Java SDK layer, which is why it appears near the end rather than with other build metadata in `-100` and `-166`.

---

## Position 29 --- MT19937 Cascade Verification

| Property | Value |
|----------|-------|
| **Field ID** | `-170` |
| **Contents** | Four comma-separated integers produced through a multiply-and-XOR cascade using MT19937 random values. |
| **Example** | `4823,-7291,8412,-3017` |
| **Stability** | Changes every call. A fresh MT19937 is instantiated per sensor, seeded from the current timestamp. |
| **Customisable** | No. Must be mathematically correct output from the cascade algorithm. |

The cascade draws four random values from `MT19937.rand_range(1, 1000)` and combines them through multiplications and XOR:

```
v1 = 7 * r1
v2 = (8 * r2) XOR v1
v3 = (9 * r3) XOR v2
v4 = (5 * r4) XOR v3
```

The multipliers `(7, 8, 9, 5)` are fixed constants in the native library. Each value is output as a signed 32-bit integer. The XOR chain means an error in any intermediate value propagates to all subsequent values.

Both `-172` and `-170` use the same timestamp as seed but instantiate separate MT19937 instances, so their outputs are independent.

---

## Session Stability Summary

The following table classifies every field by its stability characteristics. Understanding these categories is critical for building a generator that produces consistent multi-sensor sessions.

| Stability Class | Fields | Description |
|----------------|--------|-------------|
| **Immutable** | `-70`, `-80`, `-121`, `-108`, `-117`, `-144`, `-160`, `-142`, `-145`, `-161`, `-143`, `-240` | Always empty or constant zero. Never changes regardless of device, session, or call. |
| **Device-stable** | `-101`, `-102`, `-104` (CPU arch), `-165`, `-166`, `-171`, `-164`, SDK version | Determined by the device hardware and app configuration. Identical across sessions on the same device. Changes only with system updates or hardware changes. |
| **Session-stable** | `-90`, `-112`, `-163`, `-150` (after first), attestation blob | Set once at SDK initialisation. Identical across all sensors within a single session. Changes between sessions. |
| **Per-call dynamic** | `-100`, `-103`, `-115`, `-172`, `-170`, `-150` (first only) | Recomputed for every sensor generation due to timestamps, counters, CRC values, or PRNG state. Must show plausible progression across consecutive sensors in a session. |

---

## Device Attestation Suffix

After encryption and envelope construction, the final `x-acf-sensor-data` header appends a device attestation blob separated by a `$$$` triple-dollar delimiter:

```
6,a,{RSA_AES},{RSA_HMAC}${AES_CBC_PAYLOAD}${T1},{T2},{T3}$$${DEVICE_ATTESTATION}
```

The attestation blob is a URL-encoded SafetyNet or Play Integrity result, issued during the SDK initialisation handshake (stored in `pke.f`) and not independently generable.

| Property | Value |
|----------|-------|
| **Source** | `pke.f` field, populated during `get_params` handshake with Akamai edge |
| **Format** | URL-encoded binary blob, typically 250--260 characters |
| **Example** | `AAQAAAAF%2f%2f%2f%2f%2f5T2Xfw4vYUddOczYx%2foCt0mcLEw...%3d` |
| **Lifetime** | Session-bound. Valid for the duration of the SDK session. Stale blobs from previous sessions have been observed to continue passing for extended periods, but this is not guaranteed. |
| **Validation** | Tier 3. The server checks the attestation against its own record of the initialisation handshake. Missing or empty attestation is treated as a strong negative signal (common on emulators and rooted devices). |

The attestation blob is the one component a standalone generator cannot synthesise. On rooted devices or emulators, this field is typically empty, which Akamai treats as a significant risk factor. The same blob can be reused across sensor submissions within a session, but cross-session reuse is unreliable. Generators must periodically refresh it by running the real SDK on a physical device and capturing the value via Frida's `pke.f` hook.
