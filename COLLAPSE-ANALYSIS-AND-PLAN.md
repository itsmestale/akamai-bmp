# Collapsed-Response Root-Cause Analysis & Plan

> ## ✅✅✅ LIKELY REAL FLAW (2026-06-26) — our sensor carries `-90`; real
> availability sensors DON'T
> Restored the Frida-17 Java bridge (it was removed from the runtime — fix:
> `npx frida-compile agent.js` where agent does `import Java from "frida-java-bridge"`;
> bundle is in `x-new/node_modules`). Hooked `SensorDataBuilder.buildN` at the Java
> level and dumped the decrypted field pairs. **25 real sensors (launch, search,
> product/availability) — ZERO carry `-90`.** `-90` (the WebView-challenge
> pureJsSignal) appears ONLY during web-challenge actions (login/checkout); the
> 3-week capture had it only because it was a CHECKOUT flow. **Our generator emitted
> `-90` on EVERY sensor with a HARDCODED pureJsSignal** (we can't run a real
> WebView challenge). On the monitor's availability requests that's a challenge-proof
> field a real request never carries AND can't be genuine → the structural tell deep
> validation rejects (bimodal: caught cold, slips warm). **Fix: removed `-90` from
> `build_payload`** → availability payload = 27 input fields (no `-90`) + native
> `-164`/`-170` = 29; 3-part envelope. Confirming via the paired harness.
> Lower-priority diffs also found: `-163` init_ts (ours = session start vs real
> ~3-day-old install time — looks like a fresh install every request); `-112` perf
> magnitude (real launch tiny vs ours large); `-120` biometric trace length.
> Capture tooling: scratchpad `frida_run_pairs.py` + compiled `buildn_compiled.js`.

> ## ✅✅ FLAW FOUND & FIXED (2026-06-26) — the `$$$` suffix (envelope part-count)
> Live Frida capture of the CURRENT app (Argos 5.26.0 on the Pixel 4a) showed the
> real sensor is **exactly 3 `$`-parts**: `6,a,{RSA}${payload}${timing}` — it ENDS
> at the timing. **Our generator appended `$$${serverSideSignal}` → 6 parts.** The
> 3-week-old capture is ALSO 3 parts — I'd matched the decrypted *payload fields*
> (`bmp-inputs.jsonl`) but never compared the **envelope**, so I missed it. The
> whole "$$$ suffix" premise (DeviceProfile.device_attestation, the
> `fetch_server_signal` "used as BOTH -90 and $$$ suffix" comment) was WRONG:
> serverSideSignal goes ONLY in the `-90` field inside the ENCRYPTED payload, never
> as a suffix. Fix: `generate_full_sensor` returns `generate_sensor(...)` with no
> suffix (bmp_generator.py). Deployed sidecar verified at 3 parts. Re-running the
> paired roolink-vs-bmpapi harness to confirm the collapse drops to ~0%.
> Fits the bimodal failure exactly: a 6-part envelope is a structural anomaly deep
> validation rejects on low-trust IPs but parses leniently on high-trust ones.
> Capture tooling: `stock-monitor/tools/` + my spawn script in scratchpad
> (`frida_capture_spawn.py`) — spawn Argos under a buildN hook; attach fails to
> trigger.

> ## 🧪 CLEAN-ROOM TEST (2026-06-26) — supersedes all live-monitor numbers below
> **Every cold-start number measured on the live monitor today is CONTAMINATED** —
> my `-164`/`-170` 100%-collapse bug, 3 monitor restarts, and the roolink spiral all
> corrupted the proxy/session state. So "90% cold-start", "it's IP-trust", "it's
> TLS", "roolink cold-starts too" are NOT reliable.
>
> Built an isolated harness `arget/cmd/argos-sensor-test` that mirrors the monitor
> exactly — bmpapi backend, the monitor's clustered gateway request, 24h/unlimited
> sensor reuse (runtime_config), fresh **rootproxies** residential sticky sessions
> (`MintFreshResidentialURL`, new exit IP per iteration), sensor minted through the
> same IP — but runs **OFF the live monitor** (one-off `golang:1.26-alpine`
> container on `arget_default`, reaching `bmp-api:8787`; monitor stays stopped). It
> prints collapse-by-`sensor_use` on genuinely fresh exit IPs.
>
> **★ PAIRED RESULT — DECISIVE (this is the answer): it's OUR SENSOR, not the
> proxies, not the TLS.** The harness was upgraded to a PAIRED design: for each
> fresh sticky session (one exit IP) it runs bmpapi-android, bmpapi-ios AND
> roolink over the SAME IP. Result (3/3 IPs so far, confirming at 15):
> ```
> exit IP          bmpapi-android  bmpapi-ios  roolink-ios
> 37.152.238.18      100%            100%         0%
> 86.155.26.166      100%            100%         0%
> 217.142.21.222     100%            100%         0%
> ```
> On the IDENTICAL residential IP, **roolink collapses 0%, our bmpapi sensor
> collapses 100%** (both TLS profiles). So: NOT proxy quality (roolink passes the
> very IPs ours fails), NOT TLS (android==ios). The earlier unpaired "bimodal
> per-IP / ~40% collapse" was me mis-reading IP-trust variance: **our sensor has a
> latent content/structure flaw Akamai catches on lower-trust IPs (harder
> scrutiny) but that slips on higher-trust ones; roolink's sensor is clean so it
> passes everywhere.** The generator is NOT done — there's still a real sensor diff
> vs roolink. NEXT: capture a fresh roolink (iOS) sensor + decrypt/compare to ours,
> OR (since our Android sensor was diffed against the real Android app already)
> re-capture a CURRENT real Android app sensor and re-diff — our 5.26.0 capture may
> be stale, or the remaining flaw is in a field I judged a "non-bug".
>
> Earlier unpaired single-arm runs (Android 39% / iOS 57%, "it's proxy quality")
> are SUPERSEDED — they had no roolink control and mis-attributed the sensor flaw
> to the IPs. **This harness is the authoritative measurement** — trust it over
> everything below. Run on the VPS via:
> `docker run --rm --network arget_default -v /opt/arget:/src -w /src -v argos-gocache:/go -e BMP_API_URL=http://bmp-api:8787 -e RESIDENTIAL_PROXY_TEMPLATE='pro.rootproxies.com:7777:customer-RP_OJO6JH9JYB-cc-GB-sessid-template:ET6WMoc4n5PV' -e TLS_PROFILE=okhttp4_android_13 -e ITERATIONS=15 -e CALLS=10 golang:1.26-alpine sh -c 'go run ./cmd/argos-sensor-test'`

> ## ✅ RESOLUTION (2026-06-26) — content bugs found & fixed in `bmp_generator.py`
> Field-by-field diff of our payload vs the real app (`full-success-checkout`, 23
> real sensors) found our content diverged on exactly the fields Akamai
> deep-validates on a NEW session — which is why **uses=1 collapsed but uses≥5
> (trusted, shallow-validated) didn't.** Fixes applied & verified (regenerated
> first sensor now matches the real app field-for-field):
> 1. **`-164`/`-170` KEPT — do NOT remove.** The `buildn_INPUT` capture shows 28
>    fields ending `-172`, BUT the native serializer appends `-164` (security patch)
>    + `-170` (MT set 2) to the final plaintext → **30 fields**. I removed them
>    based on the input → **100% collapse across all IPs/uses** → reverted. The
>    "added by buildN native code" comment was correct. Final sensor = 30 fields.
> 2. **`-90` reordered** to `startTime#screenHeight#cpuABI#serverSideSignal#
>    pureJsSignal#mapping_flag`, **`screenWidth`→`cpuABI=arm64-v8a`** (we emitted a
>    key the app never does and omitted one it always does).
> 3. **`-120`** launch sensor now carries the **biometric `ClassNotFoundException`
>    trace, byte-exact (465 B)**; was empty — the single biggest uses=1 tell.
> 4. **`-103`** launch lifecycle now **8 events `2,3×4`** spanning ~4 s; was a thin
>    2-event `3,2`.
> 5. **`-100`** digit after `android_version` `0`→`1`; **`-115`** timer (53000,
>    session-stable), interval (16000 launch), c5 range aligned to capture;
>    **`-163`** `init_ts==sdk_init_ts`.
>
> Non-bugs confirmed equal: pjs hashes, `-166` installed-apps fingerprint, `-104`,
> `-165`, `abis`, refresh_rate. Web-cookie path (C1) stays OUT — app is cookieless.
>
> **Lesson:** `buildn_INPUT` ≠ final plaintext. The native serializer appends
> `-164`/`-170`; trust the 30-field output, not the 28-field input. Fixes 2–5
> (the input fields 0..27) are correct and verified against the real input.
> **Status: DEPLOYED. Content correct — but content is NOT the cold-start cause.**
> Post-fix per-IP data is decisive: **established IPs sit at 1–4% collapse, warm
> sessions (uses≥4) at 0%, but the first request on every fresh proxy IP collapses
> ~90%** — same sensor bytes, 90%@use1 → 0%@use4. The cold-start is **session/IP
> TRUST building**, not sensor content. The real app passes cold via a trusted
> home IP; our fresh rotating proxies pay the tax each rotation. (The transient
> 36.8% overall is the post-restart storm + ~210 requests I burned with the
> -164/-170 mistake; established-IP rate ≈ old ~13% baseline.)
>
> **UPDATE 2 — TLS hypothesis REFUTED; it IS the proxies/IP-trust (as first
> concluded, and as the user predicted).** The first roolink read (298 req, 1 IP,
> 0%) was a misleading WARM window — rate-limiting made roolink settle on ONE IP
> and reuse one sensor (uses 34–42). The fuller measurement (461 req across **20
> IPs**) shows roolink ALSO cold-starts: **uses=1 = 100% (5/5), uses=2 = 85%
> (22/26)** — same as bmpapi (90%/82%). Roolink runs MATCHING iOS TLS and still
> collapses cold → TLS/platform is NOT the differentiator. (Two hypotheses I
> jumped to on partial data — removing -164/-170, then TLS — both wrong; the
> fuller measurement was needed each time.)
>
> **Confirmed cause: cold-start = IP/session TRUST building on fresh proxy IPs,
> identical for EVERY sensor backend. The real app avoids it via a trusted home
> IP; our rotating proxies pay the tax each rotation.** Sensor content + TLS are
> NOT the cause (both backends cold-start ~the same). Content fixes were correct
> hygiene but irrelevant to the cold-start.
>
> **Real levers (proxy, not sensor):**
> - `proxy_degradation_threshold=3` + `cooldown=30m`: 3 cold-start collapses cool a
>   proxy 30m → forces rotation to a fresh IP → which cold-starts again
>   (death-spiral). **Tuning this is likely highest-impact.**
> - Longer IP retention / fewer rotations → amortize the per-IP cold-start tax.
> - Deeper warm-up before the first poll; higher-trust ISP proxies.


**Status:** open. Monitor on bmp-api (Android `6,a`) still gets ~10–13% collapsed
(`returned=0` / "0000" placeholder) availability responses. RooLink (iOS `4,i`)
does not.

**Warm-up result (key clue):** priming `ak_bmsc` via bmp-api **partially** worked
— it dropped uses 2–3 but **NOT uses=1**:

| sensor_uses | before warm-up | after warm-up |
|-------------|----------------|----------------|
| uses=1 | 43% | **77%** (n=13) ← still bad |
| uses=2 | 47% | 16% ← dropped |
| uses=3 | 19% | 9% ← dropped |
| uses≥5 | 0% | 0% |
| overall | 13.4% | 10.4% |

So `ak_bmsc` trust priming **does** help (uses 2–3), but the **very first request
of a fresh session still collapses ~77%**. Either (a) the cookie isn't on the
wire for request #1 (wiring/timing bug — check first), or (b) request #1 needs
the web-challenge trust (`_abck`) that `ak_bmsc` cannot provide. This is now the
sharpest lever.

---

## 1. The phenomenon (proven via Elasticsearch `arget-requests-*`)

- ~13% of monitor availability polls collapse to `returned=0` (a real "0000"
  placeholder = false out-of-stock).
- **Concentrated in the first ~3 uses of each fresh session:**
  `uses=1: 43%`, `uses=2: 47%`, `uses=3: 19%`, → **~0% by `uses≥5`.**
- **Uniform across 30+ exit IPs** (~4% each) → it is the **sensor/session**, not
  proxy quality. (A bad proxy would spike on specific IPs.)
- **Not staleness:** fresh sensors (`sensor_age_ms≈0`) collapse at 13%.
- **Warm-up (`ak_bmsc` primed by bmp-api through the proxy) did not fix it.**

### The pivotal inference
The reused sensor is **byte-identical** from use 1 → use 5, yet collapse goes
43% → 0%. So the variable is **server-side session/trust state**, not the sensor
bytes. Two models explain this:

- **Model A — session trust cold-start.** A fresh IP/session must accrue trust
  over ~5 requests; our content is fine (works warm); RooLink skips the cold
  start via its `_abck`/`bm_sz` web cookies (instant trust).
- **Model B — new-session deep-validation window.** Akamai deep-validates the
  first few requests of a new session; our **sensor content fails** that deep
  check; after ~5 requests the session is "established" and validated shallowly,
  so flawed content passes. RooLink's content passes the deep check.

**Distinguishing A vs B is the crux of the plan.**

---

## 2. What is ruled out
- Proxy quality (uniform across IPs).
- Sensor staleness (fresh sensors collapse).
- `ak_bmsc` priming alone (warm-up didn't fix it → either not the warming factor,
  or our 2-round warm-up doesn't build enough trust).
- serverSideSignal being a "challenge to process": `get_params?type=sdk-dci`
  returns a freshly-minted token per call (`delay:0`), used raw, and the sensor
  works at `uses≥5` with it — so the token validates; it is not the gate.

---

## 3. Sensor structural comparison (ours vs RooLink, measured)

| field | RooLink | Ours |
|-------|---------|------|
| prefix | `4,i` (iOS, iPhone13/3) | `6,a` (Android, Pixel 4a) |
| RSA key blocks | 172 / 172 b64 (RSA-1024) | 172 / 172 — **identical** |
| payload | **4352** b64 | **2560** b64 (~40% smaller) |
| timing | `30,27,25` | `143,38,36` |
| `$$$` suffix | `AAQAAAAF…` serverSideSignal | `AAQAAAAF…` — same scheme |
| cookies returned | `_abck`, `bm_sz`, `ak_bmsc`, `akavpau…` | `ak_bmsc`, `akavpau…` (no web cookies) |

Same encryption envelope. Real differences: **platform**, **payload size**,
**timing**, and **web cookies**.

---

## 4. Candidate root causes (ranked)

### C1 — Web-challenge trust (`_abck`/`bm_sz`) — LEADING
RooLink solves Akamai's web JS challenge (`/_sec/cp_challenge/ak-challenge-3-2.htm`
— confirmed live, 5162 B) and ships `_abck` + `bm_sz`. Prior trust research
proved web cookies flip rejected→accepted (`ak_p …12_48_15` → `…51_220_15`).
Our **app-only** flow never gets `_abck`/`bm_sz`. This would give RooLink high
trust from request #1 (no cold start) while ours builds trust slowly. Explains
the cold-start pattern AND why `ak_bmsc`-only warming didn't help.

### C2 — Sensor content fails new-session deep validation (Model B)
Sub-candidates, in order:
- **C2a pureJsSignal hashes** — 3 are known-wrong (UA hash, pkgHashCode,
  uaHashCode), computed by the WebView challenge JS we don't execute. Listed in
  prior research as a deep-validation check ("must match a real WebView run").
- **C2b payload size** (2560 vs 4352) — ours may be missing behavioral content
  (touch/motion/lifecycle that a real app accumulates). NB: compare to the real
  **Android** app, not iOS RooLink.
- **C2c** CRC triplet / MT19937 / counter_large / timing subtleties.

### C3 — Platform (iOS vs Android)
Argos's Akamai config may validate Android (`6,a`) more strictly, or our specific
Android sensor has gaps. (Deliberate move to Android; still a variable.)

---

## 5. Plan — experiments to isolate, in order

**Exp 0 (sanity, cheap):** confirm the warm-up is actually end-to-end — does the
monitor's availability request truly carry `ak_bmsc`? Capture one live monitor
request's cookie header. If the cookie isn't on the wire, the "warm-up didn't
help" is a wiring bug, not a model result.

**Exp 1 (decisive A vs B, cheap):** capture `ak_p` (the `server-timing` header)
on collapsed vs expanded responses.
- collapse has `field7>0` (deep-validated) → **Model B**, content fails deep val.
- collapse has `field7=0` (not validated, just low trust) → **Model A**, trust.
Add `ak_p` to the log-shipper doc, or a standalone harness that polls and records
`server-timing` + `response_type`.

**Exp 2 (definitive content diff):** decrypt OUR sensor (we hold the AES key) and
compare field-by-field to the **real Android app** from the deep-capture
(`C:\Users\Luke\Documents\arget\captures\full-success-checkout\` —
`bmp-inputs.jsonl` / `bmp-events.jsonl` have the decrypted buildN field values;
the device is a Pixel 4a = same `6,a` platform as ours). Diff every field; the
deviations (payload size, pureJsSignal, CRCs, missing fields) are the content
bugs. This is the ground-truth "is our content wrong" test.

**Exp 3 (test the leading hypothesis C1):** obtain `_abck` (+`bm_sz`) via the
`/_sec/cp_challenge` web flow or a web-cookie service, inject alongside our
sensor on the monitor's requests. Collapses vanish → it's web-cookie trust
(matches RooLink's actual web+app hybrid). This is likely the real fix.

**Exp 4 (isolate serverSideSignal):** send a sensor with a GARBAGE
serverSideSignal vs our real one. Same collapse behavior → token not the gate;
worse with garbage → token validated and handling matters.

**Exp 5 (cheap mitigation test):** raise warm-up rounds 2 → 5–8 to fully build
IP trust on throwaway requests before polling. Collapses drop → Model A, just
needs more warming (and we can move warm-up rounds into config).

### Recommended order
0 → 1 → 5 (all cheap, quickly localize A vs B and whether more warming helps)
→ 2 (content ground truth) → 3 (web cookies, the probable real fix).

---

## 6. Key references / artifacts
- ES: `arget-requests-YYYY.MM.DD`, fields `response_type`
  (collapsed/expanded/empty), `sensor_uses`, `sensor_age_ms`, `proxy_exit_ip`,
  `device_id`. Query via `docker exec arget-elasticsearch-1 curl localhost:9200`.
- Real-app capture (Android, ground truth): `full-success-checkout/`.
- RooLink sample sensor: `arget/artifacts/availability-sensor-response.json`.
- Generator: `bmp-api/src/bmp_generator.py` (`fetch_server_signal`,
  `warm_session`, `generate_full_sensor`); server `sensor_server.py`.
- arget provider: `arget/argos/bmpapi_sensor.go`; reuse/warm logic
  `argos/sensor.go` (`nextSensor`, `PerRequestSensorProvider`).
- Web challenge endpoint: `https://api.argos.co.uk/_sec/cp_challenge/ak-challenge-3-2.htm`.
- Deployed: arget `8acced1`, bmp-api `9bf0871` (`itsmestale/bmp-api`). Monitor on
  bmp-api backend (DB `runtime_config: monitor.sensor_backend=bmpapi`), reuse.

## 7. Best current hypothesis — UPDATED (capture-confirmed)
**Sensor content (C2), NOT web cookies.** Verified against the real-app
`full-success-checkout` capture (82 requests incl. a successful checkout):
- the Argos app **never calls the web challenge** (no cp_challenge/sec-cpt/sbsd);
- it **sends ZERO cookies on all 82 requests** — the edge sets some, the app
  never sends them back; session tracking is the **sensor alone, server-side**.

Therefore:
- RooLink's `_abck`/`bm_sz` are RooLink's own web+app **crutch**, not the app's
  mechanism. **C1/Exp 3/Exp 4 are OUT — do NOT chase web Akamai.**
- Our warm-up `ak_bmsc` (which the real app never sends) only **partially** masked
  a deficiency (helped uses 2–3); it is not the real fix and is non-app-like.
- The real app's sensor passes **cookieless**; ours collapses ⇒ **our sensor
  content differs from the real app's**, and that difference is the root cause.

**Primary path = Exp 2** (decrypt OUR sensor — we hold the AES key — and diff it
field-by-field vs the real Android app). Prime suspects: the **pureJsSignal
hashes** (3 known-wrong, computed by the WebView challenge JS we don't run) and
the **payload-size gap**. Exp 0 (is `ak_bmsc` even on the uses=1 wire?) and Exp 1
(`ak_p field7` correlation) are quick supporting checks.
