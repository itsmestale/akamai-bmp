# Cookie Policy & TLS Fingerprint Reference

This page documents the precise cookie handling, TLS fingerprint requirements, and header ordering constraints that a synthetic client must satisfy to pass Akamai's pre-sensor network validation. These checks execute at **Tier 0** of the validation model -- before the sensor payload is even examined. Failing any of them produces an immediate 403, and the sensor generation work is wasted.

---

## Required Cookies

Two cookies must be present on every API request. Both are set by Akamai infrastructure during the initial session handshake and must be forwarded verbatim.

| Cookie | Set By | Purpose | Lifetime |
|--------|--------|---------|----------|
| `ak_bmsc` | Akamai Bot Manager | Session validation token. Confirms that the edge server accepted the most recent sensor submission and that the session is in good standing. Without this cookie, the server treats the request as an uninitialised client and returns 403. | Max-Age=7200 (2 hours). Reissued on each successful sensor submission with a refreshed expiry. |
| `akavpau_vpc_api_retail` | Akamai edge (VPC layer) | API retail session cookie. Carries a Unix timestamp TTL that controls how long the session remains valid. The edge server checks this timestamp on every request and reissues the cookie with a refreshed TTL on valid responses. | Short-lived, auto-renewed on each successful request. Expiry is encoded as a Unix timestamp suffix in the cookie value itself. |

Both cookies are `HttpOnly` (but not `Secure`). They are set via `Set-Cookie` response headers from Akamai's edge, not by JavaScript. Your HTTP client must have a cookie jar that captures and replays them automatically.

---

## Cookies to Strip

The following cookies are set by various Akamai and analytics subsystems during normal browser or app operation. They must be **stripped from outbound requests** to avoid detection. Forwarding them from a synthetic client signals that the client is replaying captured browser state rather than operating as a genuine mobile app, which does not carry browser analytics cookies.

| Cookie | Origin | Why Strip |
|--------|--------|-----------|
| `_abck` | Akamai web challenge | The primary web-side bot detection cookie. `tls_client` consumes this internally during challenge-solve flows, but it must never appear on forwarded API requests. A mobile app does not run the web challenge and would never possess this cookie. |
| `bm_sz` | Akamai Bot Manager | Browser session sizing cookie. Records viewport and window dimensions from the web challenge. Mobile API clients have no browser window. |
| `bm_sv` | Akamai Bot Manager | Server-side session validation cookie for the web path. Presence on a mobile API request is contradictory. |
| `analytics_channel` | Retailer analytics | Marketing channel attribution cookie. Irrelevant to API authentication and leaks the fact that a browser session exists. |
| `mdr_browser` | MDR (Measurement & Data Routing) | Browser detection cookie. Its presence on a mobile API request is a direct indicator of session blending. |
| `AMCV_*` | Adobe Marketing Cloud | Adobe visitor ID cookies (pattern `AMCV_{org_id}%40AdobeOrg`). Set by Adobe's JavaScript SDK. A native mobile app uses the Adobe Mobile SDK instead, which stores its visitor ID in shared preferences, not cookies. |
| `s_cc` | Adobe Analytics | Cookie-check flag set by Adobe's `s_code.js`. Confirms JavaScript cookie support. Meaningless for a mobile API client. |
| `s_sq` | Adobe Analytics | Click-tracking cookie recording the last link clicked. No mobile app equivalent. |

### Python Cookie Filter

The following utility strips unwanted cookies from a `tls_client` session before forwarding requests to the API. It preserves only the two required Akamai cookies and discards everything else.

```python
import re

# Cookies to keep -- everything else is stripped
KEEP_COOKIES = {"ak_bmsc", "akavpau_vpc_api_retail"}

# Patterns for wildcard stripping (e.g. AMCV_*)
STRIP_PATTERNS = [
    re.compile(r"^AMCV_"),
]

# Explicit names to strip
STRIP_NAMES = {
    "_abck", "bm_sz", "bm_sv",
    "analytics_channel", "mdr_browser",
    "s_cc", "s_sq",
}


def filter_cookies(session):
    """Remove all cookies except the two required Akamai session cookies.

    Call this after tls_client completes any challenge-solve flow and
    before forwarding requests to the target API.

    Args:
        session: A tls_client.Session instance with an active cookie jar.
    """
    to_remove = []

    for cookie in session.cookies:
        name = cookie.name

        # Keep if it is in the allowlist
        if name in KEEP_COOKIES:
            continue

        # Strip if it matches an explicit name or a wildcard pattern
        if name in STRIP_NAMES or any(p.match(name) for p in STRIP_PATTERNS):
            to_remove.append(name)
            continue

        # Strip anything not in the allowlist -- defence in depth
        to_remove.append(name)

    for name in to_remove:
        session.cookies.delete(name)
```

The allowlist approach (keep only what is needed, strip everything else) is safer than a blocklist. New analytics cookies appear regularly; an allowlist handles them automatically without code changes.

---

## TLS Fingerprint

Akamai's edge validates the TLS fingerprint of every inbound connection **before** inspecting cookies, headers, or sensor data. This is a Tier 0 check -- the cheapest possible filter, applied at the network layer.

### JA3 / JA4 Profile

The `okhttp4_android_13` TLS profile is required. This profile reproduces the exact JA3 fingerprint generated by OkHttp 4.x on Android 13, which is what the real Argos app uses for all HTTPS connections.

| Property | Requirement |
|----------|-------------|
| TLS client library | `tls_client` with `okhttp4_android_13` profile |
| JA3 match | Must match OkHttp 4.x on Android 13 exactly |
| JA4 match | Validated alongside JA3 on Akamai's edge |
| Cipher suite order | Determined by the profile -- do not override |
| TLS extensions | ALPN, SNI, and extension order set by the profile |

Using standard Python `requests`, `httpx`, or raw `curl` produces a completely different JA3 fingerprint and results in an **immediate 403** -- the request never reaches sensor validation. This is the single most common failure mode for new integrations.

```python
import tls_client

session = tls_client.Session(
    client_identifier="okhttp4_android_13",
    random_tls_extension_order=True,
)
```

The `random_tls_extension_order` parameter must be `True`. The `tls_client` library applies its own deterministic extension ordering for the selected profile; setting this to `True` enables that behaviour rather than falling back to the library's default order.

### HTTP/2 SETTINGS Frame

Beyond the TLS handshake, Akamai also fingerprints the HTTP/2 SETTINGS frame. This is a second pre-sensor check that validates:

- **INITIAL_WINDOW_SIZE** -- must match OkHttp's default value.
- **Frame ordering** -- the order of SETTINGS parameters (HEADER_TABLE_SIZE, ENABLE_PUSH, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, MAX_HEADER_LIST_SIZE) must follow OkHttp's emission order.
- **WINDOW_UPDATE value** -- the initial connection-level flow control window update must match.

The `okhttp4_android_13` profile in `tls_client` handles all of these automatically. If you are building a custom HTTP/2 client, you must match the exact SETTINGS frame that OkHttp 4.x emits, including parameter order and values.

---

## Header Ordering

Akamai validates not just the presence of required headers but their **order** in the HTTP request. The real Argos app, via OkHttp's interceptor chain, emits headers in a specific sequence. Deviating from this order causes intermittent blocks -- not consistent 403s, but elevated block rates that manifest as sporadic failures under load.

The required header order for API requests is:

1. **`x-acf-sensor-data`** -- must be the first header (after the pseudo-headers in HTTP/2). This is the sensor payload.
2. **`user-agent`** -- the Android app's user agent string.
3. **`content-type`** -- present only on POST requests (typically `application/json`).
4. **`accept-encoding`** -- compression support declaration (typically `gzip`).

```python
# Correct: sensor header first, then standard headers in order
headers = OrderedDict([
    ("x-acf-sensor-data", sensor_value),
    ("user-agent", "Argos/2042300(phone-v2; Android 13; Scale/2.75)"),
    ("content-type", "application/json"),
    ("accept-encoding", "gzip"),
])

response = session.post(url, headers=headers, data=payload)
```

Using a regular `dict` in Python 3.7+ preserves insertion order, but `OrderedDict` makes the intent explicit. The critical constraint is that `x-acf-sensor-data` must appear first. If `content-type` or `accept-encoding` appear before the sensor header, the block rate increases measurably.

---

## Validation Order Summary

The following table shows how these network-layer checks fit into Akamai's overall validation pipeline. All three checks documented on this page execute at Tier 0, before the sensor is decrypted or inspected.

| Check | Layer | Failure Mode | Cost to Akamai |
|-------|-------|-------------|----------------|
| JA3/JA4 TLS fingerprint | Tier 0 -- network | Immediate 403 | Near-zero (TLS termination layer) |
| HTTP/2 SETTINGS frame | Tier 0 -- network | Immediate 403 | Near-zero (HTTP/2 framing layer) |
| Header ordering | Tier 0 -- network | Intermittent blocks | Low (header inspection) |
| Cookie presence (`ak_bmsc`) | Tier 0 -- network | Immediate 403 | Low (cookie check) |
| Sensor decryption + HMAC | Tier 1 -- crypto | 400 or 403 | Moderate (RSA + AES + HMAC) |
| Field validation + CRC | Tier 2 -- content | 403 | Higher (field-by-field parsing) |
| Behavioural analysis | Tier 3 -- behavioural | Delayed blocking | Highest (statistical models) |

Getting Tier 0 right is non-negotiable. A perfectly valid sensor attached to a request with the wrong TLS fingerprint or missing cookies will be rejected before Akamai even looks at it.
