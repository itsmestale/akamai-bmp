'use strict';
/*
 * bmp-challenge-harness.js
 * ------------------------
 * Node.js trace harness for the Akamai BMP SDK challenge JS
 * (tools/sdk_challenge_latest.js).
 *
 * GOAL: run the obfuscated challenge VM under a mock JSBridge / WebView
 * environment and trace the device-data collection + signal computation,
 * capturing the final signal the script submits.
 *
 * ===========================================================================
 * HARD CONSTRAINT — DO NOT MODIFY THE SCRIPT SOURCE
 * ===========================================================================
 * The script is guarded by a MurmurHash3 checksum (`xg`) computed over its OWN
 * source text (the IIFE `dsXEzOjmVs.toString()`). The hash result feeds a
 * correction factor `X` baked into every XOR string-decode index. Any edit to
 * the source — even reformatting — changes the hash, breaks `X`, and makes all
 * property/method names decode to garbage (the VM then fails SILENTLY).
 * Likewise, overriding built-ins the hash path touches (String/Array/Math/
 * parseFloat/Number) on the global corrupts decoding. We therefore run the
 * source byte-for-byte and provide REAL built-ins, instrumenting only the host
 * objects the script reaches (JSBridge, document, webkit, window.setRes).
 *
 * ===========================================================================
 * RUNTIME CONTRACT (reverse-engineered from sdk_challenge_latest.js)
 * ===========================================================================
 * Init: Y() picks N = window (we make `window` the global). Q() computes X.
 *       Bg()/Sg() build constants. p6(G5) boots the orchestrator, which loads
 *       a webpack-style module whose factory runs inner-VM case Q5.
 *
 * Case Q5 (offset ~6700) does:
 *   - defines 7 module exports via webpack `__webpack_require__.d(exports,...)`:
 *       os, delimiter, getWeekStr,
 *       buildPostDataAndroid,   sendChallengeResponseAndroid,
 *       buildPostDataIos,       sendChallengeResponseIos
 *   - assigns  window.setRes = function(Xk){ ... }   (the data SINK)
 *       Xk is a STRING "key=value". It does:
 *         Dk[ Xk.split("=")[0] ] = Xk;
 *         if (--kk === 1) OG(Dk, jk);   // OG = case I5 = submit signal
 *   - calls H6()  (= getWeekStr / case qP): computes a timezone/week string
 *       via `new Date()` + `Intl.DateTimeFormat()`. (Intl MUST exist or the VM
 *       throws here and aborts.)
 *
 * Bridge selection (case wR, offset ~36401): if `window.webkit.messageHandlers`
 *   exists -> iOS path; else -> Android path (window.JSBridge).
 *
 * Data collection (case AP, offset ~37845) = export `buildPostDataAndroid`:
 *   sets kk = dD[orderIndex].length, then for each method posts its name via
 *     window.document.defaultView.JSBridge.postMessage(methodName)
 *   (guarded by `window.window.document &&`). The NATIVE side fetches each value
 *   and calls window.setRes("methodName=value"); when the counter is exhausted,
 *   the signal is built (SHA-256 over the concatenated values) and POSTed the
 *   same way (a long string, not a method name).
 *
 * ===========================================================================
 * IMPORTANT LIMITATION
 * ===========================================================================
 * `buildPostDataAndroid` / `sendChallengeResponseAndroid` are MODULE EXPORTS
 * (returned from the webpack require as `Td`). They are NOT attached to the
 * global, so on a real device the native SDK calls them on the object it gets
 * back from evaluating the script — they are unreachable from outside the IIFE.
 * Consequently the Android path does NOT self-start: loading the script just
 * assigns window.setRes and idles, waiting for native to call the export.
 *
 * The iOS path, by contrast, self-drives on load (H6() kicks off posting of the
 * iOS method list). So this harness DRIVES THE COMPUTATION by:
 *   (1) presenting the webkit message-handler so the script self-starts, AND
 *   (2) servicing the collection loop: each method the script posts is echoed
 *       back through window.setRes("name=value") with the Android device value,
 *   until the script posts the final signal string.
 *
 * This exercises the real VM (string decode, data assembly, SHA-256, signal
 * format) end-to-end and captures the signal. The collected VALUES are the
 * Android Pixel-4a profile below; the per-method NAMES the VM posts are decoded
 * by the VM itself and logged in the trace.
 *
 * Usage:
 *   node tools/bmp-challenge-harness.js
 *   node tools/bmp-challenge-harness.js --android   (no webkit; load + idle, for
 *                                                     observing the Android setup
 *                                                     without driving collection)
 *   node tools/bmp-challenge-harness.js --json       (emit machine-readable trace)
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const SCRIPT_PATH = path.join(__dirname, 'sdk_challenge_latest.js');
const ARGS = process.argv.slice(2);
const OPT = {
  android: ARGS.includes('--android'), // suppress webkit -> Android path (idles)
  // --drive-android: capture the webpack module exports (via an Object.defineProperty
  // trap) and actively invoke buildPostDataAndroid across candidate order keys so the
  // Android collection path runs instead of just idling. Implies --android.
  driveAndroid: ARGS.includes('--drive-android'),
  json: ARGS.includes('--json'),
};
if (OPT.driveAndroid) OPT.android = true;

// ---------------------------------------------------------------------------
// 1. Realistic Android device data (Pixel 4a / Argos app), per task spec.
//    Keyed by the BMP getter/method name. Includes common iOS aliases so the
//    echo-loop can answer whichever method-name set the VM decides to request.
// ---------------------------------------------------------------------------
const START_TIME = Date.now().toString();

const DEVICE = {
  // Android JSBridge method names
  appIdentifier: 'com.homeretailgroup.argos.android',
  model: 'Pixel 4a',
  carrierName: '-1',
  systemVersion: '12',
  hardWareType: 'sunfish',
  androidId: 'abc123def456',
  screenHeight: '851',
  screenWidth: '393',
  adbStatus: '0',
  isDebugEnabled: '0',
  buildId: 'SP2A.220505.008',
  cpuABI: 'arm64-v8a',
  deviceProperties: '{}',
  defaultBuildFingerPrintProperties: '{}',
  mountFileProperties: '{}',
  qemuProperties: '{}',
  sdkVersion: '3.3.0',
  startTime: START_TIME,
  host: 'abfarm-release', // Build.HOST, referenced by getServerSignals
};

// getServerSignals = "startTime,sdkVersion,androidId,buildId,systemVersion,model,host"
// (per knowledge/targets/akamai-bmp/crypto/sdk_challenge_analysis.md). Normally a
// URL-encoded base64 blob from the native side; we synthesize the documented
// concatenation so the VM has well-formed input to parse.
DEVICE.getServerSignals = [
  DEVICE.startTime, DEVICE.sdkVersion, DEVICE.androidId, DEVICE.buildId,
  DEVICE.systemVersion, DEVICE.model, DEVICE.host,
].join(',');

// iOS aliases (the VM posts these names when the webkit bridge is present). We
// answer them with the equivalent Android values so the computation completes.
const IOS_ALIASES = {
  deviceHardwareType: DEVICE.hardWareType,
  kernalOsRelease: '4.14.180-perf', // uname -r style
  cpuInfo: DEVICE.cpuABI,
  deviceModel: DEVICE.model,
  osVersion: DEVICE.systemVersion,
  bundleId: DEVICE.appIdentifier,
  systemName: 'Android',
};

const METHOD_NAMES = new Set([...Object.keys(DEVICE), ...Object.keys(IOS_ALIASES)]);

function valueForMethod(name) {
  if (Object.prototype.hasOwnProperty.call(DEVICE, name)) return DEVICE[name];
  if (Object.prototype.hasOwnProperty.call(IOS_ALIASES, name)) return IOS_ALIASES[name];
  return ''; // unknown method -> empty (matches native returning "")
}

// ---------------------------------------------------------------------------
// 2. Trace plumbing.
// ---------------------------------------------------------------------------
const trace = [];
let seq = 0;
function log(kind, msg, extra) {
  seq++;
  const line = { seq, kind, msg };
  if (extra !== undefined) line.extra = truncate(extra);
  trace.push(line);
  if (!OPT.json) {
    const prefix = `[${String(seq).padStart(3, '0')}] ${kind.padEnd(20)}`;
    console.log(extra !== undefined ? `${prefix} ${msg} => ${truncate(extra)}` : `${prefix} ${msg}`);
  }
}
function truncate(v) {
  const s = typeof v === 'string' ? v : (() => { try { return JSON.stringify(v); } catch (_) { return String(v); } })();
  if (s == null) return s;
  return s.length > 240 ? s.slice(0, 240) + `…(${s.length} chars)` : s;
}

// ---------------------------------------------------------------------------
// 3. State + collection-loop servicing.
// ---------------------------------------------------------------------------
let setResFn = null;           // window.setRes, assigned by the VM in Q5
let capturedSignal = null;     // the final signal string the VM posts
const postedMethods = [];      // method names the VM requested
let postSeq = 0;
let moduleExports = null;      // captured webpack exports (for --drive-android)

// Module export names defined by case Q5 via __webpack_require__.d(exports, ...).
// Spotting any of these being defined lets us grab the exports object so we can
// invoke buildPostDataAndroid directly (the native SDK's entry point).
const EXPORT_NAMES = new Set([
  'os', 'delimiter', 'getWeekStr',
  'buildPostDataAndroid', 'sendChallengeResponseAndroid',
  'buildPostDataIos', 'sendChallengeResponseIos',
]);

// Object proxy that captures the module exports object the first time one of the
// known export names is defined on it. Only `defineProperty` is intercepted; every
// other Object operation passes straight through, and `Object` is NOT part of the
// MurmurHash3 integrity path, so this does not affect string decoding.
const RealDefineProperty = Object.defineProperty;
const ObjectProxy = new Proxy(Object, {
  get(t, p) {
    if (p === 'defineProperty') {
      return function (obj, key, desc) {
        if (moduleExports == null && EXPORT_NAMES.has(String(key))) moduleExports = obj;
        return RealDefineProperty(obj, key, desc);
      };
    }
    return t[p];
  },
});

// A posted string is the FINAL SIGNAL (not a method name) if it is not a known
// method identifier and looks substantial (contains the delimiter, or is long /
// has a hex hash run). Method names are short pure-letter identifiers.
function isSignalString(s) {
  if (typeof s !== 'string') return false;
  if (METHOD_NAMES.has(s)) return false;
  if (/^[A-Za-z]+$/.test(s) && s.length < 26) return false; // looks like a method name
  return s.length >= 24 || s.indexOf('=') >= 0 || /[0-9a-f]{16,}/i.test(s);
}

function captureSignal(signal, via) {
  if (capturedSignal != null) return;
  capturedSignal = signal;
  log('SIGNAL', `*** captured via ${via} ***`, signal);
}

// Service the collection loop: echo a method's value back through setRes, as
// the native SDK would, on the next tick (async round-trip).
function echoToSetRes(methodName) {
  const value = valueForMethod(methodName);
  const msg = methodName + '=' + value;
  setImmediate(() => {
    if (typeof setResFn !== 'function') {
      log('NATIVE->JS', `drop "${methodName}=…" (setRes not assigned)`);
      return;
    }
    log('NATIVE->JS', `setRes("${methodName}=…")`, value);
    try { setResFn(msg); }
    catch (e) { log('ERROR', 'setRes threw', String((e && e.stack) || e)); }
  });
}

// Handle any postMessage the VM emits (from JSBridge or the webkit handler).
function handlePost(raw, channel) {
  postSeq++;
  const s = String(raw);
  if (isSignalString(s)) {
    captureSignal(s, `${channel}.postMessage`);
    return;
  }
  postedMethods.push(s);
  log('JS->NATIVE', `${channel}.postMessage("${s}") [collect method]`);
  echoToSetRes(s);
}

// ---------------------------------------------------------------------------
// 4. Mock JSBridge (Proxy-backed; never throws on an unmocked method, since a
//    throw aborts the VM silently). Classify calls by SHAPE:
//      - no-arg whose name is a device field  -> return device value (sync)
//      - postMessage(x)                        -> route to handlePost
//      - everything else                       -> log + no-op
// ---------------------------------------------------------------------------
const bridgeMethodHandler = {
  apply(target, thisArg, args) {
    const name = target.__bridgeName || '?';
    if (args.length === 0 && Object.prototype.hasOwnProperty.call(DEVICE, name)) {
      log('JSBridge.get', `${name}()`, DEVICE[name]);
      return DEVICE[name];
    }
    if (name === 'postMessage') {
      handlePost(args[0], 'JSBridge');
      return undefined;
    }
    if (args.length >= 1 && isSignalString(String(args[0]))) {
      captureSignal(String(args[0]), `JSBridge.${name}`);
      return undefined;
    }
    log('JSBridge.other', `${name}(${args.map(truncate).join(', ')})`);
    return undefined;
  },
};
function bridgeFn(name) {
  const fn = function () {};
  fn.__bridgeName = name;
  return new Proxy(fn, bridgeMethodHandler);
}

let WINDOW; // forward ref

// JSBridge.document: holds onmessage (in case a version uses it) and
// defaultView -> window (so the deep chain ...document.defaultView.JSBridge.*
// resolves back to our bridge).
const bridgeDocument = {
  _onmessage: null,
  get onmessage() { return this._onmessage; },
  set onmessage(fn) { log('bridge.doc.onmessage', 'assigned'); this._onmessage = fn; },
  get defaultView() { return WINDOW; },
  addEventListener() {},
  removeEventListener() {},
};

const JSBridge = new Proxy({}, {
  get(target, prop) {
    if (prop === 'document') return bridgeDocument;
    if (typeof prop === 'symbol') return undefined;
    const p = String(prop);
    if (p === 'then' || p === 'toString' || p === 'valueOf' || p === 'inspect') return undefined;
    if (!target[p]) target[p] = bridgeFn(p);
    return target[p];
  },
  set(target, prop, value) { target[String(prop)] = value; return true; },
  has() { return true; },
});

// ---------------------------------------------------------------------------
// 5. Page document (distinct from JSBridge.document). The Android collection
//    chain is window.document.defaultView.JSBridge.postMessage(...), so the page
//    document needs defaultView -> window and a <script> element with .src (the
//    VM reads document.getElementsByTagName('script')[...].src to find its own
//    URL / serverSideSignal param).
// ---------------------------------------------------------------------------
const SCRIPT_SRC = 'https://www.argos.co.uk/_sec/sdk_challenge.js';
const pageDocument = new Proxy({ _onmessage: null }, {
  get(t, p) {
    const k = String(p);
    if (k === 'defaultView') return WINDOW;
    if (k === 'getElementsByTagName') return () => [{ src: SCRIPT_SRC, getAttribute: () => SCRIPT_SRC }];
    if (k === 'querySelector' || k === 'querySelectorAll') return () => null;
    if (k === 'onmessage') return t._onmessage;
    if (k === 'cookie') return '';
    if (k === 'referrer' || k === 'title') return '';
    if (k === 'createElement') return () => ({ style: {}, setAttribute() {}, appendChild() {} });
    if (k === 'addEventListener' || k === 'removeEventListener') return () => {};
    if (typeof p === 'symbol') return undefined;
    if (!t[k]) t[k] = function () {};
    return t[k];
  },
  set(t, p, v) {
    if (String(p) === 'onmessage') t._onmessage = v; else t[String(p)] = v;
    return true;
  },
});

// ---------------------------------------------------------------------------
// 6. Build the sandbox global == window, hosting real built-ins + host objects.
// ---------------------------------------------------------------------------
function buildGlobal() {
  // REAL built-ins (overriding these would corrupt the integrity hash path).
  const base = {
    String, Array, Number, Math, JSON, parseInt, parseFloat, isNaN, isFinite,
    Date, RegExp, Object: OPT.driveAndroid ? ObjectProxy : Object,
    Function, Boolean, Symbol, Error, TypeError, RangeError,
    Promise, encodeURIComponent, decodeURIComponent,
    // Intl is REQUIRED (case qP / getWeekStr uses Intl.DateTimeFormat()).
    Intl,
    escape: typeof escape !== 'undefined' ? escape : (s) => s,
    unescape: typeof unescape !== 'undefined' ? unescape : (s) => s,
    atob: (b64) => Buffer.from(b64, 'base64').toString('binary'),
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    console,
    setTimeout, clearTimeout, setInterval, clearInterval,
  };

  base.navigator = {
    userAgent: 'Mozilla/5.0 (Linux; Android 12; Pixel 4a) AppleWebKit/537.36 ' +
      '(KHTML, like Gecko) Version/4.0 Chrome/146.0.0.0 Mobile Safari/537.36',
    platform: 'Linux armv8l', language: 'en-US', languages: ['en-US', 'en'],
    appName: 'Netscape', product: 'Gecko', vendor: 'Google Inc.', hardwareConcurrency: 8,
  };
  base.location = {
    href: SCRIPT_SRC, protocol: 'https:', host: 'www.argos.co.uk',
    hostname: 'www.argos.co.uk', pathname: '/_sec/sdk_challenge.js', search: '',
  };
  base.screen = {
    width: Number(DEVICE.screenWidth), height: Number(DEVICE.screenHeight),
    availWidth: Number(DEVICE.screenWidth), availHeight: Number(DEVICE.screenHeight),
    colorDepth: 24, pixelDepth: 24,
  };
  base.document = pageDocument;
  base.JSBridge = JSBridge;

  // webkit message-handler bridge (iOS). Present unless --android. Its presence
  // makes the VM take the self-starting iOS path; absence -> Android (idles).
  if (!OPT.android) {
    base.webkit = {
      messageHandlers: new Proxy({}, {
        get() { return { postMessage: (m) => handlePost(m, 'webkit') }; },
      }),
    };
  } else {
    base.webkit = undefined;
  }

  base.requestAnimationFrame = (cb) => setTimeout(() => cb(Date.now()), 16);
  base.cancelAnimationFrame = clearTimeout;
  base.addEventListener = () => {};
  base.removeEventListener = () => {};
  base.postMessage = (data) => handlePost(data, 'window');

  // The known global keys; anything the VM ASSIGNS beyond these is an "export"
  // surface (in practice only `setRes`), which we capture.
  const knownKeys = new Set(Object.keys(base).concat(
    ['window', 'self', 'globalThis', 'top', 'parent']));

  const G = new Proxy(base, {
    get(t, p) { return t[p]; },
    set(t, p, v) {
      const k = String(p);
      if (!knownKeys.has(k)) {
        log('window.set', `window.${k} = ${typeof v}`);
        if (k === 'setRes' && typeof v === 'function') setResFn = v;
      }
      t[k] = v;
      return true;
    },
    // `has` true so `typeof undefinedGlobal` yields "undefined" (no ReferenceError)
    // and bare global refs resolve to undefined rather than throwing.
    has() { return true; },
  });

  base.window = G; base.self = G; base.globalThis = G; base.top = G; base.parent = G;
  WINDOW = G;
  return G;
}

// ---------------------------------------------------------------------------
// 7. Run the (unmodified) challenge script, then drive + report.
// ---------------------------------------------------------------------------
function run() {
  const source = fs.readFileSync(SCRIPT_PATH, 'utf8');

  if (source.indexOf('0x38d466e') === -1) {
    console.error('FATAL: integrity marker 0x38d466e missing — wrong/edited file?');
    process.exit(1);
  }
  if (source.indexOf('dsXEzOjmVs') === -1) {
    console.error('FATAL: IIFE name dsXEzOjmVs missing — wrong/edited file?');
    process.exit(1);
  }

  const G = buildGlobal();
  const context = vm.createContext(G);

  if (!OPT.json) {
    console.log('='.repeat(72));
    console.log('BMP SDK Challenge Harness');
    console.log('  script   :', SCRIPT_PATH);
    console.log('  bytes    :', source.length);
    console.log('  startTime:', START_TIME);
    console.log('  path     :', OPT.driveAndroid ? 'ANDROID (drive via exports, order keys w1..w10)' :
        OPT.android ? 'ANDROID (no webkit; idles without --drive-android)' : 'iOS-bridge (self-driving)');
    console.log('='.repeat(72));
  }

  let runError = null;
  try {
    const script = new vm.Script(source, { filename: 'sdk_challenge_latest.js' });
    script.runInContext(context, { timeout: 15000 });
  } catch (e) {
    runError = e;
    log('ERROR', 'script execution threw', String((e && e.stack) || e));
  }

  log('PHASE', `load complete — window.setRes ${typeof setResFn === 'function' ? 'ASSIGNED' : 'NOT assigned'}, ` +
      `${postedMethods.length} method(s) posted during load`);

  // --drive-android: invoke the captured buildPostDataAndroid export to start the
  // Android collection path. AP runs only if its order index is a key in the dD
  // ordering table; we don't know the key statically, so we probe a range. The
  // first invocation that makes the VM post a method name (serviced by the echo
  // loop) wins; the rest are harmless no-ops.
  if (OPT.driveAndroid) {
    if (moduleExports == null) {
      log('PHASE', 'drive-android: module exports NOT captured (cannot invoke entry)');
    } else {
      let entry;
      try { entry = moduleExports.buildPostDataAndroid; } catch (_) { entry = null; }
      log('PHASE', `drive-android: exports=[${Object.keys(moduleExports).join(',')}], ` +
          `buildPostDataAndroid is ${typeof entry}`);
      if (typeof entry === 'function') {
        const before = postSeq;
        // dD/wk order-table keys are decoded strings: "w1" through "w54", plus
        // some "G"-prefixed variants. Each key selects a different subset of methods.
        // "w1" -> buildId, model, sdkVersion, androidId (4 fields).
        // Supply a specific key via BMP_ORDER_KEY env var, or we probe w1..w10.
        const candidates = [];
        if (process.env.BMP_ORDER_KEY) candidates.push(process.env.BMP_ORDER_KEY);
        for (let i = 1; i <= 10; i++) candidates.push('w' + i);
        for (const idx of candidates) {
          if (postSeq > before) break; // collection started
          try { entry.call(moduleExports, idx); } catch (_) { /* ignore bad index */ }
        }
        log('PHASE', `drive-android: probed ${candidates.length} order keys` +
            (process.env.BMP_ORDER_KEY ? ` (incl BMP_ORDER_KEY="${process.env.BMP_ORDER_KEY}")` : '') +
            `, posts triggered: ${postSeq - before}`);
      }
    }
  }

  // Let the async collection loop (postMessage -> setRes -> ... -> signal) settle.
  let idle = 0;
  (function settle() {
    setImmediate(() => {
      const before = postSeq;
      // small delay lets queued setImmediate echoes + their re-posts drain
      setTimeout(() => {
        if (capturedSignal != null) return finish(runError);
        if (postSeq === before) { idle++; } else { idle = 0; }
        if (idle > 6) return finish(runError);
        settle();
      }, 25);
    });
  })();
}

function finish(runError) {
  if (OPT.json) {
    process.stdout.write(JSON.stringify({
      startTime: START_TIME,
      path: OPT.android ? 'android' : 'ios-bridge',
      setResAssigned: typeof setResFn === 'function',
      methodsPosted: postedMethods,
      signal: capturedSignal,
      signalSha256: capturedSignal != null
        ? crypto.createHash('sha256').update(String(capturedSignal)).digest('hex') : null,
      runError: runError ? String(runError.message || runError) : null,
      trace,
    }, null, 2) + '\n');
    process.exit(capturedSignal != null ? 0 : 2);
    return;
  }

  console.log('\n' + '='.repeat(72));
  console.log('TRACE SUMMARY');
  console.log('='.repeat(72));

  const getters = trace.filter((t) => t.kind === 'JSBridge.get');
  console.log(`Synchronous JSBridge getters: ${getters.length}`);
  for (const g of getters) console.log('   ', g.msg, '=>', g.extra);

  console.log(`\nMethods the VM requested via postMessage: ${postedMethods.length}`);
  for (const m of postedMethods) console.log('    ' + m + '  => "' + truncate(valueForMethod(m)) + '"');

  const others = trace.filter((t) => t.kind === 'JSBridge.other');
  if (others.length) {
    console.log(`\nOther bridge calls: ${others.length}`);
    for (const o of others.slice(0, 25)) console.log('   ', o.msg);
  }

  console.log('\nwindow.setRes assigned:', typeof setResFn === 'function');
  if (capturedSignal != null) {
    console.log('\n*** CAPTURED SIGNAL ***');
    console.log(capturedSignal);
    console.log('\nsignal length :', String(capturedSignal).length);
    console.log('signal sha256 :', crypto.createHash('sha256').update(String(capturedSignal)).digest('hex'));
    verifyInternalSha(capturedSignal);
  } else {
    console.log('\n*** NO SIGNAL CAPTURED ***');
    if (OPT.android) {
      console.log('Android path idles by design: buildPostDataAndroid is a module export the');
      console.log('native SDK calls — it is not reachable from the global, so nothing drives');
      console.log('collection here. Run WITHOUT --android to drive via the self-starting bridge.');
    } else {
      console.log('The VM loaded and assigned window.setRes but no signal was posted. Check:');
      console.log('  - ERROR lines above (an unmocked global -> silent VM abort)');
      console.log('  - whether the posted method names need values not in DEVICE/IOS_ALIASES');
    }
  }
  if (runError) console.log('\nrun error:', String(runError.message || runError));
  process.exit(capturedSignal != null ? 0 : 2);
}

// ---------------------------------------------------------------------------
// SHA-256 cross-check.
//
// We cannot hook the VM's closure-private SHA-256 (case J5) or MurmurHash3 (xg)
// from outside without editing the source and breaking the integrity hash. So we
// instead VERIFY the VM's crypto externally: the signal has the shape
//   <prefix>#field#field#...#<hex tail>
// where each field is "methodName=value" and <hex tail> is the trailing chars of
// SHA-256 over the concatenation of the field strings (no delimiter). Matching it
// with Node's reference SHA-256 confirms the VM's pure-JS SHA-256 is correct and
// shows exactly what it hashed — the instrumentation the task asked for, achieved
// without touching the protected source.
function verifyInternalSha(signal) {
  const s = String(signal);
  const parts = s.split('#').filter((p) => p.length);
  // Trailing part with no '=' is the hash tail; the '=' parts are the fields.
  const tail = parts.length && parts[parts.length - 1].indexOf('=') === -1 ? parts[parts.length - 1] : null;
  const fields = parts.filter((p) => p.indexOf('=') >= 0);
  if (!tail || !fields.length) {
    console.log('\nSHA-256 cross-check: signal shape unrecognized (skipped).');
    return;
  }
  const concat = fields.join('');                       // hash input = fields concatenated
  const full = crypto.createHash('sha256').update(concat).digest('hex');
  const ok = full.slice(-tail.length) === tail.toLowerCase() || full.slice(0, tail.length) === tail.toLowerCase();
  console.log('\nSHA-256 cross-check (VM crypto vs Node reference):');
  console.log('  hash input  :', JSON.stringify(concat));
  console.log('  node sha256 :', full);
  console.log('  signal tail :', tail, ok ? '  ==> MATCH (VM SHA-256 verified)' : '  ==> no match (input model differs)');
}

run();
