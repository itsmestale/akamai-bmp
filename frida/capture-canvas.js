// Capture canvas ops by adding a custom JSBridge method that the injected
// instrumentation calls during execution (not after setSignal).
Java.perform(function() {
    console.log("[*] Canvas ops v2 — inline exfiltration");

    var WebView = Java.use("android.webkit.WebView");
    var u7f = Java.use("u7f");

    // Add a custom JSBridge method to u7f for receiving canvas data
    // We'll hook the EXISTING u7f methods instead — intercept any call
    // with a special prefix as canvas data.

    // Hook setSignal to detect both canvas data and the real signal
    u7f.setSignal.implementation = function(signal) {
        if (signal.indexOf("__CANVAS__") === 0) {
            // This is canvas data, not the real signal
            console.log("[CANVAS] " + signal.substring(10));
            return; // Don't forward to original
        }
        var pjs = signal.match(/pureJsSignal=([^#]+)/);
        if (pjs) console.log("[SIGNAL] " + pjs[1]);
        this.setSignal(signal);
    };

    WebView.loadData.overload('java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(data, mimeType, encoding) {
        console.log("[*] Injecting canvas tracers with inline exfiltration...");

        var tracer = [
            '<script>',
            'window._cvOps = {};',
            'window._cvId = 0;',

            '(function(){',
            '  var origGC = HTMLCanvasElement.prototype.getContext;',
            '  HTMLCanvasElement.prototype.getContext = function(type) {',
            '    window._cvId++;',
            '    var id = window._cvId;',
            '    this._cid = id;',
            '    var ctx = origGC.apply(this, arguments);',
            '    if (ctx && type === "2d") {',
            '      ctx._cid = id;',
            '      ctx._log = [];',
            '      window._cvOps[id] = {type:type, w:this.width, h:this.height, ops:ctx._log};',

            // Wrap key drawing methods
            '      ["fillRect","strokeRect","fillText","strokeText","arc","beginPath","fill",',
            '       "stroke","closePath","moveTo","lineTo","rect","clearRect","drawImage",',
            '       "bezierCurveTo","quadraticCurveTo","save","restore","translate","rotate","scale"',
            '      ].forEach(function(m){',
            '        if(typeof ctx[m]==="function"){',
            '          var orig=ctx[m];',
            '          ctx[m]=function(){',
            '            var a=[];for(var i=0;i<arguments.length;i++)a.push(typeof arguments[i]==="object"?"[obj]":String(arguments[i]).substring(0,40));',
            '            ctx._log.push(m+"("+a.join(",")+")");',
            '            return orig.apply(this,arguments);',
            '          };',
            '        }',
            '      });',

            // Wrap property setters via direct assignment tracking
            '      ["fillStyle","strokeStyle","font","textBaseline","textAlign","lineWidth","globalAlpha","globalCompositeOperation"',
            '      ].forEach(function(p){',
            '        try{',
            '          var _v;',
            '          Object.defineProperty(ctx,p,{',
            '            get:function(){return _v;},',
            '            set:function(v){_v=v;ctx._log.push(p+"="+String(v).substring(0,40));',
            '              Object.getPrototypeOf(ctx).__lookupSetter__(p).call(this,v);',
            '            },configurable:true',
            '          });',
            '        }catch(e){}',
            '      });',
            '    }',
            '    return ctx;',
            '  };',

            // Hook toDataURL — send data to JSBridge immediately
            '  var origTDU = HTMLCanvasElement.prototype.toDataURL;',
            '  HTMLCanvasElement.prototype.toDataURL = function(){',
            '    var r = origTDU.apply(this, arguments);',
            '    var id = this._cid || "?";',
            '    var ops = window._cvOps[id] || {};',
            '    try {',
            '      JSBridge.setSignal("__CANVAS__" + JSON.stringify({',
            '        id: id,',
            '        w: this.width,',
            '        h: this.height,',
            '        opsCount: (ops.ops||[]).length,',
            '        ops: (ops.ops||[]).slice(0, 80),',
            '        resultLen: r.length,',
            '        resultHead: r.substring(0, 120),',
            '        javaHashCode: (function(s){var h=0;for(var i=0;i<s.length;i++){h=((h*31)+s.charCodeAt(i))|0;}return h;})(r)',
            '      }));',
            '    } catch(e) {}',
            '    return r;',
            '  };',

            '})();',
            '</script>'
        ].join('\n');

        var modified = data.replace(/<script\s+id="static">/, tracer + '<script id="static">');
        if (modified === data) modified = tracer + data;
        this.loadData(modified, mimeType, encoding);
    };

    console.log("[*] Ready — launch app");
});
