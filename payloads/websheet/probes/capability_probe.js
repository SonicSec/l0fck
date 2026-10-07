/**
 * WebSheet capability recon — no memory corruption.
 * Registers as __L0FCK_STAGE4_RUNNERS.capability_probe
 */
(function () {
  'use strict';

  function collect() {
    var sab = typeof SharedArrayBuffer !== 'undefined';
    var atomics = typeof Atomics !== 'undefined';
    var wasm = typeof WebAssembly === 'object';
    var sw = typeof navigator !== 'undefined' && 'serviceWorker' in navigator;
    var t0 = performance.now();
    var t1 = performance.now();
    return {
      sharedArrayBuffer: sab,
      atomics: atomics,
      webAssembly: wasm,
      serviceWorker: !!sw,
      indexedDB: !!(typeof window !== 'undefined' && window.indexedDB),
      hardwareConcurrency: (navigator && navigator.hardwareConcurrency) || null,
      timerDeltaMs: +(t1 - t0).toFixed(4),
      platform: (navigator && navigator.platform) || '',
      note: 'capability recon only — not RCE'
    };
  }

  window.__L0FCK_STAGE4_RUNNERS = window.__L0FCK_STAGE4_RUNNERS || {};
  window.__L0FCK_STAGE4_RUNNERS.capability_probe = function (ctx) {
    var detail = collect();
    if (ctx && ctx.log) ctx.log('capability: ' + JSON.stringify(detail));
    return ctx.report('capability_probe', 'ok', JSON.stringify(detail));
  };
})();
