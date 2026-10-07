/**
 * Sanitized JSC OOM / stress harness derived from
 * RESEARCH/Apple-JSC-Vulnerability-Analysis/poc.html
 *
 * DoS / allocation-pressure SIGNAL ONLY — not a weaponized RCE.
 * Opt-in via loader (?stage4=oom or __L0FCK_STAGE4_RUN_OOM()).
 * Caps allocation so lab devices are less likely to hard-lock forever.
 */
(function () {
  'use strict';

  var MAX_CHUNKS = 64;          /* 64 * 1MiB ~= 64MiB soft budget */
  var CHUNK = 1024 * 1024;

  window.__L0FCK_STAGE4_RUNNERS = window.__L0FCK_STAGE4_RUNNERS || {};
  window.__L0FCK_STAGE4_RUNNERS.jsc_watchpoint_oom = function (ctx) {
    var log = (ctx && ctx.log) || function () {};
    var report = ctx.report;
    var buffer = [];
    var allocated = 0;
    var status = 'ok';
    var detail = '';

    log('OOM stress start (capped, non-weaponized)');

    try {
      for (var i = 0; i < MAX_CHUNKS; i++) {
        var data = new ArrayBuffer(CHUNK);
        buffer.push(new Uint8Array(data).fill(0x41));
        allocated += CHUNK;
      }
      /* Original research used an enormous Array fill — keep a modest stand-in. */
      var modest = new Array(1024 * 256).fill('A');
      void modest;
      detail = JSON.stringify({
        allocated_bytes: allocated,
        chunks: buffer.length,
        crash_or_hang_suspected: false,
        note: 'completed without throw — DoS research signal only, not RCE'
      });
      status = 'ok';
    } catch (e) {
      status = 'crash_or_hang_suspected';
      detail = JSON.stringify({
        allocated_bytes: allocated,
        chunks: buffer.length,
        crash_or_hang_suspected: true,
        error: String(e && e.message ? e.message : e),
        note: 'allocation threw — still not claimed as RCE'
      });
    }

    buffer = null;
    return report('jsc_watchpoint_oom', status, detail);
  };
})();
