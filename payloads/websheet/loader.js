/**
 * l0fck SetupAssistant Stage-4 loader (research harness).
 * Loads probes from /websheet/manifest.json. Never claims native RCE.
 * Opt-in OOM: ?stage4=oom or window.__L0FCK_STAGE4_OOM = true
 */
(function () {
  'use strict';

  var API = '/api/stage4-probe';

  function log(msg) {
    try {
      if (typeof window.log === 'function') window.log('[stage4] ' + msg);
      else console.log('[l0fck stage4]', msg);
    } catch (e) {}
  }

  function report(probeId, status, detail) {
    var body = {
      probe_id: probeId,
      status: status,
      detail: detail || '',
      ua: (navigator && navigator.userAgent) || '',
      build_guess: guessBuild(),
      stage4_native_rce: false,
      ts: Date.now()
    };
    return fetch(API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }).then(function () {
      log('reported ' + probeId + ' => ' + status);
    }).catch(function (err) {
      log('report failed: ' + (err && err.message ? err.message : err));
    });
  }

  function guessBuild() {
    var ua = (navigator && navigator.userAgent) || '';
    var m = ua.match(/Mobile\/([A-Z0-9]+)/);
    if (m) return m[1];
    m = ua.match(/OS (\d+)[_.](\d+)(?:[_.](\d+))?/);
    if (m) return 'iOS_' + m[1] + '.' + m[2] + (m[3] ? '.' + m[3] : '');
    return 'unknown';
  }

  function wantOom() {
    if (window.__L0FCK_STAGE4_OOM === true) return true;
    try {
      var q = (window.location && window.location.search) || '';
      return /(?:\?|&)stage4=oom(?:&|$)/.test(q);
    } catch (e) {
      return false;
    }
  }

  function wantGlyphgrift() {
    if (window.__L0FCK_GLYPHGRIFT === true) return true;
    try {
      var q = (window.location && window.location.search) || '';
      return /(?:\?|&)glyphgrift=1(?:&|$)/.test(q);
    } catch (e) {
      return false;
    }
  }

  function loadScript(src) {
    return new Promise(function (resolve, reject) {
      var s = document.createElement('script');
      s.src = src;
      s.async = false;
      s.onload = function () { resolve(src); };
      s.onerror = function () { reject(new Error('failed to load ' + src)); };
      document.head.appendChild(s);
    });
  }

  function runProbeEntry(entryPath, probeId) {
    return loadScript('/websheet/' + entryPath).then(function () {
      var runners = window.__L0FCK_STAGE4_RUNNERS || {};
      var fn = runners[probeId];
      if (typeof fn !== 'function') {
        return report(probeId, 'error', 'runner not registered: ' + probeId);
      }
      return Promise.resolve()
        .then(function () { return fn({ report: report, log: log }); })
        .catch(function (err) {
          return report(probeId, 'error', String(err && err.message ? err.message : err));
        });
    }).catch(function (err) {
      return report(probeId, 'error', String(err && err.message ? err.message : err));
    });
  }

  function start() {
    log('loader start (harness only — stage4_native_rce=false)');
    report('loader', 'started', 'Stage-4 research harness loaded');

    fetch('/websheet/manifest.json')
      .then(function (r) { return r.json(); })
      .then(function (manifest) {
        var probes = (manifest && manifest.probes) || [];
        var chain = Promise.resolve();
        probes.forEach(function (p) {
          if (!p || !p.id || !p.entry) return;
          if (p.live === 1) {
            log('SKIP live payload ' + p.id + ' — harness refuses auto-run of live=1');
            return;
          }
          var run = !!p.auto;
          if (p.id === 'jsc_watchpoint_oom' && wantOom()) run = true;
          if (p.id === 'glyphgrift_pdf_trigger' && wantGlyphgrift()) run = true;
          if (!run) {
            log('skip (not auto): ' + p.id);
            return;
          }
          chain = chain.then(function () {
            log('running probe: ' + p.id);
            return runProbeEntry(p.entry, p.id);
          });
        });
        return chain.then(function () {
          return report('loader', 'done', 'auto probes finished; native RCE not claimed');
        });
      })
      .catch(function (err) {
        report('loader', 'error', String(err && err.message ? err.message : err));
      });
  }

  window.__L0FCK_STAGE4_RUNNERS = window.__L0FCK_STAGE4_RUNNERS || {};
  window.__L0FCK_STAGE4_RUN_OOM = function () {
    window.__L0FCK_STAGE4_OOM = true;
    return runProbeEntry('probes/jsc_watchpoint_oom.js', 'jsc_watchpoint_oom');
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    setTimeout(start, 0);
  }
})();
