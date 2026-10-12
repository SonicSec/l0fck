# Chain: GlyphGrift-Chain (CVE-2026-86950 CoreGraphics OOB)

- **CLI**: `--glyphgrift-chain` (menu 6.7), with `--glyphgrift-vector
  img|embed` (default `img`), `--glyphgrift-stack` (research-only DX=31
  stack PDF), and the usual captive port args. **Wi-Fi only — no USB.**
- **Status (honest)**: **trigger fires (behavioral Gate-1 signal) but memory
  corruption / read-back not yet observed** — see "Red herrings & corrective
  findings" below. The early "final reports" claiming 0→60% success are
  **superseded** by `PLAN/GLYPHGRIFT_CHAIN_FIX_PLAN.md`.
- **Key files**:
  - `payloads/glyphgrift/` — `gen_font.py`, `gen_pdf.py`, `render.c`
    (local Gate-0 crash check), `trigger*.pdf`/`.ttf` (dx33–40, k128, k192,
    stack), `crash_*.pdf`
  - `payloads/websheet/probes/` — `glyphgrift_pdf_trigger.js`,
    `glyphgrift_heap_spray.js`, `glyphgrift_post_trigger.js`,
    `glyphgrift_krw.js`, `captive_krw_client.js`
  - `src/exploits/bypass_chain.c` — `glyphgrift_chain_run`;
    `src/exploits/captive_payloads.c` — 10-variant PDF sweep;
    `src/exploits/captive_http.c` — `/api/glyphgrift-exploit-result`,
    `/api/glyphgrift-alive` heartbeat

## The CVE (per `PLAN/glyphgrift_plan.md`, `glyphgrift_plan_V2.md`)

**CVE-2026-86950** — CoreGraphics `aa_double_to_fixed` integer overflow →
OOB 16-bit increment in `aa_cache_render`. Compiler-induced UB: clang picks
`FCVTZS Wd` (saturating) vs `FCVTZS Vd.2D`+`XTN` (truncating) for
`aa_add_edges` bounding-box math on a crafted TrueType font (leaf glyph
x=32000, 9 composite ×2 scales → ~16M font units). Undersized `coverage`
buffer (`malloc(4*(width_px+16))` if `width_px>1015`, else `alloca`) →
controlled OOB **16-bit increment of two adjacent uint16_t** at offset
`(edge_x - bbox_min_x)/4096`. **`DX≥32 → malloc (heap)`; `DX≤31 → alloca
(stack)`**. Reach path: `CGImageSourceCreateThumbnailAtIndex` →
`CGGlyphBitmapCreateWithPathAndDilation` → `aa_cache_render`. **Fixed in iOS
26.7.1; 23G83 vulnerable.**

## Stages

```
 0: DNS/HTTP prep (captive portal, same as SetupAssistant-Chain Stages 0-1)
 1: WebSheet forced
 2: JS foothold confirmed (telemetry POST)
 3: trigger.pdf served (vector: <img> ImageIO thumbnail — DEFAULT & REQUIRED)
 4: crash / OOB telemetry (heartbeat-gap = trigger-fired signal)
 5: Heap spray — multi-bmalloc zones 48/64/80/96/128/160/192/256 B
 6: Multi-PDF trigger sweep (k128, k192, dx33–40 — 10 entries)
 6b: Post-trigger KRW init (glyphgrift_krw.js: ArrayBuffer byteLength OOB →
     relative R/W; scanForKernelPointer for kbase)
 7: KRW bridge (captive_krw_client.js polls /api/krw/poll)
 8: AMFI/SEP/activation (reuses SetupAssistant Stages 6-8)
```

## Design decisions (per `PLAN/glyphgrift_success_rate_plan.md`,
`GLYPHGRIFT_IMPLEMENTATION_SUMMARY.md`, `GLYPHGRIFT_FINAL_REPORT.md`)

- **bmalloc/libpas, not kalloc** (P1) — WebKit ArrayBuffers don't use XNU
  kalloc → multi-zone spray.
- **Force `<img>` vector** (P6) — `<iframe>`/`<object>`/embed spawn an
  *isolated renderer process* so the OOB can't hit main-process spray;
  ImageIO thumbnailing runs in-process. `--glyphgrift-stack` (DX=31, alloca)
  remains research-only.
- **DX sweep + GC timing + retry rounds** (P2/P4/P5/P7).

## Red herrings & corrective findings (per `PLAN/GLYPHGRIFT_CHAIN_FIX_PLAN.md`)

The most-refuted chain in the project. The fix plan found 4 defects the
"final reports" missed:

- **D1**: the "VUL 23 USB 60%" alternative (see
  `findings-preboard-vul23.md`) is not a real vuln.
- **D2 — wrong KASLR anchor table** in `glyphgrift_krw.js` (`allproc=0x00c4d000`
  vs verified `0xb23a880`) → plausible-but-wrong kbase → "kwrite64 fails
  ~80%". Fixed table + **2-anchor cross-check** required.
- **D3 — the 5-round retry is an illusion**: rounds 2–5 render in
  `render_time_ms: 0.00` because the `<img>` PDFs are **cached**; the trigger
  fires at most once.
- **D4 — "10-PDF sweep" is 8 distinct payloads** (`k128≡dx34`,
  `trigger≡dx33` by MD5), and the bundled PDFs don't match the verified
  research PoC (different fonttools regen). Use the assets from the CVE
  RESEARCH folder, not regenerated prebuilts.
- **U1 (load-bearing)**: unverified whether WebSheet `<img src=pdf>` even
  reaches `CGGlyphBitmapCreateWithPathAndDilation` at the 1024 pt
  cache-path gate.
- **Naming red herring**: the primitive is a **userspace OOB** (ArrayBuffer
  `byteLength` increment = WebKit-heap relative R/W), **not kernel R/W** —
  "Stage 7 Kernel R/W" naming overstates it.

**Gate-1 addendum (2026-10-11)**: after the host served `trigger_dx36.pdf`,
the device sent zero requests for ~13 s, then heartbeats resumed on the same
phase → renderer **main thread blocked** while the in-page ImageIO rasterizer
ground the wide glyph = positive trigger-fired (behavioral) signal.
`createImageBitmap` cannot decode PDF on iOS (`decode_err`) — removed as
noise. Phase 9 heartbeat-gap detector → `stage4_oob_signal` /
`stage4_oob_confirmed` (recovering stall) vs renderer crash
(non-recovering). **Net: OOB path runs in-process, but no memory read-back
and no kbase yet.**

## Gates & telemetry

- Gate 0: local `render.c` crash of the research PDF (host reproducible).
- Gate 1: trigger fires (heartbeat-gap). Gate 2: one real read-back or
  documented crash. Gate 3: `gVirtBase` read matches KASLR-adjusted value.
- **Sentinel canary read-back** (Phase 4 of fix plan): hardcoded 0xA5
  buffer in a dense, no-hole spray immediately before the trigger so a
  single OOB increment flips an assertable byte; host requires
  `relative_rw_achieved` + read-back before Stage 7.
- Telemetry: `/tmp/l0fck_glyphgrift_result.json`,
  `/tmp/l0fck_glyphgrift_exploit_result.json`; renderer heartbeat on
  `/api/glyphgrift-alive`.
