# CVE-2026-86950: GlyphGrift Payload

CoreGraphics `aa_double_to_fixed` integer overflow → heap/stack OOB write in `aa_cache_render`.
Fixed in iOS 26.7.1 / macOS 26.7.1. Target iOS 26.6.1 (23G83) is vulnerable.

Trigger: render a crafted PDF (TrueType composite-glyph scaling). ImageIO/CG reaches
`CGGlyphBitmapCreateWithPathAndDilation` → `aa_cache_render` → undersized coverage buffer → OOB write.

## Root Cause

Compiler-induced undefined behavior: clang optimizes `double→int32` conversion differently:
- `aa_moveto`: `FCVTZS Wd` (saturating)
- `aa_lineto`: `FCVTZS Vd.2D` + `XTN` (truncating)

Result: bbox calculation wraps, coverage buffer is undersized, OOB increment during scanline rendering.

## Variants

| File | DX | Path | Role |
|------|----|------|------|
| `trigger.pdf` | 33 | heap malloc | Phase-1 crash/OOB telemetry |
| `trigger_stack.pdf` | 31 | stack alloca | Research only (`--glyphgrift-stack`) |
| `trigger_k128.pdf` | 34 | heap | V2 primary — target ~kalloc.128 spray zone |
| `trigger_k192.pdf` | 36 | heap | V2 fallback if k128 corruption misses |
| `trigger_dx33.pdf` – `trigger_dx40.pdf` | 33-40 | heap | Full DX sweep for empirical bmalloc bucket targeting |

## bmalloc/libpas Size Classes (FIX P1)

WebKit/WebSheet uses **bmalloc/libpas**, NOT XNU kalloc zones. Size classes:
16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512...

The coverage buffer `malloc(4*(width_px+16))` lands in an unpredictable bmalloc bucket due to
bbox corruption. V2 sprays **multiple zones** (48-256B) and sweeps **DX 33-40** to find the match.

## Delivery Vector (FIX P6)

**CRITICAL**: Use `<img>` vector (ImageIO thumbnail path) — NOT `<iframe>` or `<object embed>`.
- `<img>` → ImageIO renders PDF thumbnail **in-process** (same bmalloc heap as spray buffers)
- `<iframe>` → Spawns isolated renderer process (different heap, OOB can't hit spray)

The V2 exploit HTML **forces `vector=img`** regardless of user selection to avoid isolation.

## Exploitation Strategy

1. **Multi-zone spray**: Fill bmalloc zones 48/64/80/96/128/160/192/256B with ArrayBuffers
2. **Hole punching**: Free every 2nd slot to create holes
3. **GC pressure**: Force WebKit GC to reclaim holes (8 rounds of large allocs)
4. **Delay**: Wait 500ms for bmalloc to process frees, then 2s after GC
5. **DX sweep**: Render all 10 PDF variants (DX 33-40) sequentially
6. **Scan**: Check ALL surviving buffers across ALL zones for corruption
7. **Retry**: Up to 5 full spray→trigger→scan cycles

## Rebuild (build host only)

    pip install fonttools
    make clean && make

## References

- [PLAN/glyphgrift_plan.md](../../PLAN/glyphgrift_plan.md) — Original V1 integration plan
- [PLAN/glyphgrift_plan_V2.md](../../PLAN/glyphgrift_plan_V2.md) — Heap shaping & kernel R/W bridge
- [PLAN/glyphgrift_success_rate_plan.md](../../PLAN/glyphgrift_success_rate_plan.md) — Root cause analysis & fixes
- [../../RESEARCH/IMPORTANT TO CHECK/CVE-2026-86950/the-great-glyph-grift.md](../../RESEARCH/IMPORTANT%20TO%20CHECK/CVE-2026-86950/the-great-glyph-grift.md)
