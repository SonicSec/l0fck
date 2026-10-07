# CVE-2026-86950: GlyphGrift Payload

CoreGraphics `aa_double_to_fixed` integer overflow → heap/stack OOB write in `aa_cache_render`.
Fixed in iOS 26.7.1 / macOS 26.7.1. Target iOS 26.6.1 (23G83) is vulnerable.

Trigger: render a crafted PDF (TrueType composite-glyph scaling). ImageIO/CG reaches
`CGGlyphBitmapCreateWithPathAndDilation` → `aa_cache_render` → undersized coverage buffer → OOB write.

## Variants

| File | DX | Path | Role |
|------|----|------|------|
| `trigger.pdf` | 33 | heap malloc | Phase-1 crash/OOB telemetry |
| `trigger_stack.pdf` | 31 | stack alloca | Research only (`--glyphgrift-stack`) |
| `trigger_k128.pdf` | 34 | heap | V2 primary — target ~kalloc.128 spray zone |
| `trigger_k192.pdf` | 36 | heap | V2 fallback if k128 corruption misses |

Empirical zone table (bbox corruption makes `width_px` small; DX tunes alloc size):

| DX | Alloc (approx) | Target zone |
|----|----------------|-------------|
| 33 | ~68 B | kalloc.80 |
| 34 | ~72–80 B | kalloc.80/96 → spray at 128 |
| 36 | ~80–96 B | kalloc.96/128 → spray at 192 |

V2 exploit stages use **heap only** (k128 then k192). Runtime has **no Python** — pre-built PDFs are served by captive HTTP.

Rebuild (build host only):

    pip install fonttools
    make
