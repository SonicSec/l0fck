PYTHON ?= /opt/homebrew/bin/python3

DX_VALUES = 33 34 35 36 37 38 39 40
DX_PDFS = $(patsubst %,trigger_dx%.pdf,$(DX_VALUES))
DX_TTFS = $(patsubst %,trigger_dx%.ttf,$(DX_VALUES))

.PHONY: all clean render verify

all: trigger.pdf trigger_stack.pdf trigger_k128.pdf trigger_k192.pdf $(DX_PDFS)

render: render.c
	clang -O2 -g -o $@ $< -framework ImageIO -framework CoreGraphics -framework CoreFoundation

# Gate 0 (PLAN/GLYPHGRIFT_CHAIN_FIX_PLAN.md): prove the PDFs reach aa_cache_render.
# On an unpatched host these crash (SIGSEGV); "survived" means the local CG is patched.
verify: render
	@echo "=== Gate 0: local render harness (control + bundled) ==="
	./render trigger.pdf ; echo "trigger.pdf exit=$$?"
	./render trigger_k128.pdf ; echo "trigger_k128.pdf exit=$$?"

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

clean:
	rm -f trigger*.ttf trigger*.pdf
