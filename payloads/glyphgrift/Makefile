PYTHON ?= /opt/homebrew/bin/python3

DX_VALUES = 33 34 35 36 37 38 39 40
DX_PDFS = $(patsubst %,trigger_dx%.pdf,$(DX_VALUES))
DX_TTFS = $(patsubst %,trigger_dx%.ttf,$(DX_VALUES))

.PHONY: all clean

all: trigger.pdf trigger_stack.pdf trigger_k128.pdf trigger_k192.pdf $(DX_PDFS)

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
