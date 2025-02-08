EXTRA_DIST = symbols_to_strip.txt LICENSE
BUILT_SOURCES = chaff.c chaff.h

bin_PROGRAMS = ptooie
ptooie_SOURCES = pt.c rot13.c rot13.h
nodist_ptooie_SOURCES = chaff.c chaff.h

noinst_PROGRAMS = gen_chaff
gen_chaff_SOURCES = gen_chaff.cpp rot13.c rot13.h


chaff.c: chaff.h
chaff.h: gen_chaff
	$(builddir)/gen_chaff

clean-local:
	rm -f $(BUILT_SOURCES)

all-am: strip_debug_info

strip_debug_info: ptooie
	strip -g $<
	for SYMBOL_TO_STRIP in `cat $(srcdir)/symbols_to_strip.txt`; \
	do \
		strip -N $${SYMBOL_TO_STRIP} $<; \
	done
