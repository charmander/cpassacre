PREFIX := /usr/local

CC := clang
CFLAGS := -std=c11 -Wall -Wextra -Werror -pedantic -O3 -ffast-math -march=native -static

cpassacre: cpassacre.c KeccakSponge.o KeccakF-1600-opt64.o config.h
	$(CC) $(CFLAGS) -Weverything -Wno-reserved-id-macro -Wno-disabled-macro-expansion -Wno-padded KeccakSponge.o KeccakF-1600-opt64.o cpassacre.c -lm -o $@

KeccakSponge.o: keccak/KeccakSponge.c
	$(CC) $(CFLAGS) -c $<

KeccakF-1600-opt64.o: keccak/KeccakF-1600-opt64.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f KeccakSponge.o KeccakF-1600-opt64.o cpassacre

install: cpassacre
	mkdir -p $(DESTDIR)$(PREFIX)/bin/
	cp -f cpassacre $(DESTDIR)$(PREFIX)/bin/
	chmod 755 $(DESTDIR)$(PREFIX)/bin/cpassacre

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/cpassacre

.PHONY: clean install uninstall
