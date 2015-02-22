PREFIX := /usr/local

CC := clang
CFLAGS := -std=c11 -Wall -Wextra -Werror -pedantic -O3 -march=native

cpassacre: cpassacre-gmp.c KeccakSponge.o KeccakF-1600-opt64.o config.h
	$(CC) $(CFLAGS) KeccakSponge.o KeccakF-1600-opt64.o cpassacre-gmp.c -lm -lgmp -o $@

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
