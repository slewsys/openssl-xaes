DESTDIR ?= /usr/local
VERSION = $(shell git describe --tags 2>/dev/null)
CFLAGS  = -DHAVE_EXPLICIT_BZERO=1 -Wall -Wextra -O2
LDFLAGS = $(shell pkg-config --libs openssl)

all: openssl-xaes

openssl-xaes: io.c openssl-xaes.c xaes.c io.h xaes.h version.h

check: version.h openssl-xaes
	$(MAKE) $(MAKEFLAGS) -C testsuite check

version.h: version.h.in
	sed -e "s/@VERSION@/$(VERSION)/" version.h.in > version.h

install: openssl-xaes
	install -m 0755 openssl-xaes $(DESTDIR)/bin/openssl-xaes
clean:
	rm -f openssl-xaes xaes-test version.h
	rm -f GPATH GTAGS GRTAGS *.tmp
	$(MAKE) $(MAKEFLAGS) -C testsuite clean
