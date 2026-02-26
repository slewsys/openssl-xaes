top_srcdir = ..

CFLAGS  = -I. -I$(top_srcdir) -Wall -Wextra -g -O2
LDFLAGS = $(shell pkg-config --libs openssl)

.PHONY: all check clean

all: xaes-test

check: xaes-test
	./xaes-test
	top_srcdir=$(top_srcdir) ./xaes-test.sh

xaes-test: $(top_srcdir)/xaes.c xaes-test.c shake_stream.c shake_stream.h

clean:
	rm -f xaes-test
