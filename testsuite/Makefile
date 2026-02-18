top_srcdir = ..

CFLAGS  = -I. -I$(top_srcdir) -Wall -Wextra -g #-O2
LDFLAGS = $(shell pkg-config --libs openssl)

check: xaes-test
	./xaes-test
	top_srcdir=$(top_srcdir) ./xaes-test.sh

xaes-test: $(top_srcdir)/xaes.c xaes-test.c

clean:
	rm -f xaes-test
