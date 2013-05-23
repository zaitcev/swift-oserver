##
# requires:
#   GLib
#   libevent
#   OpenSSL (for MD5)
#   Hail (for http_req)

CFLAGS += -Wall -Wshadow -Wmissing-declarations -Wmissing-prototypes
CFLAGS += -Wnested-externs -Wpointer-arith -Wpointer-arith -Wsign-compare
CFLAGS += -Wchar-subscripts -Wstrict-prototypes -Wformat=2 -Wtype-limits
CFLAGS += -Wp,-D_FORTIFY_SOURCE=2
CFLAGS += -O2

CFLAGS += $(shell pkg-config --cflags glib-2.0)
LDFLAGS += $(shell pkg-config --libs glib-2.0)

CFLAGS += $(shell pkg-config --cflags libevent)
LDFLAGS += $(shell pkg-config --libs libevent)

# openssl
CFLAGS += $(shell pkg-config --cflags libcrypto)
LDFLAGS += $(shell pkg-config --libs libcrypto)

# XXX We use hstor because struct http_req. Open-code or something.
CFLAGS += $(shell pkg-config --cflags libhail)
LDFLAGS += $(shell pkg-config --libs libhail)

all: oserver

oserver: main.o status.o config.o util.o
	$(CC) -o $@ $^ $(LDFLAGS)

main.o: main.c oserver.h
status.o: status.c oserver.h
config.o: config.c oserver.h
util.o: util.c oserver.h

check: oserver
	cd test && nosetests --exe

clean:
	rm -f oserver *.o
