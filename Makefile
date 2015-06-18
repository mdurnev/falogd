CFLAGS ?= -pthread -O2 -DHAVE_SYSTEMD=0
LDFLAGS ?= -pthread -Wl,--hash-style=gnu

all: falogd

falogd: falogd.o log.o pid_tree.o fa.o

clean:
	rm -f *.o falogd
.PHONY: clean
