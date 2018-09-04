# Make libxt_ipaddr.so
IDIR =../include
CFLAGS = -O2 -Wall -I$(IDIR)
all: libxt_ngfilter.so
lib%.so: lib%.o
	gcc -shared -o $@ $^;
lib%.o: lib%.c
	gcc ${CFLAGS} -fPIC -D_INIT=lib$*_init -c -o $@ $<;
install:
	cp libxt_ngfilter.so /usr/lib64/xtables/
