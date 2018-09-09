MODULES_DIR := /lib/modules/$(shell uname -r)
KERNEL_DIR := ${MODULES_DIR}/build
EXTRA_CFLAGS := -I$(src)/../include -I$(src)/../ndpi/src/include

obj-m += xt_ngfilter.o
xt_ngfilter-objs := ./src/xt_ngfilter.o ./src/string_match.o

all:
	make -C ${KERNEL_DIR} M=$$PWD modules;
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
