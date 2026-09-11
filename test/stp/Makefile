# Host-side sandbox for the firmware STP/RSTP port roles.
#
# Compiles the UNMODIFIED ../../rtl837x_stp.c against shim headers: SDCC
# storage-class keywords are blanked via -D, and the module copy lives in
# build/ so quote-includes resolve to shim/ instead of the firmware tree.
CC ?= cc
CFLAGS = -std=c11 -Wall -Wextra -Wno-unknown-pragmas \
         -D__xdata= -D__code= -D__banked= -D__reentrant= \
         -Ishim -I../..

all: build/stp_sim
	./build/stp_sim

verbose: build/stp_sim
	./build/stp_sim -v

build/stp_sim: stp_sim.c ../../rtl837x_stp.c ../../rtl837x_stp.h shim/*.h
	mkdir -p build
	cp ../../rtl837x_stp.c build/stp_under_test.c
	$(CC) $(CFLAGS) -o $@ stp_sim.c build/stp_under_test.c

clean:
	rm -rf build

.PHONY: all verbose clean
