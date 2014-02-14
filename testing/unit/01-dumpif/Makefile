RFC6204D_SRCDIR?=$(shell cd ../../..; pwd)
INC?=${RFC6204D_SRCDIR}/include

all: check

include ${RFC6204D_SRCDIR}/Makefile.inc
include ../Makefile.testing

dumpif: dumpif.cpp ${INC}/iface.h
	${CXX} ${CXXFLAGS} -o dumpif dumpif.cpp ${LDFLAGS}

check::	dumpif
	./dumpif | grep "lo type=loopback"

checkprograms:: dumpif
programs::

clean::
	@rm -rf dumpif *.o
