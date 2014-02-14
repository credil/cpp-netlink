# Neighbour Discovery Library
# Copyright (C) 2009-2013 Michael Richardson <mcr@sandelman.ca>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#


RFC6204D_SRCDIR?=$(shell cd ../..; pwd)
export RFC6204D_SRCDIR

include ${RFC6204D_SRCDIR}/Makefile.ver
include ${RFC6204D_SRCDIR}/Makefile.inc

srcdir?=${RFC6204D_SRCDIR}/lib/libndmgmt/

LIBRARY=ndmgmt
LIB=lib${LIBRARY}.a
MANDIR=$(MANTREE)/man3

ONEFILE=iface.cpp
CXXSRCS=iface.cpp netlink.cpp debug.cpp
#SRCS=counter_names.c

#enable to get lots more debugging about semantics.
#CFLAGS=-DPARSER_TYPE_DEBUG
CXXFLAGS+=-g -O0

OBJS=${SRCS:.c=.o} ${CXXSRCS:.cpp=.o}

include ${srcdir}../Makefile.library

