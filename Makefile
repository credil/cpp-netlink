# rfc6204d master makefile
#
# Copyright (C) 2014 Michael Richardson <mcr@finepoint.com>
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


RFC6204D_SRCDIR?=$(shell pwd)
export RFC6204D_SRCDIR

TERMCAP=
export TERMCAP

default:: programs

srcdir?=$(shell pwd)

-include ${RFC6204D_SRCDIR}/Makefile.vendor

SUBDIRS=lib programs testing

include ${RFC6204D_SRCDIR}/Makefile.top
include ${RFC6204D_SRCDIR}/Makefile.inc

