# -*- makefile -*-

default:: programs

# stuff.
INC=${RFC6204D_SRCDIR}/include
#CROSSFLAGS=-m32
CFLAGS+=-I${INC}
CXXFLAGS+=-I${INC}
OSDEP=$(shell uname -s).$(shell arch)

USE_OBJDIR=false
PANDORA_OBJDIR=${RFC6204D_SRCDIR}/.
XMLTO=xmlto

MANTREE=${DESTDIR}/usr/share/man
INSTALL=install
INSTMANFLAGS=-D
INSTBINFLAGS=-D

LIBNDMGMT=${PANDORA_OBJDIR}/lib/libndmgmt/libndmgmt.a
LIBFAKEIFACE=${PANDORA_OBJDIR}/lib/libfakeiface/libfakeiface.a
#LIBPCAP=/usr/local/ia32/lib/libpcap.a
LIBPCAP=-L/usr/local/ia32/lib -lpcap
# needed by libpcap
EXTRALIBS=${LIBPCAP} -L/sandel/lib/i386-linux-gnu -lusb-1.0

NEEDCHECK?=check

TAGS clean ${NEEDCHECK} programs checkprograms::
	@for d in $(SUBDIRS) ; \
	do \
		$(MAKE) -C $$d RFC6204D_SRCDIR=${RFC6204D_SRCDIR} $@ || exit 1; \
	done;

env:
	@env | sed -e "s/'/'\\\\''/g" -e "s/\([^=]*\)=\(.*\)/\1='\2'/"

TAGS::
	@if [ -n "${CXXSRCS}${SRCS}" ]; then etags --append -o ${RFC6204D_SRCDIR}/TAGS ${CXXSRCS} ${SRCS}; fi

