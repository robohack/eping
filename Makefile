#	@(#)Makefile            e07@nikhef.nl (Eric Wassenaar) 950930

# ----------------------------------------------------------------------
# Adapt the installation directories to your local standards.
# ----------------------------------------------------------------------

# This is where the ping executable will go.
DESTBIN = /local/sbin

# This is where the ping manual page will go.
DESTMAN = /local/share/man

BINDIR = $(DESTBIN)
MANDIR = $(DESTMAN)/man8

# ----------------------------------------------------------------------
# Special compilation options may be needed only on a few platforms.
# See also the header file port.h for portability issues.
# ----------------------------------------------------------------------

#if defined(_AIX)
SYSDEFS = -D_BSD -D_BSD_INCLUDES -U__STR__ -DBIT_ZERO_ON_LEFT
#endif
 
#if defined(solaris) && You do not want to use BSD compatibility mode
SYSDEFS = -DSYSV
#endif
 
#if defined(solaris) && You are using its default broken resolver library
SYSDEFS = -DNO_YP_LOOKUP
#endif

SYSDEFS =

# ----------------------------------------------------------------------
# Configuration definitions.
# See also the header file conf.h for more configuration definitions.
# ----------------------------------------------------------------------

# If this is a SUN with SunOS 4.1.x and you have an NC400 ethernet board
CONFIGDEFS = -DOMNINET='"ne0"'

# If combined use of IPOPT_LSRR and IPOPT_RR doesn't *hang* your router
CONFIGDEFS = -DMULTIPLE_IP_OPTIONS

# If sendto() accepts a different maximum size for atomic packets
CONFIGDEFS = -DMAXPKT=8192

CONFIGDEFS =
CONFIGDEFS = -DMULTIPLE_IP_OPTIONS

# ----------------------------------------------------------------------
# Compilation definitions.
# ----------------------------------------------------------------------

DEFS = $(CONFIGDEFS) $(SYSDEFS)

COPTS =
COPTS = -O

CFLAGS = $(COPTS) $(DEFS)

# Select your favorite compiler.
CC = /usr/ucb/cc			#if defined(solaris) && BSD
CC = /bin/cc -arch m68k -arch i386	#if defined(next)
CC = /bin/cc
CC = cc

# ----------------------------------------------------------------------
# Linking definitions.
# libresolv.a should contain the resolver library of BIND 4.8.2 or later.
# Link it in only if your default library is different.
# lib44bsd.a contains various utility routines, and comes with BIND 4.9.*
# You may need it if you link with the 4.9.* resolver library.
# libnet.a contains the getnet...() getserv...() getproto...() calls.
# It is safe to leave it out and use your default library.
# ----------------------------------------------------------------------

RES = ../res/libresolv.a
RES = -lresolv

COMPLIB =
COMPLIB = ../compat/lib/lib44bsd.a
COMPLIB = -lnet
COMPLIB =

LIBS = -lsocket -lnsl			#if defined(solaris) && not BSD
LIBS =

LIBRARIES = $(RES) $(COMPLIB) $(LIBS)

LDFLAGS =

# ----------------------------------------------------------------------
# Miscellaneous definitions.
# ----------------------------------------------------------------------

MAKE = make $(MFLAGS)

# This assumes the BSD install.
INSTALL = install -c

# Grrr
SHELL = /bin/sh

# ----------------------------------------------------------------------
# Files.
# ----------------------------------------------------------------------

HDRS = port.h conf.h icmp.h exit.h defs.h
SRCS = ping.c omni.c vers.c
OBJS = ping.o omni.o vers.o
PROG = ping
MANS = ping.8
DOCS = RELEASE_NOTES

FILES = Makefile $(DOCS) $(HDRS) $(SRCS) $(MANS)

# ----------------------------------------------------------------------
# Rules for installation.
# ----------------------------------------------------------------------

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) -o $(PROG) $(OBJS) $(LIBRARIES)

install: $(PROG)
	$(INSTALL) -m 4555 -o root -g bin $(PROG) $(BINDIR)

man: $(MANS)
	$(INSTALL) -m 444 ping.8 $(MANDIR)

clean:
	rm -f $(PROG) $(OBJS) *.o a.out core ping.tar ping.tar.Z

# ----------------------------------------------------------------------
# Rules for maintenance.
# ----------------------------------------------------------------------

lint:
	lint $(DEFS) $(SRCS)

llint:
	lint $(DEFS) $(SRCS) -lresolv

print:
	lpr -J $(PROG) -p Makefile $(DOCS) $(HDRS) $(SRCS)

dist:
	tar cf ping.tar $(FILES)
	compress ping.tar

depend:
	mkdep $(DEFS) $(SRCS)

# DO NOT DELETE THIS LINE -- mkdep uses it.
# DO NOT PUT ANYTHING AFTER THIS LINE, IT WILL GO AWAY.
