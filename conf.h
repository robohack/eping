/*
** Various configuration definitions.
**
**	@(#)conf.h              e07@nikhef.nl (Eric Wassenaar) 940226
*/

/*
** MAXPKT -- Maximum size of an ECHO request output packet.
** -------------------------------------------------------
**
**	This is configurable up to the maximum size of an atomic packet
**	accepted by sendto(). That size is platform dependent. In case
**	it is too large, sendto() will complain with an EMSGSIZE errno.
**
**	If not defined in the Makefile and not defined here in conf.h
**	a default value is used in ping.c
*/

#ifndef MAXPKT

#if defined(sun) || defined(hpux) || defined(__hpux) || defined(ultrix)
#define	MAXPKT	2048
#endif

#if defined(sgi) || defined(apollo)
#define	MAXPKT	8192
#endif

#endif /*MAXPKT*/

/*
** MULTIPLE_IP_OPTIONS -- Allow more than one IP option
** ----------------------------------------------------
**
**	Some Cisco routers may get confused if multiple IP options are
**	present in the request packets. The ARP cache may be clobbered.
**	The ethernet address of the client host is replaced with the
**	ethernet address of the next machine along the route. Subsequent
**	ordinary IP traffic from the same client host is then impossible
**	until the ARP cache is cleared again. This may take considerable
**	time if not done manually.
**
**	Setting this parameter allows the use of multiple IP options.
**	Otherwise that is restricted to the superuser only.
*/

#ifndef MULTIPLE_IP_OPTIONS

#undef MULTIPLE_IP_OPTIONS		/* default is to leave if off */

#endif /*MULTIPLE_IP_OPTIONS*/
