/*
** Various configuration definitions.
**
**	@(#)conf.h              e07@nikhef.nl (Eric Wassenaar) 961230
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

#if defined(sun)
#define	MAXPKT	2048
#endif

#if defined(hpux) || defined(__hpux)
#define	MAXPKT	2048
#endif

#if defined(ultrix)
#define	MAXPKT	2048
#endif

#if defined(sgi)
#define	MAXPKT	8192
#endif

#if defined(apollo)
#define	MAXPKT	8192
#endif

#endif /*MAXPKT*/

/*
** MULTIPLE_IP_OPTIONS -- Allow more than one IP option
** ----------------------------------------------------
**
**	Old Cisco routers may get confused if multiple IP options are
**	present in the request packets. The ARP cache may be clobbered.
**	The ethernet address of the client host is replaced with the
**	ethernet address of the next machine along the route. Subsequent
**	ordinary IP traffic from the same client host is then impossible
**	until the ARP cache is cleared again. This may take considerable
**	time if not done manually.
**
**	Setting this parameter allows the use of multiple IP options.
**	Otherwise such is restricted to the superuser only.
*/

#ifndef MULTIPLE_IP_OPTIONS

#define MULTIPLE_IP_OPTIONS		/* assume it is okay nowadays */

#endif /*MULTIPLE_IP_OPTIONS*/

/*
** RESTRICT_PINGMODES -- Restrict special ping modes to the superuser
** ------------------------------------------------------------------
**
**	The special ping modes, especially the flood ping mode, may
**	generate an undesired network load if not used with care.
**	They can be disabled for the ordinary user.
**	Note that you can restrict each of them individually.
*/

#ifdef RESTRICT_PINGMODES

#define RESTRICT_FLOOD			/* disallow flood ping */
#define RESTRICT_CISCO			/* disallow cisco ping */
#define RESTRICT_FAST			/* disallow fast ping */

#endif /*RESTRICT_PINGMODES*/

/*
 * Miscellaneous default values.
 */

#define DEF_TIMEOUT	1	/* -t  timeout between packets (secs) */
#define DEF_DELAY	10	/* -w  delay in flood mode (millisecs) */

#define DEF_RETRIES	2	/* number of datagram retries per nameserver */
#define DEF_RETRANS	3	/* timeout (seconds) between datagram retries */
