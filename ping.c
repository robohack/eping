/*
 * Copyright (c) 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * The original version of this program comes from Mike Muuss.
 *
 * Totally rewritten by Eric Wassenaar, Nikhef-H, <e07@nikhef.nl>
 *
 * The source of this particular version of the program is available
 * via anonymous ftp from machine 'ftp.nikhef.nl' [192.16.199.1]
 * in the directory '/pub/network' as 'ping.tar.Z'
 */

#ifndef lint
static char Version[] = "@(#)ping.c	e07@nikhef.nl (Eric Wassenaar) 970525";
#endif

#if defined(apollo) && defined(lint)
#define __attribute(x)
#endif
 
#if defined(__alpha) && defined(__osf__) && __GNUC__
#define __STDC__ 2		/* workaround for alpha <netinet/ip.h> bug */
#endif

#undef  obsolete		/* old code left as a reminder */
#undef  notyet			/* new code for possible future use */

/*
 *			P I N G . C
 *
 * Using the Internet Control Message Protocol (ICMP) "ECHO" facility,
 * measure round-trip-delays and packet loss across network paths.
 *
 * Author -
 *	Mike Muuss
 *	U. S. Army Ballistic Research Laboratory
 *	December, 1983
 * Modified at UC Berkeley.
 * Modified at Rutgers: Ron Natalie, David Paul Zimmerman.
 * Modified at DECWRL: Jeffrey Mogul.
 * Record Route and verbose headers - Phil Dykstra, BRL, March 1988.
 * Modified at Cornell: Jeffrey C Honig, April 1989.
 * Rewritten at NIKHEF: Eric Wassenaar, February 1994.
 *
 * Status -
 *	Public Domain.  Distribution Unlimited.
 *
 * Bugs -
 *	More statistics could always be gathered.
 *	This program has to run SUID to ROOT to access the ICMP socket.
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <setjmp.h>
#include <netdb.h>

#include <sys/types.h>		/* not always automatically included */
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/file.h>
#if 1
#include <sys/ioctl.h>		/* needed for TIOCGWINSZ */
#endif

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#if 0
#include <netinet/ip_var.h>	/* only needed for MAX_IPOPTLEN */
#endif
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#undef NOERROR			/* in <sys/streams.h> on solaris 2.x */
#include <arpa/nameser.h>
#include <resolv.h>

#if defined(linux)
#include "linux.h"		/* special compatibility definitions */
#endif

#include "port.h"		/* various portability definitions */
#include "conf.h"		/* various configuration definitions */
#include "exit.h"		/* exit codes come from <sysexits.h> */
#include "icmp.h"		/* icmp types belong in <netinet/ip_icmp.h> */

#ifndef MAXDNAME
#define MAXDNAME	256	/* maximum length of domain name */
#endif

typedef int	bool;		/* boolean type */
#define TRUE	1
#define FALSE	0

#ifdef lint
#define EXTERN
#else
#define EXTERN extern
#endif

EXTERN int errno;
EXTERN res_state_t _res;	/* defined in res_init.c */
extern char *version;		/* program version number */

char **optargv = NULL;		/* argument list including default options */
int optargc = 0;		/* number of arguments in new argument list */

/*
 * Probe packet structure.
 */

#define IPHDRSZ		20	/* actually sizeof(struct ip) */
#define UDPHDRSZ	8	/* actually sizeof(struct udphdr) */

#ifdef IP_MAXPACKET
#define MAXPACKET IP_MAXPACKET	/* max ip packet size */
#else
#define MAXPACKET 65535
#endif

#ifndef MAX_IPOPTLEN
#define MAX_IPOPTLEN	40	/* max ip options buffer size */
#endif

#define IPOPT_HDRLEN	3	/* actually IPOPT_MINOFF - 1 */

#ifndef MAXPKT
#define	MAXPKT	4096			/* max output packet total size */
#endif

#define PKTSIZE	64			/* default output packet size */
#define HDRLEN	ICMP_MINLEN		/* icmp header minimum length (8) */
#define	TIMLEN	sizeof(struct timeval)	/* size of timer data (8) */
#define DATALEN	(PKTSIZE-HDRLEN)	/* default packet data length (56) */
#define	MAXDATA	(MAXPKT-HDRLEN-TIMLEN)	/* max available for fill data */

u_char opacket[MAXPACKET];	/* outgoing packet */
u_char ipacket[MAXPACKET];	/* incoming packet */

/*
 * Socket assignments.
 */

int sock;			/* socket file descriptor */
int sockopts = 0;		/* socket options */

struct sockaddr_in myaddr;	/* address of ourselves */
struct sockaddr_in toaddr;	/* address to send to */
struct sockaddr_in fromaddr;	/* address to recv from */

struct sockaddr_in *me   = (struct sockaddr_in *)&myaddr;
struct sockaddr_in *to   = (struct sockaddr_in *)&toaddr;
struct sockaddr_in *from = (struct sockaddr_in *)&fromaddr;

struct sockaddr *myaddr_sa   = (struct sockaddr *)&myaddr;
struct sockaddr *toaddr_sa   = (struct sockaddr *)&toaddr;
struct sockaddr *fromaddr_sa = (struct sockaddr *)&fromaddr;

/*
 * Modes of operation.
 */

#define PING_NORMAL	0	/* ping at regular intervals */
#define PING_FLOOD	1	/* ping as fast as possible */
#define PING_CISCO	2	/* ping Cisco-style */

int pingmode = PING_NORMAL;	/* how to ping */
bool multihost = FALSE;		/* set if multi-target mode specified */

/*
 * Command line flags.
 */

int verbose = 0;		/* -v  print additional information */
bool quiet = FALSE;		/* -q  don't print markers, only summary */
bool quick = FALSE;		/* -Q  don't print summary, quit if alive */
bool alladdr = FALSE;		/* -a  probe all addresses of target host */
bool numeric = FALSE;		/* -n  print IP address as dotted quad */
bool fastping = FALSE;		/* -F  next ping immediately upon response */
bool printmiss = FALSE;		/* -m  print summary of missed responses */
bool traceroute = FALSE;	/* -R  enable packet route recording */
bool looseroute = FALSE;	/* -L  enable loose source routing */

/*
 * Command line parameters.
 */

int timeout = DEF_TIMEOUT;	/* -t  timeout between packets (secs) */
int delay = DEF_DELAY;		/* -w  delay in flood mode (millisecs) */
int netbits = 0;		/* -b  number of bits for network mask */
int preload = 0;		/* -p  number of packets to "preload" */
int filldata = 0;		/* -D  pattern for data packet specified */
int datalen = DATALEN;		/* -l  size of probe packet */
int packetcount = 0;		/* -k  maximum number of packets to send */

/*
 * Description of target host.
 */

char hostnamebuf[MAXDNAME+1];
char *hostname;			/* target host name */

#define MAXADDRS	35	/* max address count from gethostnamadr.c */

ipaddr_t hostaddr[MAXADDRS];	/* multiple destination addresses */
int naddrs = 0;			/* count of destination addresses */

/*
 * Internal control variables.
 */

jmp_buf ping_buf;		/* to restart */
bool timing = TRUE;		/* set if packet contains timing info */
bool gotone = FALSE;		/* set if we got a valid reponse */
bool flushing = FALSE;		/* set if shutdown initiated */
bool broadcast = FALSE;		/* set if broadcast address specified */
int column = 0;			/* column number for cisco pings */
int ident = 0;			/* packet identifier */
int ntransmitted = 0;		/* total number of packets transmitted */
int npackets = 0;		/* maximum number of packets to send */
int request = ICMP_ECHO;	/* outbound icmp request type */
int reply = ICMP_ECHOREPLY;	/* expected inbound reply type */

/*
 * Gateway addresses for loose source routing.
 */

#define MAXIPOPT	9	/* MAX_IPOPTLEN-IPOPT_MINOFF / INADDRSZ */
#define MAXLSRR (MAXIPOPT-1)	/* leave room for destination address */

ipaddr_t lsrraddr[MAXLSRR];	/* loose source route addresses */
int nlsrr = 0;			/* count of loose source route addresses */

#define MAXGATE (MAXLSRR*MAXADDRS)

ipaddr_t gateaddr[MAXGATE];	/* all known gateway addresses */
int ngate = 0;			/* count of all known gateway addresses */

/*
 * BITMAPSIZE is the number of bits in received bitmap, i.e. the
 * maximum number of received sequence numbers we can keep track of.
 * Use 2048 for complete accuracy -- sequence numbers are 16 bits.
 */

#define WORDSIZE	(8 * sizeof(u_int))
#define BITMAPSIZE	(WORDSIZE * 2048)

u_int rcvd_bitmap[BITMAPSIZE / WORDSIZE];
u_int fail_bitmap[BITMAPSIZE / WORDSIZE];

#define MAPBIT(bit)	((bit) % BITMAPSIZE)		/* bit in bitmap */
#define MAPWORD(bit)	(MAPBIT(bit) / WORDSIZE)	/* word in bitmap */
#define WORDBIT(bit)	(1 << (MAPBIT(bit) % WORDSIZE))	/* bit in word */

#define SET(bit, map)	(map)[MAPWORD(bit)] |= WORDBIT(bit)
#define CLR(bit, map)	(map)[MAPWORD(bit)] &= ~WORDBIT(bit)
#define TST(bit, map)	(((map)[MAPWORD(bit)] & WORDBIT(bit)) != 0)

#define SETRCVD(bit)	SET(bit, rcvd_bitmap)
#define CLRRCVD(bit)	CLR(bit, rcvd_bitmap)
#define TSTRCVD(bit)	TST(bit, rcvd_bitmap)

#define SETFAIL(bit)	SET(bit, fail_bitmap)
#define CLRFAIL(bit)	CLR(bit, fail_bitmap)
#define TSTFAIL(bit)	TST(bit, fail_bitmap)

/*
 * Structure for statistics on counts and round-trip times.
 */

typedef struct _stats {
	int rcvd;			/* number of valid replies */
	int dupl;			/* number of duplicate replies */
	int fail;			/* number of bounced requests */
	time_t rttmin;			/* minimum round-trip time */
	time_t rttmax;			/* maximum round-trip time */
	double rttsum;			/* sum of recorded rtt values */
	double rttssq;			/* sum of squared  rtt values */
} stats;

#define MAXSECS		2146	/* 2147,483,647 usec */

#define VERY_LONG	((time_t)MAXSECS*1000000)

stats pings = { 0, 0, 0, VERY_LONG, 0, 0.0, 0.0 };

/*
 * Structure for host info in broadcast mode.
 */

typedef struct _hostinfo {
	struct _hostinfo *next;		/* next in chain */
	struct _stats stats;		/* host statistics */
	struct in_addr inaddr;		/* IP address */
} hostinfo;

hostinfo *hostchain = NULL;	/* chain of recorded hosts */

/*
 * Structure for storing responses for a specific route.
 */

typedef struct _optstr {
	struct _optstr *next;		/* next in chain */
	struct _stats stats;		/* routing statistics */
	u_char ipopt[MAX_IPOPTLEN];	/* routing options */
	int ipoptlen;			/* actual size of options */
} optstr;

optstr *optchain = NULL;	/* chain of recorded routes */

/*
 * Miscellaneous definitions.
 */

#define NOT_DOTTED_QUAD	((ipaddr_t)-1)

#define	RCVBUF	(48*1024)	/* size of receive buffer to specify */
#define	MAXWAIT	5		/* max secs to wait for final response */
#define STDOUT	1		/* stdout file descriptor */

/*
 * Useful inline functions.
 */

#include "defs.h"	/* declaration of functions */

#define superuser()	(getuid() == 0)
#define sameaddr(a,b)	((a)->sin_addr.s_addr == (b)->sin_addr.s_addr)
#define bitset(bit, w)	(((w) & (bit)) != 0)
#define plural(n)	(((n) == 1) ? "" : "s")
#define strlength(s)	(int)strlen(s)
#define setalarm(n)	(void) alarm((unsigned int)(n))

#define is_xdigit(c)	(isascii(c) && isxdigit(c))
#define is_space(c)	(isascii(c) && isspace(c))
#define is_digit(c)	(isascii(c) && isdigit(c))
#define is_upper(c)	(isascii(c) && isupper(c))
#define is_lower(c)	(isascii(c) && islower(c))

#define	atox(c)		(is_digit(c) ? ((c) - '0')      : \
			(is_upper(c) ? ((c) - 'A' + 10) : \
			(is_lower(c) ? ((c) - 'a' + 10) : 0)))

#define newlist(a,n,t)	(t *)xalloc((ptr_t *)(a), (siz_t)((n)*sizeof(t)))
#define newstruct(t)	(t *)xalloc((ptr_t *)NULL, (siz_t)(sizeof(t)))
#define newstring(s)	(char *)xalloc((ptr_t *)NULL, (siz_t)(strlen(s)+1))
#define newstr(s)	strcpy(newstring(s), s)
#define xfree(a)	(void) free((ptr_t *)(a))

#ifdef DEBUG
#define assert(condition)\
{\
	if (!(condition))\
	{\
		(void) fprintf(stderr, "assertion botch: ");\
		(void) fprintf(stderr, "%s(%d): ", __FILE__, __LINE__);\
		(void) fprintf(stderr, "%s\n", "condition");\
		exit(EX_SOFTWARE);\
	}\
}
#else
#define assert(condition)
#endif

static char Usage[] =
"\
Usage:   %s [options] host [length [count]]\n\
Flags:   [-c|-f] [-F] [-Q] [-LR] [-a] [-mnqv] [-dr]\n\
Options: [-l length] [-k count] [-p preload] [-D pattern]\n\
Options: [-b netbits] [-g gateway] [-t timeout]\
";

/*
** MAIN -- Start of program ping
** -----------------------------
**
**	Normal exits are via finish(), when the maximum packet count
**	is exhausted or when terminated with an interrupt.
**	Premature exits occur when abnormal conditions are detected.
**
**	Exit status:
**		Various possibilities from <sysexits.h> among which
**		EX_SUCCESS	At least one valid response received
**		EX_UNAVAILABLE	In case there were none
**		EX_NOHOST	Could not lookup explicit host
**		EX_OSERR	Could not obtain resources
**		EX_USAGE	Improper parameter/option specified
*/

int
main(argc, argv)
int argc;
char *argv[];
{
	register char *option;
	register char *cp;
	register int i;
	bool got_there = FALSE;		/* set if some address was reached */
	char *program;			/* name that ping was called with */
	ipaddr_t addr;
	struct in_addr inaddr;
	struct hostent *hp;
	u_char *pattern = &opacket[HDRLEN+TIMLEN];

	assert(sizeof(u_int) >= 4);	/* probably paranoid */
#ifdef obsolete
	assert(sizeof(u_short) == 2);	/* perhaps less paranoid */
	assert(sizeof(ipaddr_t) == 4);	/* but this is critical */
#endif /*obsolete*/

/*
 * Synchronize stdout and stderr in case output is redirected.
 */
	linebufmode(stdout);

/*
 * Initialize resolver. Shorter timeout values are set later.
 */
	(void) res_init();

/*
 * Scan command line options and flags.
 * Interpolate default options and parameters.
 */
	if (argc < 1 || argv[0] == NULL)
		exit(EX_USAGE);

	option = getenv("PING_DEFAULTS");
	if (option != NULL)
	{
		set_defaults(option, argc, argv);
		argc = optargc; argv = optargv;
	}

	program = rindex(argv[0], '/');
	if (program++ == NULL)
		program = argv[0];

	while (argc > 1 && argv[1] != NULL && argv[1][0] == '-')
	{
	    for (option = &argv[1][1]; *option != '\0'; option++)
	    {
		switch (*option)
		{
		    case 'a':
			/* probe all of multiple addresses */
			alladdr = TRUE;
			break;

		    case 'b':
			/* number of bits in netmask */
			netbits = getval(argv[2], "netmask bitcount", 1, 31);
			argv++; argc--;
			break;

		    case 'c':
			/* cisco style pings */
			if (pingmode == PING_FLOOD)
				fatal("Conflicting options -c and -f");
			pingmode = PING_CISCO;
			break;

		    case 'D':
			/* specify fill data */
			if (argv[2] == NULL || argv[2][0] == '-')
				fatal("Missing pattern data");
			for (cp = argv[2]; *cp != '\0'; cp += 2)
			{
				u_char pat;

				if (!is_xdigit(cp[0]) || !is_xdigit(cp[1]))
					fatal("Invalid hex data %s", argv[2]);
				if (filldata >= MAXDATA)
					fatal("Too much fill data specified");
				pat = (atox(cp[0]) << 4) | atox(cp[1]);
				pattern[filldata++] = pat;
			}
			argv++; argc--;
			break;

		    case 'd':
			/* socket debugging */
			sockopts |= SO_DEBUG;
			break;

		    case 'F':
			/* no delay between pings */
			fastping = TRUE;
			break;

		    case 'f':
			/* flood pings */
			if (pingmode == PING_CISCO)
				fatal("Conflicting options -f and -c");
			pingmode = PING_FLOOD;
			break;

		    case 'g':
			/* loose source route gateway address */
			if (argv[2] == NULL || argv[2][0] == '-')
				fatal("Missing gateway name");
			if (nlsrr >= MAXLSRR)
				fatal("Maximum %s gateways", itoa(MAXLSRR));
			lsrraddr[nlsrr++] = getgate(argv[2]);
			argc--, argv++;
			/*FALLTHROUGH*/

		    case 'L':
			/* loose source route */
			looseroute = TRUE;
			break;

		    case 'k':
			/* packet count */
			packetcount = getval(argv[2], "packet count", preload, 0);
			argv++; argc--;
			break;

		    case 'l':
			/* packet data length */
			datalen = getval(argv[2], "packet length", 0, MAXPKT-HDRLEN);
			argv++; argc--;
			break;

		    case 'm':
			/* show missing response stats */
			printmiss = TRUE;
			break;

		    case 'n':
			/* numeric IP addresses only */
			numeric = TRUE;
			break;

		    case 'p':
			/* number of packets to preload */
			preload = getval(argv[2], "preload count", 0, packetcount);
			argv++; argc--;
			break;

		    case 'Q':
			/* don't print summary */
			quick = TRUE;
			/*FALLTHROUGH*/

		    case 'q':
			/* don't print markers */
			quiet = TRUE;
			break;

		    case 'R':
			/* record route */
			traceroute = TRUE;
			break;

		    case 'r':
			/* don't use routing table */
			sockopts |= SO_DONTROUTE;
			break;

		    case 's':
			/* compat with older versions */
			break;

		    case 't':
			/* timeout (secs) between pings */
			timeout = getval(argv[2], "timeout (secs)", 1, MAXSECS);
			argv++; argc--;
			break;

		    case 'v':
			/* increment verbosity level */
			verbose++;
			break;

		    case 'w':
			/* delay (msec) for flood mode */
			delay = getval(argv[2], "delay (msec)", 1, MAXSECS*1000);
			argv++; argc--;
			break;

		    case 'x':
			/* special multi-target mode */
			multihost = TRUE;
			break;

		    case 'V':
			/* just print version number */
			printf("Version %s\n", version);
			exit(EX_SUCCESS);

		    default:
			fatal(Usage, program);
			/*NOTREACHED*/
		}
	    }

	    argv++; argc--;
	}

/*
 * Special ping modes may have been restricted to the superuser.
 */
#ifdef RESTRICT_FLOOD

	if ((pingmode == PING_FLOOD) && !superuser())
		fatal("Must be root for flood ping option -f");

#endif

#ifdef RESTRICT_CISCO

	if ((pingmode == PING_CISCO) && !superuser())
		fatal("Must be root for cisco ping option -c");

#endif

#ifdef RESTRICT_FAST

	if (fastping && !superuser())
		fatal("Must be root for fast ping option -F");

#endif

/*
 * Check availability of special routing options.
 */
#ifdef IP_OPTIONS
#ifndef MULTIPLE_IP_OPTIONS

	if ((traceroute && looseroute) && !superuser())
		fatal("Conflicting options -R and -L");

#endif
#else /*IP_OPTIONS*/

	if (traceroute)
		error("record route not supported");
	if (looseroute)
		error("loose source route not supported");

#endif /*IP_OPTIONS*/

/*
 * Pickup our own address.
 */
	if (gethostname(hostnamebuf, MAXDNAME) < 0)
	{
		perror("gethostname");
		exit(EX_OSERR);
	}
	hostnamebuf[MAXDNAME] = '\0';

	hp = gethostbyname(hostnamebuf);
	if (hp == NULL)
	{
		error("Cannot find own name %s", hostnamebuf);
		exit(EX_NOHOST);
	}

	/* prep the address cache */
	bcopy(hp->h_addr, (char *)&inaddr, INADDRSZ);
	(void) maphostbyaddr(inaddr);

	/* setup ip address */
	bzero((char *)&myaddr, sizeof(myaddr));
	me->sin_family = AF_INET;
	me->sin_addr = inaddr;
	me->sin_port = 0;

/*
 * Setup for special multi-target mode.
 * All remaining arguments are potential host names or addresses.
 * If none are given, they come from stdin. Unknown hosts are skipped.
 */
	if (multihost)
	{
		/* fetch target addresses */
		get_targets(argc, argv);

		/* not yet supported */
		exit(EX_USAGE);
	}

/*
 * Setup for traditional ping mode.
 * Fetch (mandatory) remote host address(es) to probe.
 * This host must exist, if given by name.
 */
	if (argc < 2 || argv[1] == NULL)
		fatal(Usage, program);

	hostname = argv[1];
	addr = inet_addr(hostname);
	inaddr.s_addr = addr;

	if (addr == NOT_DOTTED_QUAD)
	{
		hp = gethostbyname(hostname);
		if (hp == NULL)
		{
			error("Unknown host %s", hostname);
			exit(EX_NOHOST);
		}

		hostname = strncpy(hostnamebuf, hp->h_name, MAXDNAME);
		hostname[MAXDNAME] = '\0';

		for (i = 0; i < MAXADDRS && hp->h_addr_list[i]; i++)
		{
			bcopy(hp->h_addr_list[i], (char *)&inaddr, INADDRSZ);
			hostaddr[i] = inaddr.s_addr;
		}
		naddrs = i;

		/* prep the address cache */
		for (i = 0; i < naddrs; i++)
		{
			inaddr.s_addr = hostaddr[i];
			(void) maphostbyaddr(inaddr);
		}
	}
	else
	{
		hostname = strcpy(hostnamebuf, inetname(inaddr));

		hostaddr[0] = addr;
		naddrs = 1;
	}

/*
 * Scan remaining optional command line arguments.
 */
	/* data length is packet size minus header length */
	if (argc > 2 && argv[2] != NULL)
		datalen = getval(argv[2], "packet length", 0, MAXPKT-HDRLEN);

	/* maximum number of packets */
	if (argc > 3 && argv[3] != NULL)
		packetcount = getval(argv[3], "packet count", preload, 0);

	/* rest is undefined */
	if (argc > 4)
		fatal(Usage, program);

/*
 * Miscellaneous initialization.
 */
	/* our packet identifier */
	ident = getpid() & 0xFFFF;

	/* set shorter nameserver timeout */
	_res.retry = DEF_RETRIES;	/* number of datagram retries */
	_res.retrans = DEF_RETRANS;	/* timeout between retries */

#ifdef IP_OPTIONS
	/* here we route our own reply packet */
	if (looseroute && (nlsrr == 0))
		request = ICMP_ECHOREPLY;
#endif /*IP_OPTIONS*/

	/* can do timing only if packet big enough */
	timing = (datalen >= TIMLEN) ? TRUE : FALSE;

	/* stuff data portion of output packet */
	if (filldata)
	{
		/* pattern specified -- replicate to fill buffer */
		for (i = 0; i < MAXDATA - filldata; i++)
			pattern[filldata+i] = pattern[i];
	}
	else
	{
		/* no pattern specified -- fill with position info */
		for (i = 0; i < MAXDATA; i++)
			pattern[i] = TIMLEN + i;
	}

	/* set current window size */
	if ((pingmode == PING_CISCO) && isatty(STDOUT))
		(void) setwindow(0);

#ifdef OMNINET
	/* initialize network device for route recording to work */
	if (traceroute)
		(void) initdevice(OMNINET);
#endif /*OMNINET*/

	/* allocate and configure raw icmp socket */
	check_proto();
	get_socket();

/*
 * All set. Start off.
 */
	/* don't need special privileges any more */
	(void) setuid(getuid());

	/* show data portion of output packet */
	if (filldata && (datalen > TIMLEN))
	{
		if (!quiet)
		{
			printf("PATTERN: ");
			for (i = 0; i < filldata; i++)
				printf("%02x", pattern[i] & 0xFF);
			printf("\n");
		}
	}

	/* probe all addresses successively */
	for (i = 0; i < naddrs; i++)
	{
		if (setjmp(ping_buf) == 0)
		{
			ping(hostaddr[i], i);
			/*NOTREACHED*/
		}

		if (pings.rcvd > 0)
			got_there = TRUE;

		if (!alladdr)
			break;
	}

	/* indicate success or failure */
	exit(got_there ? EX_SUCCESS : EX_UNAVAILABLE);
	/*NOTREACHED*/
}

/*
** SET_DEFAULTS -- Interpolate default options and parameters in argv
** ------------------------------------------------------------------
**
**	The PING_DEFAULTS env variable gives customized options.
**
**	Returns:
**		None.
**
**	Outputs:
**		Creates ``optargv'' vector with ``optargc'' arguments.
*/

void
set_defaults(option, argc, argv)
char *option;				/* option string */
int argc;				/* original command line arg count */
char *argv[];				/* original command line arguments */
{
	register char *p, *q;
	register int i;

/*
 * Allocate new argument vector.
 */
	optargv = newlist(NULL, 2, char *);
	optargv[0] = argv[0];
	optargc = 1;

/*
 * Construct argument list from option string.
 */
	for (q = "", p = newstr(option); *p != '\0'; p = q)
	{
		while (is_space(*p))
			p++;

		if (*p == '\0')
			break;

		for (q = p; *q != '\0' && !is_space(*q); q++)
			continue;

		if (*q != '\0')
			*q++ = '\0';

		optargv = newlist(optargv, optargc+2, char *);
		optargv[optargc] = p;
		optargc++;
	}

/*
 * Append command line arguments.
 */
	for (i = 1; i < argc && argv[i] != NULL; i++)
	{
		optargv = newlist(optargv, optargc+2, char *);
		optargv[optargc] = argv[i];
		optargc++;
	}

	/* and terminate */
	optargv[optargc] = NULL;
}

/*
** GETVAL -- Decode parameter value and perform range check
** --------------------------------------------------------
**
**	Returns:
**		Parameter value if successfully decoded.
**		Aborts in case of syntax or range errors.
*/

int
getval(optstring, optname, minvalue, maxvalue)
char *optstring;			/* parameter from command line */
char *optname;				/* descriptive name of option */
int minvalue;				/* minimum value for option */
int maxvalue;				/* maximum value for option */
{
	register int optvalue;

	if (optstring == NULL || optstring[0] == '-')
		fatal("Missing %s", optname);

	optvalue = atoi(optstring);

	if (optvalue == 0 && optstring[0] != '0')
		fatal("Invalid %s %s", optname, optstring);

	if (optvalue < minvalue)
		fatal("Minimum %s %s", optname, itoa(minvalue));

	if (maxvalue > 0 && optvalue > maxvalue)
		fatal("Maximum %s %s", optname, itoa(maxvalue));

	return(optvalue);
}

/*
** FATAL -- Abort program when illegal option encountered
** ------------------------------------------------------
**
**	Returns:
**		Aborts after issuing error message.
*/

void /*VARARGS1*/
fatal(fmt, a, b, c, d)
char *fmt;				/* format of message */
char *a, *b, *c, *d;			/* optional arguments */
{
	(void) fprintf(stderr, fmt, a, b, c, d);
	(void) fprintf(stderr, "\n");
	exit(EX_USAGE);
}


/*
** ERROR -- Issue error message to error output
** --------------------------------------------
**
**	Returns:
**		None.
*/

void /*VARARGS1*/
error(fmt, a, b, c, d)
char *fmt;				/* format of message */
char *a, *b, *c, *d;			/* optional arguments */
{
	(void) fprintf(stderr, fmt, a, b, c, d);
	(void) fprintf(stderr, "\n");
}

/*
** CHECK_PROTO -- Check protocol numbers
** -------------------------------------
**
**	ping uses protocol numbers as defined in <netinet/in.h>.
**	Verify whether they correspond to the values in /etc/protocols.
**	This is probably rather paranoid.
*/

void
check_proto()
{
	struct protoent *proto;

	proto = getprotobyname("ip");
	if (proto == NULL)
	{
		(void) fprintf(stderr, "ip: unknown protocol\n");
		exit(EX_OSFILE);
	}
	if (proto->p_proto != IPPROTO_IP)
	{
		(void) fprintf(stderr, "ip protocol %d should be %d\n",
			proto->p_proto, IPPROTO_IP);
		exit(EX_CONFIG);
	}

	proto = getprotobyname("icmp");
	if (proto == NULL)
	{
		(void) fprintf(stderr, "icmp: unknown protocol\n");
		exit(EX_OSFILE);
	}
	if (proto->p_proto != IPPROTO_ICMP)
	{
		(void) fprintf(stderr, "icmp protocol %d should be %d\n",
			proto->p_proto, IPPROTO_ICMP);
		exit(EX_CONFIG);
	}

	proto = getprotobyname("tcp");
	if (proto == NULL)
	{
		(void) fprintf(stderr, "tcp: unknown protocol\n");
		exit(EX_OSFILE);
	}
	if (proto->p_proto != IPPROTO_TCP)
	{
		(void) fprintf(stderr, "tcp protocol %d should be %d\n",
			proto->p_proto, IPPROTO_TCP);
		exit(EX_CONFIG);
	}

	proto = getprotobyname("udp");
	if (proto == NULL)
	{
		(void) fprintf(stderr, "udp: unknown protocol\n");
		exit(EX_OSFILE);
	}
	if (proto->p_proto != IPPROTO_UDP)
	{
		(void) fprintf(stderr, "udp protocol %d should be %d\n",
			proto->p_proto, IPPROTO_UDP);
		exit(EX_CONFIG);
	}
}

/*
** GET_SOCKET -- Allocate and configure socket
** -------------------------------------------
**
**	A raw icmp socket is allocated. This can be done only by root.
**	Extra socket options are set as requested on the command line.
*/

void
get_socket()
{
	int on = 1;
	int rcvbuf = RCVBUF;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0)
	{
		perror("icmp socket");
		exit(EX_OSERR);
	}

	if (bitset(SO_DEBUG, sockopts))
	{
		if (setsockopt(sock, SOL_SOCKET, SO_DEBUG,
			(char *)&on, sizeof(on)) < 0)
		{
			perror("setsockopt: SO_DEBUG");
			exit(EX_OSERR);
		}
	}

	if (bitset(SO_DONTROUTE, sockopts))
	{
		if (setsockopt(sock, SOL_SOCKET, SO_DONTROUTE,
			(char *)&on, sizeof(on)) < 0)
		{
			perror("setsockopt: SO_DONTROUTE");
			exit(EX_OSERR);
		}
	}

#ifdef SO_RCVBUF
	{
		if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
			(char *)&rcvbuf, sizeof(rcvbuf)) < 0)
		{
			perror("setsockopt: SO_RCVBUF");
			exit(EX_OSERR);
		}
	}
#endif /*SO_RCVBUF*/
}

/*
** SET_OPTIONS -- Initialize IP options
** ------------------------------------
**
**	Special IP options are setup as requested on the command line.
**	This will extend the IP header with the IP options buffer.
**	Not all platforms may support this, even if IP_OPTIONS exists.
**
**	See the special note in conf.h about MULTIPLE_IP_OPTIONS.
*/

#ifdef IP_OPTIONS

void
set_options()
{
	u_char ipoptbuf[MAX_IPOPTLEN];	/* ip options buffer */
	u_char *ipopt = ipoptbuf;	/* current index */
	register int i;

	/* clear the entire options buffer */
	bzero((char *)ipoptbuf, sizeof(ipoptbuf));

/*
 * Start with loose source route via gateways to the target host.
 */
	if (looseroute && (nlsrr > 0))
	{
		ipopt[IPOPT_OPTVAL] = IPOPT_NOP;
		ipopt++;

		ipopt[IPOPT_OPTVAL] = IPOPT_LSRR;
		ipopt[IPOPT_OLEN]   = IPOPT_HDRLEN + (nlsrr + 1)*INADDRSZ;
		ipopt[IPOPT_OFFSET] = IPOPT_MINOFF;
		ipopt += IPOPT_HDRLEN;

		/* store intermediate gateway addresses */
		for (i = 0; i < nlsrr; i++)
		{
			struct in_addr inaddr;

			inaddr.s_addr = lsrraddr[i];
			bcopy((char *)&inaddr, (char *)ipopt, INADDRSZ);
			ipopt += INADDRSZ;
		}

		/* and the final destination */
		bcopy((char *)&to->sin_addr, (char *)ipopt, INADDRSZ);
		ipopt += INADDRSZ;
	}

/*
 * Alternatively loose source to the target back to ourselves.
 */
	if (looseroute && (nlsrr == 0))
	{
		ipopt[IPOPT_OPTVAL] = IPOPT_NOP;
		ipopt++;

		ipopt[IPOPT_OPTVAL] = IPOPT_LSRR;
		ipopt[IPOPT_OLEN]   = IPOPT_HDRLEN + 2*INADDRSZ;
		ipopt[IPOPT_OFFSET] = IPOPT_MINOFF;
		ipopt += IPOPT_HDRLEN;

		bcopy((char *)&to->sin_addr, (char *)ipopt, INADDRSZ);
		ipopt += INADDRSZ;
		bcopy((char *)&me->sin_addr, (char *)ipopt, INADDRSZ);
		ipopt += INADDRSZ;
	}

/*
 * Use remainder for route recording (if there is space available).
 */
	if (traceroute && (nlsrr < MAXLSRR))
	{
		ipopt[IPOPT_OPTVAL] = IPOPT_NOP;
		ipopt++;

		ipopt[IPOPT_OPTVAL] = IPOPT_RR;
		ipopt[IPOPT_OLEN]   = MAX_IPOPTLEN - (ipopt-ipoptbuf);
		ipopt[IPOPT_OFFSET] = IPOPT_MINOFF;
	}

/*
 * Request use of IP options.
 */
	if (setsockopt(sock, IPPROTO_IP, IP_OPTIONS,
		(char *)ipoptbuf, sizeof(ipoptbuf)) < 0)
	{
		perror("setsockopt: IP_OPTIONS");
		exit(EX_OSERR);
	}
}

#endif /*IP_OPTIONS*/

/*
** PING -- Main loop of ping
** -------------------------
**
**	This is the core module of the program. Initialization is done.
**	Start pinging according to the requested mode.
*/

void
ping(addr, pass)
ipaddr_t addr;				/* address of destination */
int pass;				/* pass number */
{
	register int i;
	int cc;

	/* setup ip address */
	bzero((char *)&toaddr, sizeof(toaddr));
	to->sin_family = AF_INET;
	to->sin_addr.s_addr = addr;
	to->sin_port = 0;

	/* special handling for broadcast address */
	broadcast = bcast_addr(to->sin_addr);

	/* this is one of the worst network killers ... */
	if (broadcast && (pingmode == PING_FLOOD) && !superuser())
		fatal("No flood ping to broadcast address");

#ifdef IP_OPTIONS
	/* set special ip options as necessary */
 	if (traceroute || looseroute)
		set_options();
#endif /*IP_OPTIONS*/

	/* initialize counters */
	clear_stats(&pings);
	ntransmitted = 0;
	npackets = packetcount;

	if (!quick)
	{
		printf("%sPING %s: %d data byte%s", (pass > 0) ? "\n" : "",
			pr_addr(to->sin_addr), datalen, plural(datalen));
		if (npackets > 0)
			printf(", %d packet%s", npackets, plural(npackets));
		if (broadcast)
			printf(", broadcast");
		printf("\n");
	}

	/* setup for first interrupt */
	(void) signal(SIGINT, prefinish);

	/* force proper mode */
	if (pingmode == PING_CISCO)
		fastping = TRUE;
	if (pingmode == PING_FLOOD)
		fastping = FALSE;

	/* enforce hard limit for consistency */
	if (npackets > 0 && preload > npackets)
		preload = npackets;

	/* fire off them quickies */
	for (i = 0; i < preload; i++)
		(void) send_ping(ntransmitted);

	/* start things going */
	if (pingmode != PING_FLOOD)
		(void) ping_alarm(0);

	for (;;)
	{
		/* send flood until reply comes in */
		if (pingmode == PING_FLOOD)
			(void) ping_alarm(0);

		/* wait for reply packet, or alarm */
		cc = recv_ping();

		/* process input packet */
		if (check_ping(ipacket, cc) >= 0)
			gotone = TRUE;

		/* terminate when alive or unreachable in quick mode */
		if (gotone && quick)
			npackets = ntransmitted;

		/* flush input queue in broadcast mode */
		if (broadcast)
			continue;

		/* terminate if we got enough */
		if (npackets > 0 && (pings.rcvd + pings.fail) >= npackets)
		{
			(void) finish(0);
			/*NOTREACHED*/
		}

		/* schedule immediate next event if necessary */
		if (gotone && fastping)
			(void) ping_alarm(0);
	}
	/*NOTREACHED*/
}

/*
** PING_ALARM -- Handle an alarm
** -----------------------------
**
**	This routine causes another PING to be transmitted, and
**	schedules another SIGALRM at the proper period from now.
**	The timeout period may be adjusted for slow links.
**	In flood mode, a flood of pings is transmitted at short
**	intervals. It returns as soon as a reponse is available.
**	Shutdown is initiated in all modes if appropriate.
** 
** 	Our sense of time will slowly skew (ie, packets will not
**	be launched exactly at 1-second intervals). This does not
**	affect the quality of the delay and loss statistics.
*/

sigtype_t
ping_alarm(sig)
int sig;				/* nonzero if this was an alarm */
{
	static int waittime = MAXWAIT;	/* timeout until alarm or shutdown */
	int sav_errno = errno;		/* save across interrupt */

/*
 * Issue warning if nothing was received within the timeout period.
 */
	if ((sig == SIGALRM) && !gotone)
	{
		if (!quiet)
		{
			if (pingmode == PING_CISCO)
			{
				c_put(".");
			}
			else if (pingmode == PING_NORMAL)
			{
				printf("no reply from %s within %d sec%s\n",
					hostname, waittime, plural(waittime));
			}
		}
	}

	/* reset for next try */
	gotone = FALSE;

/*
 * Retry until the specified packet limit is reached.
 */
resend:
	if (npackets == 0 || ntransmitted < npackets)
	{
		/* must send another packet */
		(void) send_ping(ntransmitted);

		if (pingmode == PING_FLOOD)
		{
			/* wait only a very short time */
			if (wait_ping(delay) == 0)
				goto resend;
		}
		else
		{
			/* adjust timeout for slow links */
			if (pings.rcvd > 0)
				waittime = pings.rttmax / 1000000;
			else
				waittime = 0;
			if (waittime < timeout)
				waittime = timeout;
			else
				waittime = waittime + 1;

			/* schedule next alarm */
			(void) signal(SIGALRM, ping_alarm);
			setalarm(waittime);
		}
	}
	else if (broadcast || ((pings.rcvd + pings.fail) < ntransmitted))
	{
		/* must pickup outstanding packets */
		flushing = TRUE;

		/* determine final timeout to shutdown */
		if (pingmode == PING_CISCO)
			waittime = timeout;
		else if (pings.rcvd > 0)
			waittime = timeout + (pings.rttmax / 1000000);
		else
			waittime = MAXWAIT;

		/* schedule shutdown */
		(void) signal(SIGALRM, finish);
		setalarm(waittime);
	}
	else
	{
		(void) finish(sig);
		/*NOTREACHED*/
	}

	/* restore state to avoid stale values */
	errno = sav_errno;

	sig_return(0);
}

/*
** SEND_PING -- Send a ping packet
** -------------------------------
**
**	Compose and transmit an ICMP ECHO request packet. The IP packet
**	will be added on by the kernel. The ID field is our UNIX process ID,
**	and the sequence number is an ascending integer. The first 8 bytes
**	of the data portion are used to hold a UNIX timeval struct in host
**	byte-order, to compute the round-trip time.
**
**	Returns:
**		Number of bytes sent.
**		-1 in case of errors.
*/

int
send_ping(seqnum)
int seqnum;				/* packet sequence number */
{
	struct icmp *icp;		/* icmp packet */
	struct timeval *sendtime;	/* time when transmitted */
	int len;			/* size of icmp output packet */
	int cc;				/* size actually transmitted */

/*
 * Construct the ping packet.
 */
	/* store current time in output packet */
	if (timing)
	{
		sendtime = (struct timeval *)&opacket[HDRLEN];
		(void) gettimeofday(sendtime, (struct timezone *)NULL);
	}

	/* total size of output packet */
	len = HDRLEN + datalen;

	/* construct icmp header */
	icp = (struct icmp *)opacket;
	icp->icmp_type  = request;
	icp->icmp_code  = 0;
	icp->icmp_cksum = 0;
	icp->icmp_id    = ident;
	icp->icmp_seq   = seqnum;

	/* compute checksum */
	icp->icmp_cksum = in_checksum((u_short *)icp, len);

	/* clear this packet in stats table */
	if (!multihost)
	{
		CLRRCVD(icp->icmp_seq);
		CLRFAIL(icp->icmp_seq);
	}

	/* update total packets sent */
	ntransmitted++;

/*
 * Transmit the ping packet.
 */
	cc = sendto(sock, (char *)opacket, len, 0, toaddr_sa, sizeof(toaddr));
	if (cc < 0 || cc != len)
	{
		if (!quiet && (pingmode != PING_NORMAL))
			(void) write(STDOUT, "\n", 1);
		if (cc < 0)
			perror("sendto");
		else
			error("sendto: truncated packet to %s: %s bytes",
				pr_addr(to->sin_addr), itoa(cc));
#ifdef EMSGSIZE
		/* message too long */
		if (errno == EMSGSIZE)
		{
			(void) close(sock);
			exit(EX_DATAERR);
		}
#endif /*EMSGSIZE*/

		/* don't retry in quick mode */
		if (quick && !multihost)
		{
			(void) close(sock);
			exit(EX_UNAVAILABLE);
		}

		/* failure */
		return(-1);
	}

	/* display marker if appropriate */
	if (!quiet)
	{
		if (pingmode == PING_FLOOD)
			(void) write(STDOUT, ".", 1);
	}

	/* successfully sent */
	return(cc);
}

/*
** RECV_PING -- Input a ping packet
** --------------------------------
**
**	Read a new input packet. Normally we wait here for the arrival
**	of a packet. We may be interrupted by an alarm if no packet
**	came in during the current timeout period. In flood ping mode
**	there are no alarms, and the arrival is indicated via select().
**
**	Returns:
**		The number of bytes in the input packet.
*/

int
recv_ping()
{
	int fromlen;			/* size of address buffer */
	int len;			/* size of input packet buffer */
	int cc;				/* size actually read */

restart:
	len = sizeof(ipacket);
	fromlen = sizeof(fromaddr);

	cc = recvfrom(sock, (char *)ipacket, len, 0, fromaddr_sa, &fromlen);
	if (cc <= 0)
	{
		/* shouldn't happen */
		if (cc == 0)
			errno = ECONNRESET;

		/* interrupt -- restart */
		if (errno == EINTR)
			goto restart;

		if (!quiet && (pingmode != PING_NORMAL))
			(void) write(STDOUT, "\n", 1);
		perror("recvfrom");

		(void) close(sock);
		exit(EX_OSERR);
	}

	/* successfully read */
	return(cc);
}

/*
** WAIT_PING -- Wait for a ping packet
** -----------------------------------
**
**	Wait for the arrival of a new input packet via select().
**	This is used only in flood ping mode. A very short timeout
**	is used, so that a new ping can be sent quickly.
**
**	Returns:
**		Nonzero if input is available.
**		Zero in case of timeout.
*/

int
wait_ping(millisecs)
int millisecs;				/* timeout value in millisecs */
{
	struct timeval timer;
	fd_set fds;
	int ready;

	timer.tv_sec  =  millisecs / 1000;
	timer.tv_usec = (millisecs % 1000) * 1000;

restart:
	/* FD_ZERO(&fds); */
	bzero((char *)&fds, sizeof(fds));
	FD_SET(sock, &fds);

	/* wait only a very short time */
	ready = select(FD_SETSIZE, &fds, (fd_set *)0, (fd_set *)0, &timer);
	if (ready < 0)
	{
		/* interrupt -- restart */
		if (errno == EINTR)
			goto restart;

		if (!quiet && (pingmode != PING_NORMAL))
			(void) write(STDOUT, "\n", 1);
		perror("select");

		(void) close(sock);
		exit(EX_OSERR);
	}

	/* indicate availability of packet */
	return(ready);
}

/*
** CHECK_PING -- Process incoming icmp packet
** ------------------------------------------
**
**	Print out the packet, if it came from us. This logic is necessary
**	because ALL readers of the ICMP socket get a copy of ALL ICMP packets
**	which arrive ('t is only fair). This permits multiple copies of this
**	program to be run without having intermingled output (or statistics!).
**
**	Returns:
**		Seq number if this is a valid response (or bounce) packet.
**		-1 otherwise.
*/

int
check_ping(buf, cc)
u_char *buf;				/* input packet */
int cc;					/* size of input packet */
{
	struct icmp *icp;		/* start of icmp packet */
	struct ip *ip;			/* start of ip packet */
	int iphdrlen;			/* ip header length of input packet */
	struct timeval tv;		/* elapsed time */
	struct timeval *recvtime;	/* time input packet is received */
	struct timeval *sendtime;	/* time as stored in icmp packet */
	time_t rtt = 0;			/* round-trip time in microsecs */
	bool duplicate;			/* set if this is a duplicate reply */

	/* pickup current time */
	if (timing)
	{
		recvtime = &tv;
		(void) gettimeofday(recvtime, (struct timezone *)NULL);
	}

/*
 * The input packet contains the ip header in front of the icmp packet.
 * Make sure the packet contains the icmp header after the ip header.
 */
	ip = (struct ip *)buf;
	iphdrlen = ip->ip_hl << 2;

	if (ip->ip_p != IPPROTO_ICMP)
	{
		if (verbose)
		{
			printf("\n%d bytes from %s: (not icmp)\n",
				cc, pr_addr(from->sin_addr));

			/* dump the ip packet */
			print_ippkt(ip, cc);
		}
		return(-1);
	}

	if (cc < iphdrlen + ICMP_MINLEN)
	{
		if (verbose)
		{
			printf("\n%d bytes from %s: (too short)\n",
				cc, pr_addr(from->sin_addr));

			/* dump the ip packet */
			print_ippkt(ip, cc);
		}
		return(-1);
	}

	/* move to the icmp packet */
	icp = (struct icmp *)(buf + iphdrlen);
	cc -= iphdrlen;

/*
 * Check whether we got the expected reply type.
 * Explicit bounce messages are recognized as (failed) responses.
 */
	if (icp->icmp_type != reply)
	{
		if (verbose)
		{
			printf("\n%d bytes from %s: (wrong type) ",
				cc, pr_addr(from->sin_addr));

			/* dump the icmp packet */
			print_icmph(icp, cc);
		}
		return(check_fail(icp, cc));
	}

/*
 * Check whether it belongs to us.
 */
	if (icp->icmp_id != ident)
	{
		if (verbose)
		{
			printf("\n%d bytes from %s: (wrong ident) ",
				cc, pr_addr(from->sin_addr));

			/* dump the icmp packet */
			print_icmph(icp, cc);
		}
		return(-1);
	}

	/* XXX should compare the patterns to make sure the packets match */
	if (cc != HDRLEN + datalen)
	{
		if (verbose)
		{
			printf("\n%d bytes from %s: (wrong size) ",
				cc, pr_addr(from->sin_addr));

			/* dump the icmp packet */
			print_icmph(icp, cc);
		}
		return(-1);
	}

/*
 * Check for duplicate reply.
 */
	if (broadcast)
		duplicate = sameaddr(from, to);
	else
		duplicate = TSTRCVD(icp->icmp_seq);

	if (duplicate)
		pings.dupl++;
	else
		pings.rcvd++;

	if (!duplicate)
		SETRCVD(icp->icmp_seq);

/*
 * Compute round-trip time.
 */
	if (timing)
	{
		sendtime = (struct timeval *)icp->icmp_data;
		rtt = tvsub(recvtime, sendtime);
	}

	if (timing && !duplicate)
		record_stats(&pings, rtt);

/*
 * Keep track of responding hosts in broadcast mode.
 */
	if (broadcast)
		update_hosts(from->sin_addr, duplicate, rtt);

/*
 * Print appropriate reponse.
 */
	if (!quiet)
	{
		if (pingmode == PING_FLOOD)
		{
			if (duplicate)
				(void) write(STDOUT, "*", 1);
			else if (flushing)
				(void) write(STDOUT, "!", 1);
			else if (broadcast)
				(void) write(STDOUT, "!", 1);
			else
				(void) write(STDOUT, "\b!\b", 3);
		}
		else if (pingmode == PING_CISCO)
		{
			if (duplicate)
				c_put("*");
			else
				c_put("!");
		}
		else
		{
			printf("%d bytes from %s: seq=%d ttl=%d",
				cc, pr_addr(from->sin_addr),
				(int)icp->icmp_seq, (int)ip->ip_ttl);
			if (timing)
				printf(" time=%s ms", tvprint(rtt));
			if (duplicate)
				printf(", duplicate");
			printf(".\n");
		}
	}

/*
 * The ip options buffer may be present at the end of the ip header.
 */
#ifdef IP_OPTIONS
	if (iphdrlen > IPHDRSZ)
	{
		u_char *ipopt;		/* start of options buffer */
		int ipoptlen;		/* total size of options buffer */

		ipopt = (u_char *)ip + IPHDRSZ;
		ipoptlen = iphdrlen - IPHDRSZ;

		if ((traceroute || looseroute) && check_route(ipopt, ipoptlen))
			update_routes(ipopt, ipoptlen, duplicate, rtt);

		if (verbose > 1)
			print_options(ipopt, ipoptlen);
	}
#endif /*IP_OPTIONS*/

	/* return valid packet indication */
	return(!duplicate ? icp->icmp_seq : -1);
}

/*
** CHECK_FAIL -- Process explicit bounces to our requests
** ------------------------------------------------------
**
**	Determine whether we got an ICMP message which returns
**	our ping request because of some external error condition.
**
**	Returns:
**		Seq number if our request packet got bounced.
**		-1 otherwise.
*/

int
check_fail(buf, cc)
struct icmp *buf;			/* icmp packet buffer */
int cc;					/* size of icmp packet */
{
	struct icmp *icp = buf;		/* start of icmp packet */
	struct ip *ip;			/* start of ip packet */
	int iphdrlen;			/* total size of ip header */

/*
 * Only process ICMP messages that return an IP packet.
 */
	switch (icp->icmp_type)
	{
	    case ICMP_UNREACH:
	    case ICMP_SOURCEQUENCH:
	    case ICMP_REDIRECT:
	    case ICMP_TIMXCEED:
	    case ICMP_PARAMPROB:
		break;

	    default:
		/* not interesting */
		return(-1);
	}

/*
 * Examine the returned IP header.
 */
	/* ensure it is present */
	if (cc < ICMP_MINLEN + IPHDRSZ)
		return(-1);

	/* move to the returned ip packet */
	ip = (struct ip *)icp->icmp_data;
	iphdrlen = ip->ip_hl << 2;
	cc -= ICMP_MINLEN;

	/* it must contain an icmp message */
	if (ip->ip_p != IPPROTO_ICMP)
		return(-1);

	/* and must have been sent to our destination */
	if (!multihost && (ip->ip_dst.s_addr != to->sin_addr.s_addr))
		return(-1);

/*
 * Examine the returned ICMP header.
 */
	/* ensure it is present */
	if (cc < iphdrlen + ICMP_MINLEN)
		return(-1);

	/* move to the returned icmp packet */
	icp = (struct icmp *)((u_char *)ip + iphdrlen);
	cc -= iphdrlen;

	/* it must contain our request type */
	if (icp->icmp_type != request)
		return(-1);

	/* and must come from us */
	if (icp->icmp_id != ident)
		return(-1);

/*
 * This seems our original ping request that got bounced.
 */
	pings.fail++;

	SETFAIL(icp->icmp_seq);

	if (!quiet)
	{
		if (pingmode == PING_FLOOD)
		{
			if (flushing)
				(void) write(STDOUT, "#", 1);
			else if (broadcast)
				(void) write(STDOUT, "#", 1);
			else
				(void) write(STDOUT, "\b#\b", 3);
		}
		else if (pingmode == PING_CISCO)
		{
			c_put("#");
		}
		else
		{
			printf("packet seq=%d ", (int)icp->icmp_seq);
			if (multihost || (naddrs > 1))
				printf("to %s ", pr_addr(ip->ip_dst));
			printf("bounced at %s: ", pr_addr(from->sin_addr));
			print_icmph(buf, ICMP_MINLEN);
		}
	}

	/* return bounced packet indication */
	return(icp->icmp_seq);
}

/*
** PREFINISH -- Prepare for shutdown
** ---------------------------------
**
**	On the first SIGINT, allow any outstanding packets to dribble in.
**	In quick mode, or if nothing has been sent at all, we can finish.
**	If nothing has been received yet, we assume that we are dealing
**	with a dead target and we quit as well. In broadcast mode we are
**	always waiting for more to come.
*/

sigtype_t
prefinish(sig)
int sig;				/* nonzero on interrupt */
{
	int sav_errno = errno;		/* save across interrupt */

	/* quit now if nothing transmitted or none outstanding */
	if (quick || ntransmitted == 0 || (pings.rcvd + pings.fail) == 0 ||
	    (!broadcast && ((pings.rcvd + pings.fail) >= ntransmitted)))
	{
		(void) finish(sig);
		/*NOTREACHED*/
	}

	/* final shutdown on next interrupt */
	(void) signal(SIGINT, finish);

	/* let the normal limit work */
	npackets = ntransmitted;

	printf("\n---- Waiting for outstanding packets ----\n");
	column = 0;
	flushing = TRUE;

	/* restore state to avoid stale values */
	errno = sav_errno;

	sig_return(0);
}

/*
** FINISH -- Final postprocessing and cleanup
** ------------------------------------------
**
**	Print out statistics summary, and terminate.
*/

#define pr_host(a)	((naddrs > 1) ? pr_addr(a) : hostname)

sigtype_t
finish(sig)
int sig;				/* nonzero on interrupt */
{
/*
 * Reset state.
 */
	/* no more background action */
	(void) signal(SIGALRM, SIG_IGN);
	setalarm(0);

	/* and no more special interrupt handling */
	(void) signal(SIGINT, SIG_DFL);

/*
 * Show status if no statistics required.
 */
	if (quick)
	{
		if (sig == SIGINT)
			printf("\n");
		if (pings.rcvd > 0)
			printf("%s is alive\n", pr_host(to->sin_addr));
		else if (pings.fail > 0)
			printf("%s is unreachable\n", pr_host(to->sin_addr));
		else if (ntransmitted > 0)
			printf("no reply from %s\n", pr_host(to->sin_addr));

		/* and terminate */
		cleanup();
		/*NOTREACHED*/
	}

/*
 * Print general statistics.
 */
	printf("\n---- %s PING Statistics ----\n", pr_addr(to->sin_addr));
	printf("%d packet%s transmitted", ntransmitted, plural(ntransmitted));
	if (pings.fail > 0)
		printf(", %d packet%s bounced", pings.fail, plural(pings.fail));
	printf(", %d packet%s received", pings.rcvd, plural(pings.rcvd));
	if (pings.dupl > 0)
		printf(", %d duplicate%s", pings.dupl, plural(pings.dupl));
	if (broadcast)
		printf(", broadcast");
	else if (pings.rcvd > ntransmitted)
		printf(" -- somebody's printing up packets!");
	else if (ntransmitted > 0)
	{
		int missed = ntransmitted - pings.rcvd;
		double loss = 100 * (double)missed / (double)ntransmitted;

		if (pings.rcvd == 0)
			printf(", %d%% packet loss", 100);
		else
			printf(", %.2g%% packet loss", loss);
	}
	printf("\n");

/*
 * Print timing statistics, if appropriate.
 */
	if (timing)
		print_stats(&pings);

/*
 * Print responding hosts in broadcast mode.
 */
	if (broadcast)
		show_hosts();

/*
 * Print recorded routes, if available.
 */
#ifdef IP_OPTIONS
	if (traceroute || looseroute)
		show_routes();
#endif /*IP_OPTIONS*/

/*
 * Print missing responses (accurate only if we didn't wrap).
 */
	if (printmiss)
		show_missed();

/*
 * Final termination.
 */
	cleanup();
	/*NOTREACHED*/
}

/*
** CLEANUP -- Clean up and terminate
** ---------------------------------
**
**	Jump back for next pass, if any is needed.
**	Must first reset internal administration.
*/

void
cleanup()
{
	/* chain of recorded routes */
	if (optchain != NULL)
	{
		register optstr *p, *q;

		for (q = NULL, p = optchain; p != NULL; p = q)
		{
			q = p->next;
			xfree(p);
		}
		optchain = NULL;
	}

	/* chain of recorded hosts */
	if (hostchain != NULL)
	{
		register hostinfo *p, *q;

		for (q = NULL, p = hostchain; p != NULL; p = q)
		{
			q = p->next;
			xfree(p);
		}
		hostchain = NULL;
	}

	/* reset bitmap */
	bzero((char *)rcvd_bitmap, sizeof(rcvd_bitmap));
	bzero((char *)fail_bitmap, sizeof(fail_bitmap));

	/* miscellaneous */
	column = 0;
	flushing = FALSE;

	/* back to main loop */
	longjmp(ping_buf, 1);
	/*NOTREACHED*/
}

/*
** PRINT_ICMPH -- Print a descriptive string about an ICMP header
** --------------------------------------------------------------
*/

void
print_icmph(icp, cc)
struct icmp *icp;			/* icmp packet buffer */
int cc;					/* size of icmp packet */
{
	/* check basic type and subcode */
	switch (icp->icmp_type)
	{
	    case ICMP_ECHOREPLY:
		printf("Echo reply\n");
		/* XXX ID + Seq + Data */
		break;

	    case ICMP_UNREACH:
		switch (icp->icmp_code)
		{
		    case ICMP_UNREACH_NET:
			printf("Network unreachable\n");
			break;
		    case ICMP_UNREACH_HOST:
			printf("Host unreachable\n");
			break;
		    case ICMP_UNREACH_PROTOCOL:
			printf("Protocol unreachable\n");
			break;
		    case ICMP_UNREACH_PORT:
			printf("Port unreachable\n");
			break;
		    case ICMP_UNREACH_NEEDFRAG:
			printf("Frag needed and DF set\n");
			break;
		    case ICMP_UNREACH_SRCFAIL:
			printf("Source route failed\n");
			break;
		    case ICMP_UNREACH_NET_UNKNOWN:
			printf("Network unknown\n");
			break;
		    case ICMP_UNREACH_HOST_UNKNOWN:
			printf("Host unknown\n");
			break;
		    case ICMP_UNREACH_ISOLATED:
			printf("Source host isolated\n");
			break;
		    case ICMP_UNREACH_NET_PROHIB:
			printf("Network access prohibited\n");
			break;
		    case ICMP_UNREACH_HOST_PROHIB:
			printf("Host access prohibited\n");
			break;
		    case ICMP_UNREACH_TOSNET:
			printf("Network unreachable for TOS\n");
			break;
		    case ICMP_UNREACH_TOSHOST:
			printf("Host unreachable for TOS\n");
			break;
		    case ICMP_UNREACH_ADM_PROHIB:
			printf("Access prohibited\n");
			break;
		    case ICMP_UNREACH_PREC_VIOL:
			printf("Precedence violation\n");
			break;
		    case ICMP_UNREACH_PREC_CUT:
			printf("Precedence cutoff\n");
			break;
		    default:
			printf("Destination unreachable, unknown code %d\n", icp->icmp_code);
			break;
		}
		print_ippkt((struct ip *)icp->icmp_data, cc - ICMP_MINLEN);
		break;

	    case ICMP_SOURCEQUENCH:
		printf("Source quench\n");
		print_ippkt((struct ip *)icp->icmp_data, cc - ICMP_MINLEN);
		break;

	    case ICMP_REDIRECT:
		switch (icp->icmp_code)
		{
		    case ICMP_REDIRECT_NET:
			printf("Redirect network");
			break;
		    case ICMP_REDIRECT_HOST:
			printf("Redirect host");
			break;
		    case ICMP_REDIRECT_TOSNET:
			printf("Redirect TOS and network");
			break;
		    case ICMP_REDIRECT_TOSHOST:
			printf("Redirect TOS and host");
			break;
		    default:
			printf("Redirect, unknown code %d", icp->icmp_code);
			break;
		}
		printf(" (new: %s)\n", inet_ntoa(icp->icmp_gwaddr));
		print_ippkt((struct ip *)icp->icmp_data, cc - ICMP_MINLEN);
		break;

	    case ICMP_ECHO:
		printf("Echo request\n");
		/* XXX ID + Seq + Data */
		break;

	    case ICMP_ROUTERADVERT:
		printf("Router advertisement\n");
		break;

	    case ICMP_ROUTERSOLICIT:
		printf("Router solicitation\n");
		break;

	    case ICMP_TIMXCEED:
		switch (icp->icmp_code)
		{
		    case ICMP_TIMXCEED_INTRANS:
			printf("Time to live exceeded\n");
			break;
		    case ICMP_TIMXCEED_REASS:
			printf("Frag reassembly time exceeded\n");
			break;
		    default:
			printf("Time exceeded, unknown code %d\n", icp->icmp_code);
			break;
		}
		print_ippkt((struct ip *)icp->icmp_data, cc - ICMP_MINLEN);
		break;

	    case ICMP_PARAMPROB:
		printf("Parameter problem");
		printf(" (pointer: 0x%02x)\n", icp->icmp_pptr);
		print_ippkt((struct ip *)icp->icmp_data, cc - ICMP_MINLEN);
		break;

	    case ICMP_TSTAMP:
		printf("Timestamp request\n");
		/* XXX ID + Seq + 3 timestamps */
		break;

	    case ICMP_TSTAMPREPLY:
		printf("Timestamp reply\n");
		/* XXX ID + Seq + 3 timestamps */
		break;

	    case ICMP_IREQ:
		printf("Information request\n");
		/* XXX ID + Seq */
		break;

	    case ICMP_IREQREPLY:
		printf("Information reply\n");
		/* XXX ID + Seq */
		break;

	    case ICMP_MASKREQ:
		printf("Address mask request\n");
		break;

	    case ICMP_MASKREPLY:
		printf("Address mask reply\n");
		break;

	    default:
		printf("Unknown ICMP type %d\n", icp->icmp_type);
		break;
	}
}

/*
** PRINT_IPPKT -- Dump some info on a returned (via ICMP) IP packet
** ----------------------------------------------------------------
*/

void
print_ippkt(ip, cc)
struct ip *ip;				/* returned ip packet buffer */
int cc;					/* size of ip packet */
{
	int iphdrlen;			/* total size of ip header */
	struct tcphdr *tcp;		/* start of tcp packet */
	struct udphdr *udp;		/* start of udp packet */
	struct icmp *icp;		/* start of icmp packet */

	/* silently discard too short packets */
	if (cc < IPHDRSZ)
		return;
/*
 * Print ip header itself.
 */
	print_iphdr(ip, cc);

/*
 * Plus extra info for certain protocols.
 */
	iphdrlen = ip->ip_hl << 2;
	cc -= iphdrlen;

	if (ip->ip_p == IPPROTO_TCP && cc >= 2*INT16SZ)
	{
		tcp = (struct tcphdr *)((u_char *)ip + iphdrlen);
		printf("TCP: ");
		printf("from port %s", pr_port("tcp", tcp->th_sport));
		printf(", to port %s", pr_port("tcp", tcp->th_dport));
		printf("\n");
	}
	else if (ip->ip_p == IPPROTO_UDP && cc >= 2*INT16SZ)
	{
		udp = (struct udphdr *)((u_char *)ip + iphdrlen);
		printf("UDP: ");
		printf("from port %s", pr_port("udp", udp->uh_sport));
		printf(", to port %s", pr_port("udp", udp->uh_dport));
		printf("\n");
	}
	else if (ip->ip_p == IPPROTO_ICMP && cc >= ICMP_MINLEN)
	{
		icp = (struct icmp *)((u_char *)ip + iphdrlen);
		printf("ICMP: ");
		print_icmph(icp, cc);
	}
}

/*
** PRINT_IPHDR -- Print an IP header with options
** ----------------------------------------------
*/

void
print_iphdr(ip, cc)
struct ip *ip;				/* returned ip packet buffer */
int cc;					/* size of ip packet */
{
	int iphdrlen;			/* total size of ip header */

/*
 * Dump the ip header.
 */
	printf("VR HL TOS  LEN   ID FLG  OFF TTL PRO  CKS SRC             DST\n");
	printf("%2d %2d", ip->ip_v, ip->ip_hl);
	printf("  %02x",  ip->ip_tos);
	printf(" %4d",    (int)ip->ip_len);
	printf(" %04x",   ip->ip_id);
	printf("   %01x", ((ip->ip_off) & 0xE000) >> 13);
	printf(" %04x",   ((ip->ip_off) & 0x1FFF));
	printf(" %3d",    (int)ip->ip_ttl);
	printf(" %3d",    (int)ip->ip_p);
	printf(" %04x",   ip->ip_sum);
	printf(" %-15s",  inet_ntoa(ip->ip_src));
	printf(" %-15s",  inet_ntoa(ip->ip_dst));
	printf("\n");

/*
 * Dump option bytes.
 */
	iphdrlen = ip->ip_hl << 2;
	if (iphdrlen > IPHDRSZ && cc >= iphdrlen)
	{
		register int i;
		u_char *ipopt;		/* address of options buffer */
		int ipoptlen;		/* total size of options buffer */

		ipopt = (u_char *)ip + IPHDRSZ;
		ipoptlen = iphdrlen - IPHDRSZ;

		printf("IPOPT:");
		for (i = 0; i < ipoptlen; i++)
			printf(" %02x", ipopt[i]);
		printf("\n");
#ifdef IP_OPTIONS
		print_options(ipopt, ipoptlen);
#endif /*IP_OPTIONS*/
	}
}

/*
** PRINT_OPTIONS -- Print ip options data
** --------------------------------------
*/

#ifdef IP_OPTIONS

void
print_options(ipopt, ipoptlen)
u_char *ipopt;				/* address of options buffer */
int ipoptlen;				/* total size of options buffer */
{
	int optval;			/* option value */
	int optlen;			/* size of this option */

	while (ipoptlen > 0)
	{
		optval = ipopt[IPOPT_OPTVAL];
		optlen = ipopt[IPOPT_OLEN];

		switch (optval)
		{
		    case IPOPT_EOL:
			/* force end of options */
			optlen = 0;
			break;

		    case IPOPT_NOP:
			/* has no parameters */
			optlen = 1;
			break;

		    case IPOPT_RR:
			printf("<%s>\n", "recorded route");
			print_route(ipopt);
			break;

		    case IPOPT_LSRR:
			printf("<%s>\n", "loose source route");
			print_route(ipopt);
			break;

		    case IPOPT_SSRR:
			printf("<%s>\n", "strict source route");
			print_route(ipopt);
			break;

		    case IPOPT_TS:
			printf("<%s>\n", "time stamp");
			break;

		    case IPOPT_SECURITY:
			printf("<%s>\n", "security");
			break;

		    case IPOPT_SATID:
			printf("<%s>\n", "stream id");
			break;

		    default:
			printf("<option %d, length %d>\n", optval, optlen);
			break;
		}

		/* end of options encountered */
		if (optlen == 0)
			break;

		/* move to next option */
		ipopt += optlen;
		ipoptlen -= optlen;
	}
}

#endif /*IP_OPTIONS*/

/*
** PRINT_ROUTE -- Print ip route data
** ----------------------------------
*/

#ifdef IP_OPTIONS

void
print_route(ipopt)
u_char *ipopt;				/* start of current option */
{
	int optval;			/* option value */
	int optlen;			/* size of this option */
	u_char *optptr;			/* pointer to option data */
	int offset;			/* length of option data */

	optval = ipopt[IPOPT_OPTVAL];
	optlen = ipopt[IPOPT_OLEN];
	offset = ipopt[IPOPT_OFFSET];

	optptr = &ipopt[IPOPT_HDRLEN];
	optlen -= IPOPT_HDRLEN;

	while (offset > IPOPT_MINOFF)
	{
		struct in_addr inaddr;

		bcopy((char *)optptr, (char *)&inaddr, INADDRSZ);
		printf("\t%s\n", pr_addr(inaddr));

		optptr += INADDRSZ;
		offset -= INADDRSZ;
		optlen -= INADDRSZ;
	}

	/* buffer full -- perhaps route not complete */
	if (optval == IPOPT_RR && optlen == 0)
		printf("\t%s\n", "...");
}

#endif /*IP_OPTIONS*/

/*
** CHECK_ROUTE -- Check whether routing info is available
** ------------------------------------------------------
**
**	Returns:
**		TRUE if the options buffer contains any routing info.
**		FALSE otherwise.
*/

#ifdef IP_OPTIONS

bool
check_route(ipopt, ipoptlen)
u_char *ipopt;				/* address of options buffer */
int ipoptlen;				/* total size of options buffer */
{
	int optval;			/* option value */
	int optlen;			/* size of this option */

	while (ipoptlen > 0)
	{
		optval = ipopt[IPOPT_OPTVAL];
		optlen = ipopt[IPOPT_OLEN];

		switch (optval)
		{
		    case IPOPT_EOL:
			optlen = 0;
			break;

		    case IPOPT_NOP:
			optlen = 1;
			break;

		    case IPOPT_RR:
		    case IPOPT_LSRR:
		    case IPOPT_SSRR:
			return(TRUE);
		}

		if (optlen == 0)
			break;

		ipopt += optlen;
		ipoptlen -= optlen;
	}

	return(FALSE);
}

#endif /*IP_OPTIONS*/

/*
** PR_PORT -- Return a service port name
** -------------------------------------
**
**	Returns:
**		Pointer to static storage containing port name/number.
*/

char *
pr_port(protocol, port)
char *protocol;				/* the protocol used */
u_short port;				/* port number in network order */
{
	struct servent *service;
	static char buf[BUFSIZ];

	service = getservbyport((int)port, protocol);
	if (service != NULL)
		(void) sprintf(buf, "%s", service->s_name);
	else
		(void) sprintf(buf, "%d", (int)ntohs(port));

	return(buf);
}

/*
** PR_ADDR -- Return a host name and/or dotted quad
** ------------------------------------------------
**
**	Returns:
**		Pointer to static storage containing host/address string.
*/

char *
pr_addr(inaddr)
struct in_addr inaddr;			/* IP address */
{
	static char buf[MAXDNAME+19+1];
	register char *host;

	if (numeric || (inaddr.s_addr == INADDR_ANY))
		host = NULL;
	else
		host = maphostbyaddr(inaddr);

	if (host != NULL)
		(void) sprintf(buf, "%s (%s)", host, inet_ntoa(inaddr));
	else
		(void) sprintf(buf, "%s", inet_ntoa(inaddr));

	return(buf);
}

/*
** INETNAME -- Return a host name or dotted quad
** ---------------------------------------------
**
**	Returns:
**		Pointer to static storage containing host/address string.
*/

char *
inetname(inaddr)
struct in_addr inaddr;			/* IP address */
{
	static char buf[MAXDNAME+1];
	register char *host;

	if (numeric || (inaddr.s_addr == INADDR_ANY))
		host = NULL;
	else
		host = maphostbyaddr(inaddr);

	if (host != NULL)
		(void) strcpy(buf, host);
	else
		(void) strcpy(buf, inet_ntoa(inaddr));

	return(buf);
}

/*
** MAPHOSTBYADDR -- Map IP address to host name
** --------------------------------------------
**
**	Returns:
**		Pointer to string containing host name.
**		NULL if address could not be resolved.
**
**	The results are cached for subsequent retrieval.
*/

#define AHASHSIZE	0x2000
#define AHASHMASK	0x1fff

typedef struct addr_tab {
	ipaddr_t *addrlist;		/* list of IP addresses */
	char **namelist;		/* list of corresponding host names */
	int addrcount;			/* count of addresses on the list */
} addr_tab_t;

addr_tab_t addrtab[AHASHSIZE];		/* hash list of addresses and names */

char *
maphostbyaddr(inaddr)
struct in_addr inaddr;			/* IP address to map */
{
	ipaddr_t addr = inaddr.s_addr;	/* address in network order */
	register addr_tab_t *s;
	register char *host;
 	register int i;
	struct hostent *hp;

	/* in case no mapping is desired */
	if (numeric || (inaddr.s_addr == INADDR_ANY))
		return(NULL);

/*
 * Lookup the address in the appropriate hash list.
 */
	s = &addrtab[ntohl(addr) & AHASHMASK];

	for (i = 0; i < s->addrcount; i++)
		if (s->addrlist[i] == addr)
			return(s->namelist[i]);

/*
 * Unknown address. Try to resolve it.
 */
	hp = gethostbyaddr((char *)&inaddr, INADDRSZ, AF_INET);

	if (hp != NULL)
		host = maxstr(newstr(hp->h_name), MAXDNAME, FALSE);
	else
		host = NULL;

/*
 * Put it on the hash list.
 */
	s->addrlist = newlist(s->addrlist, s->addrcount+1, ipaddr_t);
	s->namelist = newlist(s->namelist, s->addrcount+1, char *);
	s->addrlist[s->addrcount] = addr;
	s->namelist[s->addrcount] = host;
	s->addrcount++;

	return(host);
}

/*
** PRINT_STATS -- Print round-trip statistics
** ------------------------------------------
*/

void
print_stats(sp)
stats *sp;				/* statistics buffer */
{
	double rttavg;			/* average round-trip time */
	double rttstd;			/* rtt standard deviation */

	if (sp->rcvd > 0)
	{
		rttavg = sp->rttsum / sp->rcvd;
		rttstd = sp->rttssq - (rttavg * sp->rttsum);
		rttstd = xsqrt(rttstd / sp->rcvd);

		printf("round-trip (ms) min/avg/max =");
		printf(" %s", tvprint(sp->rttmin));
		printf("/%s", tvprint((time_t)rttavg));
		printf("/%s", tvprint(sp->rttmax));
		printf(" (std = %s)\n", tvprint((time_t)rttstd));
	}
}

/*
** RECORD_STATS -- Update round-trip statistics
** --------------------------------------------
*/

void
record_stats(sp, rtt)
stats *sp;				/* statistics buffer */
time_t rtt;				/* round-trip time */
{
	if (rtt < sp->rttmin)
		sp->rttmin = rtt;

	if (rtt > sp->rttmax)
		sp->rttmax = rtt;

	sp->rttsum += (double)rtt;
	sp->rttssq += (double)rtt * (double)rtt;
}


/*
** CLEAR_STATS -- Clear out round-trip statistics
** ----------------------------------------------
*/

void
clear_stats(sp)
stats *sp;				/* statistics buffer */
{
	sp->rcvd = 0;
	sp->dupl = 0;
	sp->fail = 0;
	sp->rttmin = VERY_LONG;
	sp->rttmax = 0;
	sp->rttsum = 0.0;
	sp->rttssq = 0.0;
}

/*
** UPDATE_HOSTS -- Register host during broadcast
** ----------------------------------------------
**
**	Note. During broadcast, the duplicate flag is used to indicate
**	a returned packet having its source address set to the broadcast
**	address instead of the address belonging to a specific host.
*/

void
update_hosts(inaddr, duplicate, rtt)
struct in_addr inaddr;			/* IP address */
bool duplicate;				/* set if this is a duplicate reply */
time_t rtt;				/* round-trip time in microsecs */
{
	register hostinfo *h;
	register hostinfo **hp;

	/* check whether this address is known */
	for (h = hostchain; h != NULL; h = h->next)
		if (h->inaddr.s_addr == inaddr.s_addr)
			break;

	/* allocate new entry if unknown */
	if (h == NULL)
	{
		/* sort according to ascending IP address */
		for (hp = &hostchain; (h = *hp) != NULL; hp = &h->next)
			if (ntohl(inaddr.s_addr) < ntohl(h->inaddr.s_addr))
				break;

		h = newstruct(hostinfo);
		clear_stats(&h->stats);
		h->inaddr = inaddr;
		h->next = *hp;
		*hp = h;
	}

	/* update statistics for this entry */
	h->stats.rcvd++;

	if (duplicate)
		h->stats.dupl++;

	if (timing)
		record_stats(&h->stats, rtt);
}

/*
** SHOW_HOSTS -- Print responding hosts during broadcast
** -----------------------------------------------------
*/

void
show_hosts()
{
	register hostinfo *h;
	int hostcount;

	hostcount = 0;
	for (h = hostchain; h != NULL; h = h->next)
		hostcount++;

	if (hostcount == 0)
		printf("No hosts responded\n");
	else
		printf("%d different host%s responded\n",
			hostcount, plural(hostcount));

	for (h = hostchain; h != NULL; h = h->next)
	{
		printf("\t%d packet%s",
			h->stats.rcvd, plural(h->stats.rcvd));

		if (ntransmitted > 0)
		{
			double frac = 100 * (double)h->stats.rcvd /
					    (double)ntransmitted;

			if (h->stats.rcvd == ntransmitted)
				printf(" (%d%%)", 100);
			else if (h->stats.rcvd < ntransmitted)
				printf(" (%.2g%%)", frac);
		}

		if (h->stats.dupl > 0)
			printf(" %d duplicate%s",
				h->stats.dupl, plural(h->stats.dupl));

		printf(" from %s", pr_addr(h->inaddr));

		if (timing && (h->stats.rcvd > 0))
		{
			double rttavg = h->stats.rttsum / h->stats.rcvd;
			printf(" (avg = %s)", tvprint((time_t)rttavg));
		}

		printf("\n");
	}
}

/*
** UPDATE_ROUTES -- Register route from IP options
** -----------------------------------------------
*/

#ifdef IP_OPTIONS

void
update_routes(ipopt, ipoptlen, duplicate, rtt)
u_char *ipopt;				/* address of options buffer */
int ipoptlen;				/* total size of options buffer */
bool duplicate;				/* set if this is a duplicate reply */
time_t rtt;				/* round-trip time in microsecs */
{
	register optstr *opt;

	/* make sure the size is in range */
	if (ipoptlen > MAX_IPOPTLEN)
		ipoptlen = MAX_IPOPTLEN;

	/* locate identical data in current chain */
	for (opt = optchain; opt != NULL; opt = opt->next)
	{
		if (ipoptlen != opt->ipoptlen)
			continue;
		if (bcmp((char *)ipopt, (char *)opt->ipopt, ipoptlen) == 0)
			break;
	}

	/* allocate new entry if this is new data */
	if (opt == NULL)
	{
		opt = newstruct(optstr);
		clear_stats(&opt->stats);
		bcopy((char *)ipopt, (char *)opt->ipopt, ipoptlen);
		opt->ipoptlen = ipoptlen;
		opt->next = optchain;
		optchain = opt;
	}

	/* update statistics for this entry */
	if (duplicate)
		opt->stats.dupl++;
	else
		opt->stats.rcvd++;

	if (timing && !duplicate)
		record_stats(&opt->stats, rtt);
}

#endif /*IP_OPTIONS*/

/*
** SHOW_ROUTES -- Print all recorded routes from IP options
** --------------------------------------------------------
*/

#ifdef IP_OPTIONS

void
show_routes()
{
	register optstr *opt;
	int optcount;

	optcount = 0;
	for (opt = optchain; opt != NULL; opt = opt->next)
		optcount++;

	if (optcount == 0)
		printf("No packets with routing info received\n");
	else if (optcount > 1)
		printf("%d different route%s received\n",
			optcount, plural(optcount));

	for (opt = optchain; opt != NULL; opt = opt->next)
	{
		printf("\n%d packet%s",
			opt->stats.rcvd, plural(opt->stats.rcvd));

		if (pings.rcvd > 0)
		{
			double frac = 100 * (double)opt->stats.rcvd /
					    (double)pings.rcvd;

			if (opt->stats.rcvd == pings.rcvd)
				printf(" (%d%%)", 100);
			else
				printf(" (%.2g%%)", frac);
		}

		if (opt->stats.dupl > 0)
			printf(" %d duplicate%s",
				opt->stats.dupl, plural(opt->stats.dupl));

		printf(" via:\n");
		print_options(opt->ipopt, opt->ipoptlen);

		if (timing)
			print_stats(&opt->stats);
	}
}

#endif /*IP_OPTIONS*/

/*
** SHOW_MISSED -- Print all missed responses
** -----------------------------------------
**
**	This is not accurate in case we transmitted more packets
**	than can be recorded in the bitmap (seq number wrapped).
*/

void
show_missed()
{
	register int response;
	int missing, maxmissed;

	maxmissed = ntransmitted;
	if (maxmissed > BITMAPSIZE)
		maxmissed = BITMAPSIZE;

	missing = 0;
	for (response = 0; response < maxmissed; response++)
		if (!TSTRCVD(response))
			missing++;

	printf("%d missed response%s\n", missing, plural(missing));
	if (missing > 0 && missing < maxmissed)
	{
		missing = 0;
		for (response = 0; response < maxmissed; response++)
		{
			if (!TSTRCVD(response))
			{
				missing++;
				printf("%3d ", response);

				if ((missing % 15) == 0)
					printf("\n");
			}
		}

		if ((missing % 15) != 0)
			printf("\n");
	}
}

/*
** C_PUT -- Print markers in Cisco style
** -------------------------------------
*/

int maxcolumn = 79;		/* last column on screen to print marker */

void
c_put(str)
char *str;				/* marker to print (first char only) */
{
	if (column >= maxcolumn)
	{
		(void) write(STDOUT, "\n", 1);
		column = 0;
	}
	(void) write(STDOUT, str, 1);
	column++;
}


/*
** SETWINDOW -- Set new terminal window size
** -----------------------------------------
*/

sigtype_t /*ARGSUSED*/
setwindow(sig)
int sig;				/* nonzero if this was a signal */
{
	int sav_errno = errno;		/* save across interrupt */
#ifdef TIOCGWINSZ
	struct winsize win;

	if ((ioctl(STDOUT, TIOCGWINSZ, &win) == 0) && (win.ws_col > 1))
		maxcolumn = win.ws_col - 1;
#endif
#ifdef SIGWINCH
	(void) signal(SIGWINCH, setwindow);
#endif
	/* restore state to avoid stale values */
	errno = sav_errno;

	sig_return(0);
}

/*
** TVSUB -- Subtract two timeval structs
** -------------------------------------
**
**	Returns:
**		Time difference in micro(!)seconds.
**
**	Side effects:
**		The difference of the two timeval structs
**		is stored back into the first.
**
**	This implementation assumes that time_t is a signed value.
**	On 32-bit machines this limits the range to ~35 minutes.
**	That seems sufficient for most practical purposes.
**	Note that tv_sec is an *un*signed entity on some platforms.
*/

time_t
tvsub(t2, t1)
struct timeval *t2;			/* latest timeval */
struct timeval *t1;			/* oldest timeval */
{
	register time_t usec;

	t2->tv_usec -= t1->tv_usec;
	while (t2->tv_usec < 0)
	{
		t2->tv_usec += 1000000;
		if (t2->tv_sec != 0)
			t2->tv_sec--;
		else
			t2->tv_usec = 0;
	}

	if (t2->tv_sec < t1->tv_sec)
	{
		t2->tv_sec = 0;
		t2->tv_usec = 0;
	}
	else
		t2->tv_sec -= t1->tv_sec;

	if (t2->tv_sec > MAXSECS)
	{
		t2->tv_sec = MAXSECS;
		t2->tv_usec = 0;
	}

	usec = t2->tv_sec*1000000 + t2->tv_usec;
	return(usec);
}

/*
** TVPRINT -- Convert time value to ascii string
** ---------------------------------------------
**
**	Returns:
**		Pointer to string in static storage.
**
**	Output is in variable format, depending on the value.
**	This avoids printing of non-significant digits.
*/

char *
tvprint(usec)
time_t usec;				/* value to convert */
{
	static char buf[30];		/* sufficient for 64-bit values */

	if (usec < 1000)
		(void) sprintf(buf, "%ld.%ld", usec/1000, (usec%1000)/1);
	else if (usec < 10000)
		(void) sprintf(buf, "%ld.%ld", usec/1000, (usec%1000)/10);
	else if (usec < 100000)
		(void) sprintf(buf, "%ld.%ld", usec/1000, (usec%1000)/100);
	else
		(void) sprintf(buf, "%ld", (usec + 500)/1000);

	return(buf);
}

/*
** IN_CHECKSUM -- Compute checksum for IP packets
** ----------------------------------------------
**
**	The complete packet must have been constructed.
**	The checksum field to be computed must be zero.
**
**	Returns:
**		Computed checksum.
*/

#ifdef obsolete

u_short
in_checksum(buf, len)
u_short *buf;				/* start of packet */
int len;				/* length of packet in bytes */
{
	register u_short *w = buf;	/* address of next 16-bit word */
	register int nleft = len;	/* remaining 16-bit words */
	register int sum = 0;		/* 32-bit accumulator */
	u_short answer = 0;

/*
 * Our algorithm is simple, using a 32 bit accumulator (sum),
 * we add sequential 16 bit words to it, and at the end, fold back
 * all the carry bits from the top 16 bits into the lower 16 bits.
 */
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(u_char *)(&answer) = *(u_char *)w;
		sum += answer;
	}

/*
 * Add back carry outs from top 16 bits to low 16 bits.
 */
	sum = (sum >> 16) + (sum & 0xFFFF);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return(answer);
}

#endif /*obsolete*/

/*
** IN_CHECKSUM -- Compute checksum for IP packets
** ----------------------------------------------
**
**	The complete packet must have been constructed.
**	The checksum field to be computed must be zero.
**
**	Returns:
**		Computed checksum.
*/

u_short
in_checksum(buf, len)
u_short *buf;				/* start of packet */
int len;				/* length of packet in bytes */
{
	register u_char *b = (u_char *)buf;
	register int n = len;		/* remaining 16-bit words */
	register int sum = 0;		/* 32-bit accumulator */
	u_short answer;

/*
 * Our algorithm is simple, using a 32 bit accumulator (sum),
 * we add sequential 16 bit words to it, and at the end, fold back
 * all the carry bits from the top 16 bits into the lower 16 bits.
 */
	while (n > 1)
	{
		answer = (b[0] << 8) | b[1];
		sum += answer;
		b += 2; n -= 2;
	}

	if (n == 1)
	{
		answer = (b[0] << 8);
		sum += answer;
	}

/*
 * Add back carry outs from top 16 bits to low 16 bits.
 */
	sum = (sum >> 16) + (sum & 0xFFFF);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum & 0xFFFF;			/* truncate to 16 bits */
	answer = htons(answer);			/* correct order */
	return(answer);
}

/*
** GETGATE -- Fetch internet address of gateway host
** -------------------------------------------------
**
**	Returns:
**		Internet address of given host.
**		Aborts if address could not be determined.
**
**	Only the first address as returned by the resolver is used.
**	This address is used as loose source route gateway address.
**
**	As a side effect, we will try to determine all its addresses
**	and add them to the global address list ``gateaddr[]'' which
**	has ``ngate'' entries.
*/

ipaddr_t
getgate(host)
char *host;				/* host name or dotted quad */
{
	register int i;
	ipaddr_t addr;
	struct in_addr inaddr;
	struct hostent *hp;

/*
 * Determine all addresses of the given host. Add original to the list.
 */
	addr = inet_addr(host);
	inaddr.s_addr = addr;

	if (addr == NOT_DOTTED_QUAD)
	{
		hp = gethostbyname(host);
		if (hp == NULL)
		{
			error("Unknown host %s", host);
			exit(EX_NOHOST);
		}

		bcopy(hp->h_addr, (char *)&inaddr, INADDRSZ);
		addr = inaddr.s_addr;
	}
	else
	{
		host = maphostbyaddr(inaddr);
		if (host != NULL)
			hp = gethostbyname(host);
		else
			hp = NULL;

		if ((ngate < MAXGATE) && !gatewayaddr(inaddr))
			gateaddr[ngate++] = inaddr.s_addr;
	}

/*
 * Append all found addresses to the global address list.
 */
	for (i = 0; hp != NULL && hp->h_addr_list[i]; i++)
	{
		bcopy(hp->h_addr_list[i], (char *)&inaddr, INADDRSZ);
		if ((ngate < MAXGATE) && !gatewayaddr(inaddr))
			gateaddr[ngate++] = inaddr.s_addr;
	}

	/* prep the address cache */
	for (i = 0; i < ngate; i++)
	{
		inaddr.s_addr = gateaddr[i];
		(void) maphostbyaddr(inaddr);
	}

	return(addr);
}

/*
** GATEWAYADDR -- Check whether address belongs to known gateways
** --------------------------------------------------------------
**
**	Returns:
**		TRUE if the address is listed in the global table.
**		FALSE otherwise.
*/

bool
gatewayaddr(inaddr)
struct in_addr inaddr;			/* internet address to check */
{
	register int i;

	for (i = 0; i < ngate; i++)
	{
		if (inaddr.s_addr == gateaddr[i])
			break;
	}

	return((i < ngate) ? TRUE : FALSE);
}

/*
** BCAST_ADDR -- Check whether this is a broadcast address
** -------------------------------------------------------
**
**	Returns:
**		TRUE if this represents a broadcast address.
**		FALSE otherwise.
*/

#define	CLASSA(a)	(((a) & (ipaddr_t)0x80000000) == (ipaddr_t)0x00000000)
#define	CLASSB(a)	(((a) & (ipaddr_t)0xC0000000) == (ipaddr_t)0x80000000)
#define	CLASSC(a)	(((a) & (ipaddr_t)0xE0000000) == (ipaddr_t)0xC0000000)

#define	CLASSD(a)	(((a) & (ipaddr_t)0xF0000000) == (ipaddr_t)0xE0000000)
#define	CLASSE(a)	(((a) & (ipaddr_t)0xF0000000) == (ipaddr_t)0xF0000000)
#define	CLASSL(a)	(((a) & (ipaddr_t)0xFF000000) == (ipaddr_t)0x7F000000)

bool
bcast_addr(inaddr)
struct in_addr inaddr;			/* IP address */
{
	register ipaddr_t address = ntohl(inaddr.s_addr);
	register ipaddr_t hostmask;
	register int hostbits, bit;

	if (CLASSL(address))
		return(FALSE);		/* loopback */
	else if (CLASSA(address))
		hostbits = 24;		/* 0x00FFFFFF */
	else if (CLASSB(address))
		hostbits = 16;		/* 0x0000FFFF */
	else if (CLASSC(address))
		hostbits = 8;		/* 0x000000FF */
	else if (CLASSD(address))
		return(TRUE);		/* multicast */
	else
		return(FALSE);		/* reserved */

	/* if explicit netmask given */
	if (netbits > 0 && netbits < 32)
		hostbits = 32 - netbits;

	/* construct hostmask */
	for (hostmask = 0, bit = 0; bit < hostbits; bit++)
		hostmask |= (1 << bit);

	/* mask host part */
	address &= hostmask;

	/* must be all zeroes or all ones */
	return((address == 0 || address == hostmask) ? TRUE : FALSE);
}

/*
** MAXSTR -- Ensure string does not exceed maximum size
** ----------------------------------------------------
**
**	Returns:
**		Pointer to the (possibly truncated) string.
**
**	If necessary, a new string is allocated, and is then
**	truncated, and the original string is left intact.
**	Otherwise the original string is truncated in place.
**
*/

char *
maxstr(string, n, save)
char *string;				/* the string to check */
int n;					/* the maximum allowed size */
bool save;				/* allocate new string, if set */
{
	if (strlength(string) > n)
	{
		if (save)
			string = newstr(string);
		string[n] = '\0';
	}
	return(string);
}

/*
** XALLOC -- Allocate or reallocate additional memory
** --------------------------------------------------
**
**	Returns:
**		Pointer to (re)allocated buffer space.
**		Aborts if the requested memory could not be obtained.
*/

ptr_t *
xalloc(buf, size)
register ptr_t *buf;			/* current start of buffer space */
siz_t size;				/* number of bytes to allocate */
{
	if (buf == NULL)
		buf = malloc(size);
	else
		buf = realloc(buf, size);

	if (buf == NULL)
	{
		error("Out of memory");
		exit(EX_OSERR);
	}

	return(buf);
}

/*
** ITOA -- Convert integer value to ascii string
** ---------------------------------------------
**
**	Returns:
**		Pointer to static storage containing string.
*/

char *
itoa(n)
int n;					/* value to convert */
{
	static char buf[30];		/* sufficient for 64-bit values */

	(void) sprintf(buf, "%d", n);
	return(buf);
}

/*
** XSQRT -- Compute arithmetic square root
** ---------------------------------------
**
**	Returns:
**		Computed square root value.
**
**	This is supplied to avoid linking with the -lm library.
**	Several Newton-Raphson iterations are performed until
**	the machine precision is hit.
*/

double
xsqrt(y)
double y;
{
	double t, x;

	if (y <= 0)
		return(0);

	x = (y < 1.0) ? 1.0 : y;
	do {
		t = x;
		x = (t + (y/t))/2.0;
	} while (0 < x && x < t);

	return(x);
}


/*
 * Host chain for multi-target ping.
 */

typedef struct _hostdata {
	struct _hostdata *next;		/* next in chain */
	struct timeval pingtime;	/* time when last processed */
	struct in_addr inaddr;		/* IP address */
	char *host;			/* host name */
	int seqnum;			/* index in host table */
	int pktcnt;			/* number of packets sent */
} hostdata;

hostdata *hostlist = NULL;	/* chain of target hosts */
hostdata **hosttab = NULL;	/* table of target hosts */
int nhosts = 0;			/* number of target hosts in table */

/*
** GET_TARGETS -- Accumulate list of target hosts
** ----------------------------------------------
*/

void
get_targets(argc, argv)
int argc;				/* command line arg count */
char *argv[];				/* command line arguments */
{
	register int i;
	register char *p, *q;
	char buf[BUFSIZ];

	if (argc > 1)
	{
		/* fetch targets from command line */
		for (i = 1; i < argc && argv[i] != NULL; i++)
		{
			add_host(argv[i]);
		}
	}
	else
	{
		/* fetch targets from standard input */
		while (fgets(buf, sizeof(buf), stdin) != NULL)
		{
			p = index(buf, '\n');
			if (p != NULL)
				*p = '\0';

			for (p = buf; is_space(*p); p++)
				continue;

			/* skip comment lines */
			if (*p == '\0' || *p == '#')
				continue;

			/* only extract first item per line */
			for (q = p; *q != '\0' && !is_space(*q); q++)
				continue;

			if (*q != '\0')
				*q = '\0';

			add_host(p);
		}
	}
}

/*
** ADD_HOST -- Add new host to the target list
** -------------------------------------------
*/

void
add_host(host)
char *host;				/* host name or dotted quad */
{
	register int i;
	ipaddr_t addr;
	struct in_addr inaddr;
	struct hostent *hp;

/*
 * Determine all addresses of the given host.
 */
	addr = inet_addr(host);
	inaddr.s_addr = addr;

	if (addr == NOT_DOTTED_QUAD)
	{
		hp = gethostbyname(host);
		if (hp == NULL)
		{
			error("Unknown host %s", host);
			return;
		}

		hostname = strncpy(hostnamebuf, hp->h_name, MAXDNAME);
		hostname[MAXDNAME] = '\0';

		for (i = 0; i < MAXADDRS && hp->h_addr_list[i]; i++)
		{
			bcopy(hp->h_addr_list[i], (char *)&inaddr, INADDRSZ);
			hostaddr[i] = inaddr.s_addr;
		}
		naddrs = i;

		/* prep the address cache */
		for (i = 0; i < naddrs; i++)
		{
			inaddr.s_addr = hostaddr[i];
			(void) maphostbyaddr(inaddr);
		}
	}
	else
	{
		hostname = strcpy(hostnamebuf, inetname(inaddr));

		hostaddr[0] = addr;
		naddrs = 1;
	}

/*
 * Add this entry on the host list.
 */
	for (i = 0; i < naddrs; i++)
	{
		register hostdata *h;

		inaddr.s_addr = hostaddr[i];
		if (bcast_addr(inaddr))
			fatal("No multi ping to broadcast address");

		/* allocate new entry */
		h = newstruct(hostdata);
		h->host = newstr(hostname);
		h->inaddr = inaddr;
		h->seqnum = nhosts;
		h->pktcnt = 0;

		/* link it in */
		h->next = hostlist;
		hostlist = h;

		/* extend the host table */
		hosttab = newlist(hosttab, nhosts+1, hostdata *);
		hosttab[nhosts] = h;
		nhosts++;

		if (!alladdr)
			break;
	}
}
