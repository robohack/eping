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
 * Extensively modified by Eric Wassenaar, Nikhef-H, <e07@nikhef.nl>
 *
 * The source of this particular version of the program is available
 * via anonymous ftp from machine 'ftp.nikhef.nl' [192.16.199.1]
 * in the directory '/pub/network' as 'ping.tar.Z'
 */

#ifndef lint
static char Version[] = "@(#)ping.c	e07@nikhef.nl (Eric Wassenaar) 950918";
#endif

#if defined(apollo) && defined(lint)
#define __attribute(x)
#endif

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
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <setjmp.h>

#include <sys/types.h>		/* not always automatically included */
#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#undef NOERROR			/* in <sys/streams.h> on solaris 2.x */
#include <arpa/nameser.h>
#include <resolv.h>

#include "conf.h"		/* various configuration definitions */
#include "exit.h"		/* exit codes come from <sysexits.h> */
#include "port.h"		/* various portability definitions */
#include "icmp.h"		/* icmp types belong in <netinet/ip_icmp.h> */

typedef int	bool;		/* boolean type */
#define TRUE	1
#define FALSE	0

#define STDIN	0
#define STDOUT	1
#define STDERR	2

#ifdef lint
#define EXTERN
#else
#define EXTERN extern
#endif

EXTERN int errno;
EXTERN res_state_t _res;	/* defined in res_init.c */
extern char *version;		/* program version number */

/*
 * Various buffer sizes.
 */

#ifndef MAXPKT
#define	MAXPKT	4096			/* max output packet total size */
#endif
#define PKTSIZE	64			/* default output packet size */
#define HDRLEN	ICMP_MINLEN		/* icmp header minimum length (8) */
#define	TIMLEN	sizeof(struct timeval)	/* size of timer data (8) */
#define DATALEN	(PKTSIZE-HDRLEN)	/* default packet data length (56) */
#define	MAXDATA	(MAXPKT-HDRLEN-TIMLEN)	/* max available for fill data */

#ifdef IP_MAXPACKET
#define MAXPACKET IP_MAXPACKET	/* max ip packet size */
#else
#define MAXPACKET 65535
#endif

#define IPHDRSZ		20	/* actually sizeof(struct ip) */

#ifndef MAX_IPOPTLEN
#define MAX_IPOPTLEN	40	/* max ip options buffer size */
#endif
#define IPOPT_HDRLEN	3	/* actually IPOPT_MINOFF - 1 */

#define	RCVBUF	48*1024		/* size of receive buffer to specify */

#define	MAXWAIT	5		/* max secs to wait for response */

/*
 * Modes of operation.
 */

#define PING_NORMAL	0	/* ping at regular intervals */
#define PING_FLOOD	1	/* ping as fast as possible */
#define PING_CISCO	2	/* ping Cisco-style */

int pingmode = PING_NORMAL;	/* how to ping */

/*
 * Command line flags.
 */

int verbose = 0;		/* -v  print additional information */
bool quiet = FALSE;		/* -q  don't print markers, only summary */
bool quick = FALSE;		/* -Q  don't print summary, quit if alive */
bool alladdr = FALSE;		/* -a  probe all addresses of target host */
bool numeric = FALSE;		/* -n  print IP address as dotted quad */
bool fastping = FALSE;		/* -F  next ping immediately upon response */
bool printmiss = FALSE;		/* -m  print missed responses */
bool traceroute = FALSE;	/* -R  enable packet route recording */
bool looseroute = FALSE;	/* -L  enable loose source routing */

/*
 * Command line options.
 */

int preload = 0;		/* -p  number of packets to "preload" */
int timeout = 1;		/* -t  timeout between packets (secs) */
int floodtime = 10;		/* -T  timeout in flood mode (millisecs) */
int filldata = 0;		/* -D  pattern for data packet specified */

int datalen = DATALEN;		/* size of probe packet */
int packetcount = 0;		/* maximum number of packets to send */

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

int ntransmitted = 0;		/* seq # for outbound packets */
int npackets = 0;		/* maximum number of packets to send */

int request = ICMP_ECHO;	/* outbound icmp request type */
int reply = ICMP_ECHOREPLY;	/* expected inbound reply type */

int sock;			/* socket file descriptor */
int sockopts = 0;		/* socket options */

struct sockaddr myaddr;		/* address of ourselves */
struct sockaddr toaddr;		/* address to send to */
struct sockaddr fromaddr;	/* address to recv from */

struct sockaddr_in *me   = (struct sockaddr_in *)&myaddr;
struct sockaddr_in *to   = (struct sockaddr_in *)&toaddr;
struct sockaddr_in *from = (struct sockaddr_in *)&fromaddr;

u_char opacket[MAXPACKET];	/* outgoing packet */
u_char ipacket[MAXPACKET];	/* incoming packet */

/*
 * BITMAPSIZE is the number of bits in received bitmap, i.e. the
 * maximum number of received sequence numbers we can keep track of.
 * Use 2048 for complete accuracy -- sequence numbers are 16 bits.
 */

#define WORDSIZE	(8 * sizeof(u_int))
#define BITMAPSIZE	(WORDSIZE * 2048)

u_int rcvd_bitmap[BITMAPSIZE / WORDSIZE];

#define MAPBIT(bit)	((bit) % BITMAPSIZE)		/* bit in bitmap */
#define MAPWORD(bit)	(MAPBIT(bit) / WORDSIZE)	/* word in bitmap */
#define WORDBIT(bit)	(1 << (MAPBIT(bit) % WORDSIZE))	/* bit in word */

#define SET(bit, map)	(map)[MAPWORD(bit)] |= WORDBIT(bit)
#define CLR(bit, map)	(map)[MAPWORD(bit)] &= ~WORDBIT(bit)
#define TST(bit, map)	(((map)[MAPWORD(bit)] & WORDBIT(bit)) != 0)

#define SETBIT(bit)	SET(bit, rcvd_bitmap)
#define CLRBIT(bit)	CLR(bit, rcvd_bitmap)
#define TSTBIT(bit)	TST(bit, rcvd_bitmap)

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
} stats;

#define VERY_LONG ((time_t)999999999)

stats pings = { 0, 0, 0, VERY_LONG, 0, 0.0 };

/*
 * Structure for host info in broadcast mode.
 */

typedef struct _hostinfo {
	struct _hostinfo *next;		/* next in chain */
	struct in_addr inaddr;		/* IP address */
	int rcvd;			/* number of responses */
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
 * Useful inline functions.
 */

#define superuser()	(getuid() == 0)
#define sameaddr(a,b)	((a)->sin_addr.s_addr == (b)->sin_addr.s_addr)
#define bitset(bit, w)	(((w) & (bit)) != 0)
#define plural(n)	((n) == 1 ? "" : "s")
#define	atox(c)		(isdigit(c) ? (c - '0')      : \
			(isupper(c) ? (c - 'A' + 10) : \
			(islower(c) ? (c - 'a' + 10) : 0)))

#define NOT_DOTTED_QUAD	((ipaddr_t)-1)

#include "defs.h"	/* declaration of functions */

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
Usage:   %s [options] host [length [npackets]]\n\
Flags:   [-c|-f] [-F] [-Q] [-LR] [-amnqv] [-dr]\n\
Options: [-p preload] [-t timeout] [-D pattern]\
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
**		Various possibilities from <sysexits.h>
**		EX_OK if at least one valid response was received.
**		EX_UNAVAILABLE if there were none.
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

	assert(sizeof(u_int) == 4);	/* probably paranoid */
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
 */
	if (argc < 1 || argv[0] == NULL)
		exit(EX_USAGE);

	program = rindex(argv[0], '/');
	if (program++ == NULL)
		program = argv[0];

	while (argc > 1 && argv[1] != NULL && argv[1][0] == '-')
	{
	    for (option = &argv[1][1]; *option != '\0'; option++)
	    {
		switch (*option)
		{
		    case 'd':		/* socket debugging */
			sockopts |= SO_DEBUG;
			break;

		    case 'r':		/* don't use routing table */
			sockopts |= SO_DONTROUTE;
			break;

		    case 'a':		/* probe all addresses */
			alladdr = TRUE;
			break;

		    case 'm':		/* show missing response stats */
			printmiss = TRUE;
			break;

		    case 'n':		/* numeric IP addresses only */
			numeric = TRUE;
			break;

		    case 'Q':		/* don't print summary */
			quick = TRUE;
			/*FALLTHROUGH*/

		    case 'q':		/* don't print markers */
			quiet = TRUE;
			break;

		    case 'v':		/* increment verbosity level */
			verbose++;
			break;

		    case 'l':		/* compat with older versions */
			/*FALLTHROUGH*/

		    case 'L':		/* loose source route */
			looseroute = TRUE;
			break;

		    case 'R':		/* record route */
			traceroute = TRUE;
			break;

		    case 'F':		/* no delay between pings */
			fastping = TRUE;
			break;

		    case 'f':		/* flood pings */
			if (pingmode == PING_CISCO)
				fatal("Conflicting options -f and -c");
			pingmode = PING_FLOOD;
			break;

		    case 'c':		/* cisco style pings */
			if (pingmode == PING_FLOOD)
				fatal("Conflicting options -c and -f");
			pingmode = PING_CISCO;
			break;

		    case 'p':		/* # of packets to preload */
			if (argv[2] == NULL || argv[2][0] == '-')
				fatal("Missing preload value");
			preload = atoi(argv[2]);
			if (preload < 1)
				fatal("Invalid preload value %s", argv[2]);
			argv++; argc--;
			break;

		    case 't':		/* timeout (secs) between pings */
			if (argv[2] == NULL || argv[2][0] == '-')
				fatal("Missing timeout value");
			timeout = atoi(argv[2]);
			if (timeout < 1)
				fatal("Invalid timeout value %s", argv[2]);
			argv++; argc--;
			break;

		    case 'T':		/* timeout (msecs) for flood mode */
			if (argv[2] == NULL || argv[2][0] == '-')
				fatal("Missing timeout value");
			floodtime = atoi(argv[2]);
			if (floodtime < 1)
				fatal("Invalid timeout value %s", argv[2]);
			if (floodtime > 1000)
				fatal("Maximum timeout value %s", itoa(1000));
			argv++; argc--;
			break;

		    case 'D':		/* specify fill data */
			if (argv[2] == NULL || argv[2][0] == '-')
				fatal("Missing pattern data");
			for (cp = argv[2]; *cp != '\0'; cp += 2)
			{
				u_char pat;

				if (!isxdigit(cp[0]) || !isxdigit(cp[1]))
					fatal("Invalid hex data %s", argv[2]);
				if (filldata >= MAXDATA)
					fatal("Too much fill data specified");
				pat = (atox(cp[0]) << 4) | atox(cp[1]);
				pattern[filldata++] = pat;
			}
			argv++; argc--;
			break;

		    case 's':		/* compat with older versions */
			break;

		    case 'V':
			printf("Version %s\n", version);
			exit(EX_OK);

		    default:
			fatal(Usage, program);
			/*NOTREACHED*/
		}
	    }

	    argv++; argc--;
	}

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
	bcopy(hp->h_addr, (char *)&inaddr, INADDRSZ);

	/* setup ip address */
	bzero((char *)&myaddr, sizeof(myaddr));
	me->sin_family = AF_INET;
	me->sin_addr = inaddr;
	me->sin_port = 0;

/*
 * Fetch (mandatory) remote host address(es) to probe.
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

		hostname = strcpy(hostnamebuf, hp->h_name);
		for (i = 0; i < MAXADDRS && hp->h_addr_list[i]; i++)
		{
			bcopy(hp->h_addr_list[i], (char *)&inaddr, INADDRSZ);
			hostaddr[i] = inaddr.s_addr;
		}
		naddrs = alladdr ? i : 1;
	}
	else
	{
		if (numeric || (inaddr.s_addr == INADDR_ANY))
			hp = NULL;
		else
			hp = gethostbyaddr((char *)&inaddr, INADDRSZ, AF_INET);
		if (hp != NULL)
			hostname = strcpy(hostnamebuf, hp->h_name);
		else
			hostname = strcpy(hostnamebuf, hostname);
		hostaddr[0] = addr;
		naddrs = 1;
	}

/*
 * Scan remaining optional command line arguments.
 */
	/* data length is packet size minus header length */
	if (argc > 2 && argv[2] != NULL)
	{
		datalen = atoi(argv[2]);
		if (datalen < 1)
			fatal("Invalid packet length %s", argv[2]);
		if (datalen > MAXPKT - HDRLEN)
			fatal("Maximum packet length %s", itoa(MAXPKT-HDRLEN));
	}

	/* maximum number of packets */
	if (argc > 3 && argv[3] != NULL)
	{
		packetcount = atoi(argv[3]);
		if (packetcount < 1)
			fatal("Invalid packet count %s", argv[3]);
	}

	/* rest is undefined */
	if (argc > 4)
		fatal(Usage, program);

/*
 * Miscellaneous initialization.
 */
	/* our packet identifier */
	ident = getpid() & 0xFFFF;

	/* set shorter nameserver timeout */
	_res.retry = 2;		/* number  of retries, default = 4 */
	_res.retrans = 3;	/* timeout in seconds, default = 5 or 6 */

#ifdef IP_OPTIONS
	/* here we route our own reply packet */
	if (looseroute)
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

#ifdef OMNINET
	/* initialize network device for route recording to work */
	if (traceroute)
		(void) initdevice(OMNINET);
#endif /*OMNINET*/

/*
 * Allocate and configure raw icmp socket.
 */
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
	}

	/* indicate success or failure */
	exit(got_there ? EX_OK : EX_UNAVAILABLE);
	/*NOTREACHED*/
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
** ERRMSG -- Issue error message to error output
** ---------------------------------------------
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
*/

#ifdef IP_OPTIONS

void
set_options()
{
	u_char ipoptbuf[MAX_IPOPTLEN];	/* ip options buffer */
	u_char *ipopt = ipoptbuf;	/* current index */

	bzero((char *)ipoptbuf, sizeof(ipoptbuf));

/*
 * Start with loose source route.
 */
	if (looseroute)
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
 * Use remainder for route recording.
 */
	if (traceroute)
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
	if ((broadcast && pingmode == PING_FLOOD) && !superuser())
		fatal("No flood ping to broadcast address");

#ifdef IP_OPTIONS
	/* set special ip options as necessary */
 	if (traceroute || looseroute)
		set_options();
#endif /*IP_OPTIONS*/

	/* initialize counters */
	zero_stats(&pings);
	ntransmitted = 0;
	npackets = packetcount;

	if (!quick)
	{
		printf("%sPING %s: %d data byte%s", pass > 0 ? "\n" : "",
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
		send_ping();

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
		if (check_ping(ipacket, cc))
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
	int waittime;			/* timeout until shutdown */
	int sav_errno = errno;		/* save across interrupt */

/*
 * Issue warning if nothing was received within the timeout period.
 */
	if ((sig == SIGALRM) && !gotone)
	{
		if (!quiet)
		{
			if (pingmode == PING_CISCO)
				c_put(".");
			else if (pingmode == PING_NORMAL)
				printf("no reply from %s\n", hostname);
		}
	}

	/* reset for next try */
	gotone = FALSE;

/*
 * Retry until the specified packet limit is reached.
 */
restart:
	if (npackets == 0 || ntransmitted < npackets)
	{
		/* must send another packet */
		send_ping();

		if (pingmode == PING_FLOOD)
		{
			/* wait only a very short time */
			if (wait_ping(floodtime) == 0)
				goto restart;
		}
		else
		{
			/* schedule next alarm */
			(void) signal(SIGALRM, ping_alarm);
			(void) alarm((unsigned)timeout);
		}
	}
	else if (broadcast || ((pings.rcvd + pings.fail) < ntransmitted))
	{
		/* must pickup outstanding packets */
		flushing = TRUE;

		if (pingmode == PING_CISCO)
		{
			/* standard timeout */
			waittime = timeout;
		}
		else if (pings.rcvd > 0)
		{
			/* make educated guess */
			waittime = timeout + (pings.rttmax / 1000);
		}
		else
		{
			/* maximum timeout */
			waittime = MAXWAIT;
		}

		/* schedule shutdown */
		(void) signal(SIGALRM, finish);
		(void) alarm((unsigned)waittime);
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
*/

void
send_ping()
{
	struct icmp *icp;		/* icmp packet */
	struct timeval *sendtime;	/* time when transmitted */
	int len;			/* size of icmp output packet */
	int cc;				/* size actually transmitted */

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
	icp->icmp_seq   = ntransmitted++;

	/* compute checksum */
	icp->icmp_cksum = in_cksum((u_short *)icp, len);

	/* clear this packet in stats table */
	CLRBIT(icp->icmp_seq);

	/* transmit the output packet */
	cc = sendto(sock, (char *)opacket, len, 0, &toaddr, sizeof(toaddr));
	if (cc < 0 || cc != len)
	{
		if (!quiet && (pingmode != PING_NORMAL))
			(void) fprintf(stderr, "\n");
		if (cc < 0)
			perror("sendto");
		else
			error("sendto: truncated packet to %s", hostname);

#ifdef EMSGSIZE
		/* message too long */
		if (errno == EMSGSIZE)
			exit(EX_DATAERR);
#endif /*EMSGSIZE*/

		/* don't retry in quick mode */
		if (quick)
			exit(EX_UNAVAILABLE);
	}

	/* display marker if appropriate */
	if (!quiet)
	{
		if (pingmode == PING_FLOOD)
			(void) write(STDOUT, ".", 1);
	}
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

	cc = recvfrom(sock, (char *)ipacket, len, 0, &fromaddr, &fromlen);
	if (cc <= 0)
	{
		/* shouldn't happen */
		if (cc == 0)
			errno = ECONNRESET;

		/* interrupt -- restart */
		if (errno == EINTR)
			goto restart;

		if (!quiet && (pingmode != PING_NORMAL))
			(void) fprintf(stderr, "\n");
		perror("recvfrom");

		(void) close(sock);
		exit(EX_OSERR);
	}

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

	timer.tv_sec = 0;
	timer.tv_usec = millisecs * 1000;

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
			(void) fprintf(stderr, "\n");
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
**		TRUE if this is a valid response (or bounce) packet.
**		FALSE otherwise.
*/

bool
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
	time_t rtt;			/* round-trip time in millisecs */
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
			pr_ippkt(ip, cc);
		}
		return(FALSE);
	}

	if (cc < iphdrlen + ICMP_MINLEN)
	{
		if (verbose)
		{
			printf("\n%d bytes from %s: (too short)\n",
				cc, pr_addr(from->sin_addr));

			/* dump the ip packet */
			pr_ippkt(ip, cc);
		}
		return(FALSE);
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
			pr_icmph(icp, cc);
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
			pr_icmph(icp, cc);
		}
		return(FALSE);
	}

	/* XXX should compare the patterns to make sure the packets match */
	if (cc != HDRLEN + datalen)
	{
		if (verbose)
		{
			printf("\n%d bytes from %s: (wrong size) ",
				cc, pr_addr(from->sin_addr));

			/* dump the icmp packet */
			pr_icmph(icp, cc);
		}
		return(FALSE);
	}

/*
 * Check for duplicate reply.
 */
	if (broadcast)
		duplicate = sameaddr(from, to);
	else
		duplicate = TSTBIT(icp->icmp_seq);

	if (duplicate)
		pings.dupl++;
	else
		pings.rcvd++;

	if (!duplicate)
		SETBIT(icp->icmp_seq);

	if (broadcast)
		update_hosts(from->sin_addr);

/*
 * Compute round-trip time.
 */
	if (timing)
	{
		sendtime = (struct timeval *)icp->icmp_data;
		tvsub(recvtime, sendtime);
		rtt = (tv.tv_sec*1000) + ((tv.tv_usec+500)/1000);
	}

	if (timing && !duplicate)
		record_stats(&pings, rtt);

/*
 * The options buffer may be present at the end of the ip header.
 */
#ifdef IP_OPTIONS
	if ((traceroute || looseroute) && (iphdrlen > IPHDRSZ))
	{
		u_char *ipopt;		/* start of options buffer */
		int ipoptlen;		/* total size of options buffer */

		ipopt = (u_char *)ip + IPHDRSZ;
		ipoptlen = iphdrlen - IPHDRSZ;

		if (ipoptlen > 0 && ipoptlen <= MAX_IPOPTLEN)
		{
			register optstr *opt;

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
				opt = (optstr *)malloc(sizeof(optstr));
				if (opt != NULL)
				{
					zero_stats(&opt->stats);
					bcopy((char *)ipopt, (char *)opt->ipopt, ipoptlen);
					opt->ipoptlen = ipoptlen;
					opt->next = optchain;
					optchain = opt;
				}
			}

			/* update statistics for this entry */
			if (opt != NULL)
			{
				if (duplicate)
					opt->stats.dupl++;
				else
					opt->stats.rcvd++;

				if (timing && !duplicate)
					record_stats(&opt->stats, rtt);
			}
		}
	}
#endif /*IP_OPTIONS*/

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
				cc, inet_ntoa(from->sin_addr),
				(int)icp->icmp_seq, (int)ip->ip_ttl);
			if (timing)
				printf(" time=%ld ms", rtt);
			if (duplicate)
				printf(", duplicate");
			printf(".\n");
		}
	}

/*
 * Print options buffer, if appropriate.
 */
#ifdef IP_OPTIONS
	if (verbose > 1 && iphdrlen > IPHDRSZ)
	{
		u_char *ipopt;		/* start of options buffer */
		int ipoptlen;		/* total size of options buffer */

		ipopt = (u_char *)ip + IPHDRSZ;
		ipoptlen = iphdrlen - IPHDRSZ;

		pr_options(ipopt, ipoptlen);
	}
#endif /*IP_OPTIONS*/

	/* return valid packet indication */
	return(!duplicate);
}

/*
** CHECK_FAIL -- Process explicit bounces to our requests
** ------------------------------------------------------
**
**	Determine whether we got an ICMP message which returns
**	our ping request because of some external error condition.
**
**	Returns:
**		TRUE if our request packet got bounced.
**		FALSE otherwise.
*/

bool
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
		return(FALSE);
	}

/*
 * Examine the returned IP header.
 */
	/* ensure it is present */
	if (cc < ICMP_MINLEN + IPHDRSZ)
		return(FALSE);

	/* move to the returned ip packet */
	ip = (struct ip *)icp->icmp_data;
	iphdrlen = ip->ip_hl << 2;
	cc -= ICMP_MINLEN;

	/* it must contain an icmp message */
	if (ip->ip_p != IPPROTO_ICMP)
		return(FALSE);

	/* and must have been sent to our destination */
	if (ip->ip_dst.s_addr != to->sin_addr.s_addr)
		return(FALSE);

/*
 * Examine the returned ICMP header.
 */
	/* ensure it is present */
	if (cc < iphdrlen + ICMP_MINLEN)
		return(FALSE);

	/* move to the returned icmp packet */
	icp = (struct icmp *)((u_char *)ip + iphdrlen);
	cc -= iphdrlen;

	/* it must contain our request type */
	if (icp->icmp_type != request)
		return(FALSE);

	/* and must come from us */
	if (icp->icmp_id != ident)
		return(FALSE);

/*
 * This seems our original ping request that got bounced.
 */
	pings.fail++;

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
			printf("bounced at %s: ", pr_addr(from->sin_addr));
			pr_icmph(buf, ICMP_MINLEN);
		}
	}

	return(TRUE);
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

#define pr_host(a)	(naddrs > 1 ? pr_addr(a) : hostname)

sigtype_t
finish(sig)
int sig;				/* nonzero on interrupt */
{
/*
 * Reset state.
 */
	/* no more background action */
	(void) signal(SIGALRM, SIG_IGN);
	(void) alarm((unsigned)0);

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
			printf("\t%d packet%s", h->rcvd, plural(h->rcvd));
			if (ntransmitted > 0)
			{
				double frac = 100 * (double)h->rcvd /
						    (double)ntransmitted;

				if (h->rcvd == ntransmitted)
					printf(" (%d%%)", 100);
				else if (h->rcvd < ntransmitted)
					printf(" (%.2g%%)", frac);
			}
			printf(" from %s\n", pr_addr(h->inaddr));
		}
	}

/*
 * Print recorded routes, if available.
 */
#ifdef IP_OPTIONS
	if (traceroute || looseroute)
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
			pr_options(opt->ipopt, opt->ipoptlen);

			if (timing)
				print_stats(&opt->stats);
		}
	}
#endif /*IP_OPTIONS*/

/*
 * Print missing responses (accurate only if we didn't wrap).
 */
	if (printmiss)
	{
		register int response;
		int missing, maxmissed;

		maxmissed = ntransmitted;
		if (maxmissed > BITMAPSIZE)
			maxmissed = BITMAPSIZE;

		missing = 0;
		for (response = 0; response < maxmissed; response++)
			if (!TSTBIT(response))
				missing++;

		printf("%d missed response%s\n", missing, plural(missing));
		if (missing > 0 && missing < maxmissed)
		{
			missing = 0;
			for (response = 0; response < maxmissed; response++)
			{
				if (!TSTBIT(response))
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

		for (p = optchain; p != NULL; p = q)
		{
			q = p->next;
			(void) free((char *)p);
		}
		optchain = NULL;
	}

	/* chain of recorded hosts */
	if (hostchain != NULL)
	{
		register hostinfo *p, *q;

		for (p = hostchain; p != NULL; p = q)
		{
			q = p->next;
			(void) free((char *)p);
		}
		hostchain = NULL;
	}

	/* reset bitmap */
	bzero((char *)rcvd_bitmap, sizeof(rcvd_bitmap));

	/* miscellaneous */
	column = 0;
	flushing = FALSE;

	/* back to main loop */
	longjmp(ping_buf, 1);
	/*NOTREACHED*/
}

/*
** PR_ICMPH -- Print a descriptive string about an ICMP header
** -----------------------------------------------------------
*/

void
pr_icmph(icp, cc)
struct icmp *icp;			/* icmp packet buffer */
int cc;					/* size of icmp packet */
{
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
		pr_ippkt((struct ip *)icp->icmp_data, cc - ICMP_MINLEN);
		break;

	    case ICMP_SOURCEQUENCH:
		printf("Source quench\n");
		pr_ippkt((struct ip *)icp->icmp_data, cc - ICMP_MINLEN);
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
		pr_ippkt((struct ip *)icp->icmp_data, cc - ICMP_MINLEN);
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
		pr_ippkt((struct ip *)icp->icmp_data, cc - ICMP_MINLEN);
		break;

	    case ICMP_PARAMPROB:
		printf("Parameter problem");
		printf(" (pointer: 0x%02x)\n", icp->icmp_pptr);
		pr_ippkt((struct ip *)icp->icmp_data, cc - ICMP_MINLEN);
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
** PR_IPPKT -- Dump some info on a returned (via ICMP) IP packet
** -------------------------------------------------------------
*/

void
pr_ippkt(ip, cc)
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
	pr_iph(ip, cc);

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
		pr_icmph(icp, cc);
	}
}

/*
** PR_IPH -- Print an IP header with options
** -----------------------------------------
*/

void
pr_iph(ip, cc)
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
		pr_options(ipopt, ipoptlen);
#endif /*IP_OPTIONS*/
	}
}

/*
** PR_OPTIONS -- Print ip options data
** -----------------------------------
*/

#ifdef IP_OPTIONS

void
pr_options(ipopt, ipoptlen)
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
			printf("<%s>\n", "recorded route");
			pr_route(ipopt);
			break;

		    case IPOPT_LSRR:
			printf("<%s>\n", "loose source route");
			pr_route(ipopt);
			break;

		    case IPOPT_SSRR:
			printf("<%s>\n", "strict source route");
			pr_route(ipopt);
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

		if (optlen == 0)
			optlen = ipoptlen;
		ipopt += optlen;
		ipoptlen -= optlen;
	}
}

#endif /*IP_OPTIONS*/

/*
** PR_ROUTE -- Print ip route data
** -------------------------------
*/

#ifdef IP_OPTIONS

void
pr_route(ipopt)
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
	static char buf[BUFSIZ];
	struct hostent *hp;

	if (numeric || (inaddr.s_addr == INADDR_ANY))
		hp = NULL;
	else
		hp = gethostbyaddr((char *)&inaddr, INADDRSZ, AF_INET);

	if (hp != NULL)
		(void) sprintf(buf, "%s (%s)", hp->h_name, inet_ntoa(inaddr));
	else
		(void) sprintf(buf, "%s", inet_ntoa(inaddr));
	return(buf);
}

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
** PRINT_STATS -- Print round_trip statistics
** ------------------------------------------
*/

void
print_stats(sp)
stats *sp;				/* statistics buffer */
{
	double rttavg;			/* average round-trip time */

	if (sp->rcvd > 0)
	{
		rttavg = sp->rttsum / sp->rcvd;
		printf("round-trip (ms)\tmin/avg/max = %ld/%.0f/%ld\n",
			sp->rttmin, rttavg, sp->rttmax);
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
}

/*
** ZERO_STATS -- Clear out round-trip statistics
** ---------------------------------------------
*/

void
zero_stats(sp)
stats *sp;				/* statistics buffer */
{
	sp->rcvd = 0;
	sp->dupl = 0;
	sp->fail = 0;
	sp->rttmin = VERY_LONG;
	sp->rttmax = 0;
	sp->rttsum = 0.0;
}

/*
** UPDATE_HOSTS -- Register host during broadcast
** ----------------------------------------------
*/

void
update_hosts(inaddr)
struct in_addr inaddr;			/* IP address */
{
	register hostinfo *h;
	register hostinfo **hp;

	/* check if this address is known */
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

		h = (hostinfo *)malloc(sizeof(hostinfo));
		if (h != NULL)
		{
			h->inaddr = inaddr;
			h->rcvd = 0;
			h->next = *hp;
			*hp = h;
		}
	}

	/* update packet count */
	if (h != NULL)
		h->rcvd++;
}

/*
** C_PUT -- Print markers in Cisco style
** -------------------------------------
*/

void
c_put(str)
char *str;				/* marker to print (first char only) */
{
	if (column >= 79)
	{
		(void) write(STDOUT, "\n", 1);
		column = 0;
	}
	(void) write(STDOUT, str, 1);
	column++;
}

/*
** TVSUB -- Subtract two timeval structs to compute delay
** ------------------------------------------------------
**
**	The difference of the two values is stored back into the first.
*/

void
tvsub(t2, t1)
struct timeval *t2;			/* ending time */
struct timeval *t1;			/* starting time */
{
	t2->tv_usec -= t1->tv_usec;
	if (t2->tv_usec < 0)
	{
		t2->tv_sec--;
		t2->tv_usec += 1000000;
	}

	if (t2->tv_sec < t1->tv_sec)
	{
		t2->tv_sec = 0;
		t2->tv_usec = 0;
	}
	else
		t2->tv_sec -= t1->tv_sec;
}

/*
** IN_CKSUM -- Compute checksum for IP packets
** -------------------------------------------
**
**	The complete packet must have been constructed.
**	The checksum field to be computed must be zero.
**
**	Returns:
**		Computed checksum.
*/

#ifdef obsolete

u_short
in_cksum(buf, len)
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
** IN_CKSUM -- Compute checksum for IP packets
** -------------------------------------------
**
**	The complete packet must have been constructed.
**	The checksum field to be computed must be zero.
**
**	Returns:
**		Computed checksum.
*/

u_short
in_cksum(buf, len)
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
** BCAST_ADDR -- Check if this represents a broadcast address
** ----------------------------------------------------------
**
**	Returns:
**		TRUE if this is a broadcast address.
**		FALSE otherwise.
*/

#define	CLASSA(a)	(((a) & (ipaddr_t)0x80000000) == (ipaddr_t)0x00000000)
#define	CLASSB(a)	(((a) & (ipaddr_t)0xC0000000) == (ipaddr_t)0x80000000)
#define	CLASSC(a)	(((a) & (ipaddr_t)0xE0000000) == (ipaddr_t)0xC0000000)

#define	CLASSD(a)	(((a) & (ipaddr_t)0xF0000000) == (ipaddr_t)0xE0000000)
#define	CLASSE(a)	(((a) & (ipaddr_t)0xF0000000) == (ipaddr_t)0xF0000000)
#define	CLASSL(a)	(((a) & (ipaddr_t)0xFF000000) == (ipaddr_t)0x7F000000)

#define	CLASSA_MASK	(ipaddr_t)0x00FFFFFF
#define	CLASSB_MASK	(ipaddr_t)0x0000FFFF
#define	CLASSC_MASK	(ipaddr_t)0x000000FF

bool
bcast_addr(inaddr)
struct in_addr inaddr;			/* IP address */
{
	register ipaddr_t address = ntohl(inaddr.s_addr);
	register ipaddr_t hostmask;

	if (CLASSL(address))
		return(FALSE);		/* loopback */
	else if (CLASSA(address))
		hostmask = CLASSA_MASK;
	else if (CLASSB(address))
		hostmask = CLASSB_MASK;
	else if (CLASSC(address))
		hostmask = CLASSC_MASK;
	else if (CLASSD(address))
		return(TRUE);		/* multicast */
	else
		return(FALSE);		/* reserved */

	/* mask host part */
	address &= hostmask;

	/* must be all zeroes or all ones */
	if (address == 0 || address == hostmask)
		return(TRUE);

	/* XXX should check for subnets here */
	return(FALSE);
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
	static char buf[30];

	(void) sprintf(buf, "%d", n);
	return(buf);
}
