/*
** Various new ICMP packet type and subcode values.
**
**	They belong in <netinet/ip_icmp.h>
**
**	@(#)icmp.h              e07@nikhef.nl (Eric Wassenaar) 950804
*/

/* new ICMP types */

#ifndef	ICMP_ROUTERADVERT
#define	ICMP_ROUTERADVERT	9		/* router advertisement */
#endif

#ifndef	ICMP_ROUTERSOLICIT
#define	ICMP_ROUTERSOLICIT	10		/* router solicitation */
#endif

/* new ICMP_UNREACH subcodes */

#ifndef	ICMP_UNREACH_NET_UNKNOWN
#define	ICMP_UNREACH_NET_UNKNOWN	6	/* unknown net */
#endif

#ifndef	ICMP_UNREACH_HOST_UNKNOWN
#define	ICMP_UNREACH_HOST_UNKNOWN	7	/* unknown host */
#endif

#ifndef	ICMP_UNREACH_ISOLATED
#define	ICMP_UNREACH_ISOLATED		8	/* src host isolated */
#endif

#ifndef	ICMP_UNREACH_NET_PROHIB
#define	ICMP_UNREACH_NET_PROHIB		9	/* prohibited access */
#endif

#ifndef	ICMP_UNREACH_HOST_PROHIB
#define	ICMP_UNREACH_HOST_PROHIB	10	/* ditto */
#endif

#ifndef	ICMP_UNREACH_TOSNET
#define	ICMP_UNREACH_TOSNET		11	/* bad tos for net */
#endif

#ifndef	ICMP_UNREACH_TOSHOST
#define	ICMP_UNREACH_TOSHOST		12	/* bad tos for host */
#endif

/* defined per RFC 1812 (chapter 5.2.7.1) */

#ifndef	ICMP_UNREACH_ADM_PROHIB
#define	ICMP_UNREACH_ADM_PROHIB		13	/* prohibited access */
#endif

#ifndef	ICMP_UNREACH_PREC_VIOL
#define	ICMP_UNREACH_PREC_VIOL		14	/* precedence violation */
#endif

#ifndef	ICMP_UNREACH_PREC_CUT
#define	ICMP_UNREACH_PREC_CUT		15	/* precedence cutoff */
#endif
