/*
** Special compatibility definitions for linux.
**
**	On the linux platform, several IP-related structures may have
**	different names. Also some of the structure fields may have
**	other names, although the layout is (obviously) fixed.
**	Several constants may not be defined in the standard files.
**
**	@(#)linux.h             e07@nikhef.nl (Eric Wassenaar) 980826
*/

#if defined(linux)

/*
 * The definitions below are necessary for those versions that do not
 * have the real BSD netinet include files, probably all pre-glibc.
 *
 * If IPVERSION is defined, there is a struct ip, otherwise there is
 * only a struct iphdr.
 *
 * If there is a struct ip, the checksum field is usually defined by
 * ip_csum, but sometimes by ip_sum. It remains unclear when.
 *
 * In case no special compile flags are given, the <features.h> file
 * sets _BSD_SOURCE and __USE_BSD but not __FAVOR_BSD, so that the
 * definitions below are applied.
 *
 * If _BSD_SOURCE is defined in advance, __FAVOR_BSD is set as well,
 * and the definitions below are skipped.
 */

#if !defined(__FAVOR_BSD)

#include <linux/version.h>	/* to get the proper LINUX_VERSION_CODE */

#include <endian.h>		/* to get the proper BYTE_ORDER */

#if !defined(BYTE_ORDER) || (BYTE_ORDER != BIG_ENDIAN && \
     BYTE_ORDER != LITTLE_ENDIAN && BYTE_ORDER != PDP_ENDIAN)
error "Undefined or invalid BYTE_ORDER";
#endif

/*
 * Structure of an ip header, without options.
 */

#if !defined(IPVERSION)

#define	IPVERSION	4

struct ip {
#if (BYTE_ORDER == LITTLE_ENDIAN || BYTE_ORDER == PDP_ENDIAN)
	u_char	ip_hl:4,		/* header length */
		ip_v:4;			/* version */
#else
	u_char	ip_v:4,			/* version */
		ip_hl:4;		/* header length */
#endif
	u_char	ip_tos;			/* type of service */
	short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
	short	ip_off;			/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

#else /* IPVERSION */

#if !defined(LINUX_IPSUM)
#define ip_sum ip_csum			/* struct ip defines ip_csum */
#endif

#endif /* IPVERSION */

#define	IP_MAXPACKET	65535		/* maximum packet size */

/*
 * Structure of an icmp header.
 */

#define n_short u_short			/* normally defined in in_systm.h */
#define n_long  u_int			/* redefine for 64-bit machines */
#define n_time  u_int			/* redefine for 64-bit machines */

struct icmp {
	u_char	icmp_type;		/* type of message, see below */
	u_char	icmp_code;		/* type sub code */
	u_short	icmp_cksum;		/* ones complement cksum of struct */
	union {
		u_char ih_pptr;			/* ICMP_PARAMPROB */
		struct in_addr ih_gwaddr;	/* ICMP_REDIRECT */
		struct ih_idseq {
			n_short	icd_id;
			n_short	icd_seq;
		} ih_idseq;
		int ih_void;
	} icmp_hun;
#define	icmp_pptr	icmp_hun.ih_pptr
#define	icmp_gwaddr	icmp_hun.ih_gwaddr
#define	icmp_id		icmp_hun.ih_idseq.icd_id
#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
#define	icmp_void	icmp_hun.ih_void
	union {
		struct id_ts {
			n_time its_otime;
			n_time its_rtime;
			n_time its_ttime;
		} id_ts;
		struct id_ip  {
			struct ip idi_ip;
			/* options and then 64 bits of data */
		} id_ip;
		n_long	id_mask;
		char	id_data[1];
	} icmp_dun;
#define	icmp_otime	icmp_dun.id_ts.its_otime
#define	icmp_rtime	icmp_dun.id_ts.its_rtime
#define	icmp_ttime	icmp_dun.id_ts.its_ttime
#define	icmp_ip		icmp_dun.id_ip.idi_ip
#define	icmp_mask	icmp_dun.id_mask
#define	icmp_data	icmp_dun.id_data
};

#define	ICMP_MINLEN	8		/* abs minimum */

/*
 * Definition of icmp type and code field values.
 */

#define	ICMP_ECHOREPLY		0		/* echo reply */
#define	ICMP_UNREACH		3		/* dest unreachable, codes: */
#define		ICMP_UNREACH_NET	0		/* bad net */
#define		ICMP_UNREACH_HOST	1		/* bad host */
#define		ICMP_UNREACH_PROTOCOL	2		/* bad protocol */
#define		ICMP_UNREACH_PORT	3		/* bad port */
#define		ICMP_UNREACH_NEEDFRAG	4		/* IP_DF caused drop */
#define		ICMP_UNREACH_SRCFAIL	5		/* src route failed */
#define	ICMP_SOURCEQUENCH	4		/* packet lost, slow down */
#define	ICMP_REDIRECT		5		/* shorter route, codes: */
#define		ICMP_REDIRECT_NET	0		/* for network */
#define		ICMP_REDIRECT_HOST	1		/* for host */
#define		ICMP_REDIRECT_TOSNET	2		/* for tos and net */
#define		ICMP_REDIRECT_TOSHOST	3		/* for tos and host */
#define	ICMP_ECHO		8		/* echo service */
#define	ICMP_TIMXCEED		11		/* time exceeded, code: */
#define		ICMP_TIMXCEED_INTRANS	0		/* ttl==0 in transit */
#define		ICMP_TIMXCEED_REASS	1		/* ttl==0 in reass */
#define	ICMP_PARAMPROB		12		/* ip header bad */
#define	ICMP_TSTAMP		13		/* timestamp request */
#define	ICMP_TSTAMPREPLY	14		/* timestamp reply */
#define	ICMP_IREQ		15		/* information request */
#define	ICMP_IREQREPLY		16		/* information reply */
#define	ICMP_MASKREQ		17		/* address mask request */
#define	ICMP_MASKREPLY		18		/* address mask reply */

/*
 * Definitions needed for the udp header structure.
 */

#define uh_sport	source
#define uh_dport	dest
#define uh_ulen		len
#define uh_sum		check

/*
 * Definitions needed for the tcp header structure.
 */

#if 0
#define th_sport	source
#define th_dport	dest
#endif

/*
 * Some IP options have different names as well.
 */

#ifndef IPOPT_SECURITY
#define IPOPT_SECURITY	IPOPT_SEC
#endif

#ifndef IPOPT_SATID
#define IPOPT_SATID	IPOPT_SID
#endif

#endif /* __FAVOR_BSD */

#endif /* linux */
