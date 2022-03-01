/*
** Various portability definitions.
**
**	@(#)port.h              e07@nikhef.nl (Eric Wassenaar) 990511
*/

#if defined(__SVR4) || defined(__svr4__)
#define SVR4
#endif

#if defined(SYSV) || defined(SVR4)
#define SYSV_MALLOC
#define SYSV_MEMSET
#define SYSV_STRCHR
#define SYSV_SETVBUF
#endif

#if defined(__hpux) || defined(hpux)
#define SYSV_MALLOC
#define SYSV_SETVBUF
#endif

#if defined(sgi)
#define SYSV_MALLOC
#endif

#if defined(linux)
#define SYSV_MALLOC
#endif

#if defined(bsdi) || defined(__bsdi__)
#define SYSV_MALLOC
#endif

#if defined(NeXT)
#define SYSV_MALLOC
#endif

/*
** Distinguish between various BIND releases.
*/

#if defined(RES_PRF_STATS)
#define BIND_49
#else
#define BIND_48
#endif

#if defined(BIND_49) && defined(__BIND)
#define BIND_493
#endif

/*
** On some platforms a raw IP packet must be in network byte order.
** Most systems require certain fields in machine byte order,
** and perform the htons()/ntohs() conversion within the kernel.
** Some systems require everything to be in network order.
** Note that this is relevant only for little-endian machines.
*/

#if defined(sun) && defined(SVR4)
#define RAW_IP_NET_ORDER
#endif

#if defined(linux)
#define RAW_IP_NET_ORDER
#endif

/*
** Define constants for fixed sizes.
*/

#ifndef INT16SZ
#define	INT16SZ		2	/* for systems without 16-bit ints */
#endif

#ifndef INT32SZ
#define	INT32SZ		4	/* for systems without 32-bit ints */
#endif

#ifndef INADDRSZ
#define	INADDRSZ	4	/* for sizeof(struct inaddr) != 4 */
#endif

/*
** The following should depend on existing definitions.
*/

typedef int	bool;		/* boolean type */
#define TRUE	1
#define FALSE	0

#if defined(BIND_48) || defined(OLD_RES_STATE)
typedef struct state		res_state_t;
#else
typedef struct __res_state	res_state_t;
#endif

#ifndef _IPADDR_T
#if defined(__alpha) || defined(BIND_49)
typedef u_int	ipaddr_t;
#else
typedef u_long	ipaddr_t;
#endif
#endif

#if defined(apollo) || defined(_BSD_SIGNALS)
typedef int	sigtype_t;
#define sig_return(n)	return(n)
#else
typedef void	sigtype_t;
#define sig_return(n)	return
#endif

#ifdef SYSV_MALLOC
typedef void	ptr_t;		/* generic pointer type */
typedef u_int	siz_t;		/* general size type */
typedef void	free_t;
#else
typedef char	ptr_t;		/* generic pointer type */
typedef u_int	siz_t;		/* general size type */
typedef int	free_t;
#endif

#ifdef SYSV_MEMSET
#define bzero(a,n)	(void) memset(a,'\0',n)
#define bcopy(a,b,n)	(void) memcpy(b,a,n)
#define bcmp(a,b,n)	memcmp(b,a,n)
#endif

#ifdef SYSV_STRCHR
#define index		strchr
#define rindex		strrchr
#endif

#ifdef SYSV_SETVBUF
#define linebufmode(a)	(void) setvbuf(a, (char *)NULL, _IOLBF, BUFSIZ);
#else
#define linebufmode(a)	(void) setlinebuf(a);
#endif

#if defined(SVR4)
#define jmp_buf		sigjmp_buf
#define setjmp(e)	sigsetjmp(e,1)
#define longjmp(e,n)	siglongjmp(e,n)
#endif

#if defined(sun) && defined(NO_YP_LOOKUP)
#define gethostbyname	(struct hostent *)res_gethostbyname
#define gethostbyaddr	(struct hostent *)res_gethostbyaddr
#endif

/*
 * FreeBSD (and Darwin in its image) is a bit brain-dead in the way they do
 * their multiple typedef avoidance -- i.e. they still follow the ancient
 * 4.4BSD style of using the fact that _BSD_SOCKLEN_T_ is NOT defined in order
 * to typedef socklen_t at the earliest point it's needed.  However they leave
 * no means for applications to know if the typedef has already been done.
 *
 * The most elegant way to protect typedefs is to prefix the type name with
 * "__" for the typedef and then use a CPP #define to map the true unprefixed
 * name to the actual typedef name.  This way the presence of the type name as
 * a #define tells us that the typedef for it has already been done.
 *
 * All the other schemes are just inelegant hacks, but at least they're better
 * than having to know the details of individual OS library implementations!
 *
 * FYI: In NetBSD socklen_t came into use just before 1.3J:
 *
 *	(__NetBSD_Version__ - 0) > 103100000
 *
 * Not sure when GNU LibC added socklen_t, but it's in 2.1 at least.
 */
#if (defined(__FreeBSD__) || defined(__darwin__)) && defined(_BSD_SOCKLEN_T_)
# include "ERROR: something's wrong with the #includes above!"
#endif
/* Sigh, standards are such wonderful things.... */
#if !defined(socklen_t) && \
    !defined(__FreeBSD__) && !defined(__darwin__) && \
    !defined(_SOCKLEN_T) && !defined(__socklen_t_defined) && \
    (!defined(__GLIBC__) || (__GLIBC__ - 0) < 2) && \
    (!defined(__GLIBC_MINOR__) || (__GLIBC_MINOR__ - 0) < 1)
# if (/* SunOS-4 gcc */defined(__sun__) && !defined(__svr4__)) || \
     (/* SunOS-4 cc */defined(sun) && defined(unix) && !defined(__svr4__)) || \
     (/* 4.3BSD */defined(BSD) && ((BSD - 0) > 0) && ((BSD - 0) < 199506))
typedef int		__socklen_t;	/* 4.3BSD and older */
# else
typedef size_t		__socklen_t;	/* P1003.1g socket-related datum length */
# endif
typedef __socklen_t	socklen_t;
# define socklen_t	__socklen_t
#endif

#if !defined(__STDC__) || defined(apollo)
#define const
#endif

#ifndef __P		/* in *BSD's <sys/cdefs.h>, included by everything! */
# if ((__STDC__ - 0) > 0) || defined(__cplusplus)
#  define __P(protos)	protos		/* full-blown ANSI C */
# else
#  define __P(protos)	()		/* traditional C */
# endif
#endif

#ifndef const		/* in *BSD's <sys/cdefs.h>, included by everything! */
# if ((__STDC__ - 0) <= 0) || defined(apollo)
#  define const		/* NOTHING */
# endif
#endif

#ifdef __STDC__
# define VA_START(args, lastarg)       va_start(args, lastarg)
#else
# define VA_START(args, lastarg)       va_start(args)
#endif
