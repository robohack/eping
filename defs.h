/*
** Declaration of functions.
**
**	@(#)defs.h              e07@nikhef.nl (Eric Wassenaar) 970918
*/

/*
** Internal modules of the ping utility
** ------------------------------------
*/
	/* main.c */

int main		__P((int, char **));
void set_defaults	__P((char *, int, char **));
int getval		__P((char *, char *, int, int));
void fatal		__P((const char *, ...));
void error		__P((const char *, ...));
void check_proto	__P((void));
void get_socket		__P((void));
#ifdef IP_OPTIONS
void set_options	__P((void));
#endif /*IP_OPTIONS*/

	/* ping.c */

void ping		__P((ipaddr_t, int));
sigtype_t ping_alarm	__P((int));
int send_ping		__P((int));
int recv_ping		__P((void));
int wait_ping		__P((int));
int check_ping		__P((u_char *, int));
int check_fail		__P((struct icmp *, int));
sigtype_t print_stats	__P((int));
sigtype_t prefinish	__P((int));
sigtype_t finish	__P((int));
void cleanup		__P((void));

	/* dump.c */

void print_icmph	__P((struct icmp *, int));
void print_ippkt	__P((struct ip *, int));
void print_iphdr	__P((struct ip *, int));
#ifdef IP_OPTIONS
void print_options	__P((u_char *, int));
void print_route	__P((u_char *));
bool check_route	__P((u_char *, int));
#endif /*IP_OPTIONS*/

	/* util.c */

char *pr_port		__P((char *, u_int));
char *pr_addr		__P((struct in_addr));
char *inetname		__P((struct in_addr));
char *maphostbyaddr	__P((struct in_addr));
void print_gen_stats	__P((stats *));
void print_timing_stats	__P((stats *));
void record_stats	__P((stats *, time_t));
void clear_stats	__P((stats *));
void update_hosts	__P((struct in_addr, bool, time_t));
void show_hosts		__P((void));
#ifdef IP_OPTIONS
void update_routes	__P((u_char *, int, bool, time_t));
void show_routes	__P((void));
#endif /*IP_OPTIONS*/
void show_missed	__P((void));
void c_put		__P((char *));
sigtype_t setwindow	__P((int));
time_t tvsub		__P((struct timeval *, struct timeval *));
char *tvprint		__P((time_t));
u_short in_checksum	__P((u_short *, int));
ipaddr_t getgate	__P((char *));
bool gatewayaddr	__P((struct in_addr));
bool bcast_addr		__P((struct in_addr));

	/* misc.c */

char *maxstr		__P((char *, int, bool));
ptr_t *xalloc		__P((ptr_t *, siz_t));
char *itoa		__P((int));
double xsqrt		__P((double));

	/* host.c */

void get_targets	__P((int, char **));
void add_host		__P((char *));

	/* omni.c */

#ifdef OMNINET
int initdevice		__P((char *));
#endif /*OMNINET*/

/*
** External library functions
** --------------------------
*/
	/* extern */

#if !defined(NO_INET_H)
#include <arpa/inet.h>
#else

ipaddr_t inet_addr	__P((CONST char *));
char *inet_ntoa		__P((struct in_addr));

#endif

	/* avoid <strings.h> */

#if !defined(index)

char *index		__P((const char *, int));
char *rindex		__P((const char *, int));

#endif

	/* <string.h> */

#if !defined(NO_STRING_H)
#include <string.h>
#else

char *strcpy		__P((char *, const char *));
char *strncpy		__P((char *, const char *, siz_t));

#endif

	/* <stdlib.h> */

#if defined(__STDC__) && !defined(apollo)
#include <stdlib.h>
#else

char *getenv		__P((const char *));
ptr_t *malloc		__P((siz_t));
ptr_t *realloc		__P((ptr_t *, siz_t));
free_t free		__P((ptr_t *));
void exit		__P((int));

#endif

	/* <unistd.h> */

#if defined(__STDC__) && !defined(apollo)
#include <unistd.h>
#else

unsigned int alarm	__P((unsigned int));

#endif
