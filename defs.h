/*
** Declaration of functions.
**
**	@(#)defs.h              e07@nikhef.nl (Eric Wassenaar) 960314
*/

/*
** Internal modules of the ping utility
** ------------------------------------
*/

	/* main.c */

int main		PROTO((int, char **));
void set_defaults	PROTO((char *, int, char **));
int getval		PROTO((char *, char *, int, int));
void fatal		PROTO((char *, ...));
void error		PROTO((char *, ...));
void check_proto	PROTO((void));
void get_socket		PROTO((void));
#ifdef IP_OPTIONS
void set_options	PROTO((void));
#endif /*IP_OPTIONS*/


	/* ping.c */

void ping		PROTO((ipaddr_t, int));
sigtype_t ping_alarm	PROTO((int));
int send_ping		PROTO((int));
int recv_ping		PROTO((void));
int wait_ping		PROTO((int));
int check_ping		PROTO((u_char *, int));
int check_fail		PROTO((struct icmp *, int));
sigtype_t prefinish	PROTO((int));
sigtype_t finish	PROTO((int));
void cleanup		PROTO((void));


	/* util.c */

void print_icmph	PROTO((struct icmp *, int));
void print_ippkt	PROTO((struct ip *, int));
void print_iphdr	PROTO((struct ip *, int));
#ifdef IP_OPTIONS
void print_options	PROTO((u_char *, int));
void print_route	PROTO((u_char *));
bool check_route	PROTO((u_char *, int));
#endif /*IP_OPTIONS*/
char *pr_port		PROTO((char *, u_short));
char *pr_addr		PROTO((struct in_addr));
char *inetname		PROTO((struct in_addr));
char *maphostbyaddr	PROTO((struct in_addr));
void print_stats	PROTO((stats *));
void record_stats	PROTO((stats *, time_t));
void clear_stats	PROTO((stats *));
void update_hosts	PROTO((struct in_addr, bool, time_t));
void show_hosts		PROTO((void));
#ifdef IP_OPTIONS
void update_routes	PROTO((u_char *, int, bool, time_t));
void show_routes	PROTO((void));
#endif /*IP_OPTIONS*/
void show_missed	PROTO((void));
void c_put		PROTO((char *));
sigtype_t setwindow	PROTO((int));
time_t tvsub		PROTO((struct timeval *, struct timeval *));
char *tvprint		PROTO((time_t));
u_short in_checksum	PROTO((u_short *, int));
ipaddr_t getgate	PROTO((char *));
bool gatewayaddr	PROTO((struct in_addr));
bool bcast_addr		PROTO((struct in_addr));


	/* misc.c */

ptr_t *xalloc		PROTO((ptr_t *, siz_t));
char *itoa		PROTO((int));
double xsqrt		PROTO((double));


	/* omni.c */

#ifdef OMNINET
int initdevice		PROTO((char *));
#endif /*OMNINET*/

/*
** External library functions
** --------------------------
*/

	/* extern */

ipaddr_t inet_addr	PROTO((CONST char *));
char *inet_ntoa		PROTO((struct in_addr));
char *index		PROTO((const char *, char));
char *rindex		PROTO((const char *, char));
char *strcpy		PROTO((char *, const char *));
char *getenv		PROTO((const char *));
ptr_t *malloc		PROTO((siz_t));
ptr_t *realloc		PROTO((ptr_t *, siz_t));
void exit		PROTO((int));
