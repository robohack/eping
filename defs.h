/*
** Declaration of functions.
**
**	@(#)defs.h              e07@nikhef.nl (Eric Wassenaar) 950909
*/

/* extern */
ipaddr_t inet_addr	PROTO((char *));
char *inet_ntoa		PROTO((struct in_addr));
char *rindex		PROTO((char *, char));
char *strcpy		PROTO((char *, char *));
char *malloc		PROTO((int));
void exit		PROTO((int));

/* main.c */
int main		PROTO((int, char **));
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
void send_ping		PROTO((void));
int recv_ping		PROTO((void));
int wait_ping		PROTO((int));
bool check_ping		PROTO((u_char *, int));
bool check_fail		PROTO((struct icmp *, int));
sigtype_t prefinish	PROTO((int));
sigtype_t finish	PROTO((int));
void cleanup		PROTO((void));

/* util.c */
void pr_icmph		PROTO((struct icmp *, int));
void pr_ippkt		PROTO((struct ip *, int));
void pr_iph		PROTO((struct ip *, int));
#ifdef IP_OPTIONS
void pr_options		PROTO((u_char *, int));
void pr_route		PROTO((u_char *));
#endif /*IP_OPTIONS*/
char *pr_addr		PROTO((struct in_addr));
char *pr_port		PROTO((char *, u_short));
void print_stats	PROTO((stats *));
void record_stats	PROTO((stats *, time_t));
void zero_stats		PROTO((stats *));
void update_hosts	PROTO((struct in_addr));
void c_put		PROTO((char *));
void tvsub		PROTO((struct timeval *, struct timeval *));
u_short in_cksum	PROTO((u_short *, int));
bool bcast_addr		PROTO((struct in_addr));

/* misc.c */
char *itoa		PROTO((int));

/* omni.c */
#ifdef OMNINET
int initdevice		PROTO((char *));
#endif /*OMNINET*/
