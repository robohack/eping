#ifndef lint
static char Version[] = "@(#)omni.c	e07@nikhef.nl (Eric Wassenaar) 940225";
#endif

#if defined(apollo) && defined(lint)
#define __attribute(x)
#endif

#ifdef OMNINET

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/fcntlcom.h>
#include <net/nit_if.h>
#include <sys/stropts.h>
#include <net/if.h>

/* extern */
char *strncpy();

/* omni.c */
int initdevice();

/*
** INITDEVICE -- Put ethernet device in promiscuous mode
** -----------------------------------------------------
**
**	Necessary for route recording to work for a SUN
**	running SunOS 4.1.x with the NC400 ethernet board.
*/

int
initdevice(device)
char *device;				/* name of ethernet device */
{
	struct strioctl si;		/* struct for ioctl() */
	struct ifreq ifr;		/* interface request struct */
	u_long if_flags;		/* modes for interface */
	int if_fd;

	if_fd = open("/dev/nit", O_RDONLY);
	if (if_fd < 0)
	{
		perror("/dev/nit");
		return(-1);
	}

	/* request the interface */
	(void) strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = ' ';
	si.ic_cmd = NIOCBIND;
	si.ic_len = sizeof(ifr);
	si.ic_dp = (char*)&ifr;
	if (ioctl(if_fd, I_STR, (char*)&si) < 0)
	{
		perror(ifr.ifr_name);
		(void) close(if_fd);
		return(-1);
	}

	/* set the interface flags */
	si.ic_cmd = NIOCSFLAGS;
	if_flags = NI_PROMISC;
	si.ic_len = sizeof(if_flags);
	si.ic_dp = (char*)&if_flags;
	if (ioctl(if_fd, I_STR, (char*)&si) < 0)
	{
		perror("NI_PROMISC");
		(void) close(if_fd);
		return(-1);
	}

	return(if_fd);
}

#endif /*OMNINET*/
