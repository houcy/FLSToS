/*
 * $Id: tun.c,v 1.3 2004/10/11 19:35:17 noah Exp $
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>


#define TUN_BASE_IP	"192.168.255.0"


int tun_get_device(void) {
	int fd;
	struct ifreq i;

	if((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		perror("open(/dev/net/tun)");
		return -1;
	}

	memset(&i, 0, sizeof(struct ifreq));
	i.ifr_flags = IFF_TUN|IFF_NO_PI;
	sprintf(i.ifr_name, "tun%d", fd);
	if(ioctl(fd, TUNSETIFF, (void *)&i) < 0) {
		close(fd);
		perror("ioctl(tun, set interfacename)");
		return -1;
	}

	return fd;
}


unsigned long tun_config(int tunid, int mtu, unsigned long leftip, int is_client) {
	struct in_addr i;
	char *l, *r, cmdline[255];

	if(leftip == 0)
		leftip = inet_addr(TUN_BASE_IP) + htonl(tunid * 2);

	i.s_addr = leftip;
	l = strdup(inet_ntoa(i));

	if(is_client == 0)
		i.s_addr = leftip + htonl(1);
	else
		i.s_addr = leftip - htonl(1);

	r = strdup(inet_ntoa(i));

	printf("[i] Konfigurerar tun%d: %s <-> %s MTU %d\n", tunid, l, r, mtu);
	sprintf(cmdline, "/sbin/ifconfig tun%d %s pointopoint %s mtu %d", tunid, l, r, mtu);
	system(cmdline);

	// XXX - iptables!!

	free(l);
	free(r);

	// Returnera remote IP
	return i.s_addr;
}


