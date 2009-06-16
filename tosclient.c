/*
 * $Id: tosclient.c,v 1.3 2004/10/11 19:35:17 noah Exp $
 *
 */

#include "common.h"


int main(int argc, char **argv) {
	unsigned char buf[0xffff], *p, *tun_domain;
	int tun_fd, dns_fd, data_fd, data_port, sasize, i, mtu;
	int len, ret, dnscount, dnsindex;
	u_long *dnsips;
	struct sockaddr_in sin;
	fd_set rfds;

	if(argc < 5) {
		fprintf(stderr, "Usage: %s <domain> <external ip> <dataport> <dns1[,dns2,..]> [mtu]\n", argv[0]);
		fprintf(stderr, "\tdomain - Domän med NS-pekare till servern\n");
		fprintf(stderr, "\texternal ip - Adress där vi lyssnar efter inkommande UDP-paket\n");
		fprintf(stderr, "\tdataport - Port där vi lyssnar efter inkommande UDP-paket\n");
		fprintf(stderr, "\tdns - 10.0.0.1,10.0.0.2 (comhem/adsl) eller 10.0.0.6 (homerun)\n");
		fprintf(stderr, "\tmtu - MTU för tunnelinterfacet\n");
		return 1;
	}


	printf("FLSToS - (c) 2002,2004 #HACK.SE\n\n");
	tun_domain = argv[1];
	data_port = atoi(argv[3]);
	if(argc == 6)
		mtu = atoi(argv[5]);
	else
		mtu = 164; // Med 164 går det att SSH'a..


	// DNS round robin!
	srand(time(NULL));
	dnscount = 0;
	dnsips = NULL;
	p = strtok(argv[4], ",");
	do {
		dnsips = (u_long *)realloc(dnsips, sizeof(u_long) * ++dnscount);
		dnsips[dnscount-1] = inet_addr(p);
	} while((p = strtok(NULL, ",")));


	// Skapa tunnel att skicka IP-trafik till som tas emot på dataporten
	if((tun_fd = tun_get_device()) < 0) {
		fprintf(stderr, "[!] Kunde inte skapa tunnel!\n");
		return -1;
	}

	// Används för att skicka DNS-requests 
	dns_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(dns_fd < 0) {
		perror("socket(dns_fd)");
		return 1;
	}

	sasize = sizeof(sin);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = PF_INET;
	sin.sin_port = htons(0);
	sin.sin_addr.s_addr = inet_addr(argv[2]);
	if(bind(dns_fd, (struct sockaddr *)&sin, sasize) < 0) {
		perror("bind(external ip)");
		return 1;
	}


	// Används för att ta emot IP-trafik kapslad i UDP
	data_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(data_fd < 0) {
		perror("socket(data_fd)");
		return 1;
	}


	sasize = sizeof(sin);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = PF_INET;
	sin.sin_port = htons(data_port);
	sin.sin_addr.s_addr = inet_addr(argv[2]);
	if(bind(data_fd, (struct sockaddr *)&sin, sasize) < 0) {
		perror("bind(external ip:data port)");
		return 1;
	}

	printf("[i] Domän: %s\n", tun_domain);
	printf("[i] Tunnel interface: tun%d\n", tun_fd);
	printf("[i] Externt IP: %s\n", argv[2]);
	printf("[i] Inkommande UDP port: %d\n", data_port);

	// Informera server om att vi vill kora
	buf[0] = 0x50;
	p = strtok(inet_ntoa(sin.sin_addr), ".");
	i = 1;
	do { 
	  buf[i] = atoi(p);
	  i++;
	} while((p = strtok(NULL, ".")));
	free(p);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = PF_INET;
	sin.sin_addr.s_addr = dnsips[0];
	sin.sin_port = htons(53);
	ret = strlen(buf);
	p = dns_build_q(tun_domain, buf, &ret);
	ret = sendto(data_fd, p, ret, 0, (struct sockaddr *)&sin, sizeof(sin));
	printf("[i] Gjorde konfigurationsanrop till servern via %s\n", inet_ntoa(sin.sin_addr));



	// Vänta på konfigureringsparametrar..
	printf("[i] Väntar på svar..\n");
	for(;;) {
		memset(buf, 0, sizeof(buf));
		ret = read(data_fd, buf, sizeof(buf));
		if(*buf != 0x50) {
			// Strunta i trafik som inte är för konfigurationen..
			printf(".");
			fflush(stdout);
			continue;
		}

		printf("\n");

		tun_config(tun_fd, mtu, *(unsigned long *)((char *)buf+1), 1);

		printf("[i] =========== Tunneln konfigurerad! ===========\n");
		printf("[i] Se till att routa trafik via tun%d\n", tun_fd);
		printf("[i] Exempel för ping.sunet.se's subnet:\n");
		printf("[i] # route add -net 130.242.80.0/24 dev tun%d\n", tun_fd);
		printf("[i] =============================================\n");
		
		break;
	}

	memset(buf, 0, sizeof(buf));
	dnsindex = 0;
	while(1) {
		FD_ZERO(&rfds);
		FD_SET(tun_fd, &rfds);
		FD_SET(data_fd, &rfds);
		ret = select(data_fd+1, &rfds, NULL, NULL, NULL);
		if(ret < 0) {
			if(errno == EINTR)
				continue;
			perror("select()");
			break;
		}

		// Läs utgående trafik från tunnel och skicka över DNS till
		// servern
		if(FD_ISSET(tun_fd, &rfds)) {
			len = ret = read(tun_fd, buf, sizeof(buf));
			printf("[i] tun%d <== %d bytes\n", tun_fd, ret);

			// Koda datat som en DNS-request och skicka till en NS
			p = dns_build_q(tun_domain, buf, &ret);

			// Skicka till en av telia's DNS-servrarna
			memset(&sin, 0, sizeof(sin));
			sin.sin_family = PF_INET;
			sin.sin_addr.s_addr = dnsips[dnsindex];
			if(++dnsindex == dnscount)
				dnsindex = 0;
			sin.sin_port = htons(53);
			ret = sendto(dns_fd, p, ret, 0, (struct sockaddr *)&sin, sizeof(sin));
			printf("[i] DNS ==> %d bytes (ID %d)\n", ret, ((HEADER *)p)->id);
			free(p);
		}


		if(FD_ISSET(data_fd, &rfds)) {
			sasize = sizeof(sin);
			memset(&sin, 0, sasize);

			// Ta emot inkommande data från servern och skriv det
			// till tunnelinterfacet så datorn "ser" den
			len = recvfrom(data_fd, buf, sizeof(buf), 0,
					(struct sockaddr *)&sin, &sasize);

			ret = write(tun_fd, buf, len);
			printf("[i] %s ==> dataport %d (%d bytes) ==> tun%d (%d bytes)\n", inet_ntoa(sin.sin_addr), data_port, len, tun_fd, len);
		}
	}

	close(tun_fd);

	return 0;
}
