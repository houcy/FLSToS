/*
 * $Id: tosserver.c,v 1.3 2004/10/11 19:35:17 noah Exp $
 *
 */


#include "common.h"

struct client {
	int fd;
	time_t lastseen;
	struct in_addr tun_right_ip;
	struct in_addr clientip;
	struct client *next;
} *clients;



struct client *client_new(void) {
	struct client *c = clients;

	while(c && c->next)
		c = c->next;
	if(c == NULL) {
		clients = malloc(sizeof(struct client));
		c = clients;
	}
	else {
		c->next = malloc(sizeof(struct client));
		c = c->next;
	}

	c->next = NULL;
	c->clientip.s_addr = 0;
	c->tun_right_ip.s_addr = 0;
	c->lastseen = time(NULL);
	// Allokera tunnel interface
	c->fd = tun_get_device();

	return c;
}


void client_del(struct client *bad) {
	struct client *c = clients;
	char cmdline[1000];

	if(c == bad)
		clients = c->next;
	else {
		while(bad != c->next)
			c = c->next;

		c->next = c->next->next;
	}


	// Ta bort firewall regler..
	printf("[i] Tar bort SNAT konfiguration med iptables\n");

	sprintf(cmdline, "/sbin/iptables -D FORWARD -i tun%d -j ACCEPT", c->fd);
	printf("[i] %s\n", cmdline);
	system(cmdline);

	sprintf(cmdline, "/sbin/iptables -D FORWARD -o tun%d -j ACCEPT", c->fd);
	printf("[i] %s\n", cmdline);
	system(cmdline);

	sprintf(cmdline, "/sbin/iptables -t nat -D POSTROUTING -s %s -j MASQUERADE", inet_ntoa(c->tun_right_ip));
	printf("[i] %s\n", cmdline);
	system(cmdline);

	printf("[i] Klart!\n");
			

	close(bad->fd);
	free(bad);
}


struct client *client_get_by_ipdata(char *data) {
	struct in_addr i;
	struct client *c;

	// Kopiera källadressen (klienten's remote ip på tunneln, right ip på servern)
	memcpy(&i, data + 12, sizeof(struct in_addr));

	for(c = clients; c; c = c->next) {
		if(i.s_addr == c->tun_right_ip.s_addr)
			return c;

		// XXX - debug
		printf("[d] Client@%s didn't match ", inet_ntoa(c->tun_right_ip));
		printf("%s\n", inet_ntoa(i));
	}

	return c;
}


void client_dump(void) {
	struct in_addr i;
	struct client *c;

	if(clients)
		printf("[i] =================== Listar klienter ===================\n");
	else
		printf("[i] =============== Inga anslutna klienter ================\n");

	for(c = clients; c; c = c->next) {
		printf("[i] %-16s  ", inet_ntoa(c->clientip));
		i.s_addr = c->tun_right_ip.s_addr - htonl(1);
		printf("tun%-2d  %s<->", c->fd, inet_ntoa(i));
		printf("%s\n", inet_ntoa(c->tun_right_ip));
	}

	if(clients)
		printf("[i] =======================================================\n");
}


void ctrlc(int s) {
	while(clients)
		client_del(clients);

	exit(0);
}

int main(int argc, char **argv) {
	unsigned char buf[0xffff], *p, *tun_domain, temp[20];
	int external_fd, max_fd;
	int data_port, sasize;
	int i, len, ret;
	struct sockaddr_in sin;
	struct client *c;
	struct timeval tv;
	fd_set rfds;


	if(argc < 4) {
		fprintf(stderr, "Usage: %s <domain> <external ip> <dataport>\n", argv[0]);
		fprintf(stderr, "\t<domain> - Domän med NS-pekare som pekar till external ip\n");
		fprintf(stderr, "\t<external ip> - Utpekad av NS-pekare. Används för datautbyte.\n");
		fprintf(stderr, "\t<dataport> - Port klienterna lyssnar på\n");
		return 1;
	}


	tun_domain = strdup(argv[1]);
	data_port = atoi(argv[3]);

	printf("FLSToS - (c) 2002,2004 #HACK.SE\n\n");
	signal(SIGINT, ctrlc);


	// Används för att skicka IP-trafik över UDP till tosclient
	if((external_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		perror("socket(world_fd)");
		return 1;
	}


	// Bind till <external ip>:53
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = PF_INET;
	sin.sin_addr.s_addr = inet_addr(argv[2]);
	sin.sin_port = htons(53);
	if(bind(external_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("[!] Kunde inte binda till <external ip:53>");
		return -1;
	}


	// Printa ut lite info
	srand(time(NULL));
	printf("[i] Domän:\t%s\n", argv[1]);
	printf("[i] Externt IP: %s\n", argv[2]);
	printf("[i] Klient port: %d\n", data_port);
	printf("[i] Väntar på konfigureringstrafik..\n\n");


	// Konvertera punkterna i domänen till label lenghts
        p = strchr(tun_domain, '.');
        for(i = 0; p[i]; i++) {
		if(p[i] != '.')
			continue;
	
		*p = i - 1;
		p += i;
		i = 0;
	}
	*p = i - 1;


	while(1) {
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		FD_SET(external_fd, &rfds);
		max_fd = external_fd;
		for(c = clients; c; c = c->next) {
			if(c->fd > max_fd)
				max_fd = c->fd;
			FD_SET(c->fd, &rfds);
		}

		tv.tv_sec = 60;
		tv.tv_usec = 0;
		ret = select(max_fd+1, &rfds, NULL, NULL, &tv);
		if(ret < 0) {
			if(errno == EINTR)
				continue;
			perror("select()");
			break;
		}


		if(FD_ISSET(0, &rfds)) {
			read(0, buf, sizeof(buf));
			client_dump();
		}

		// Ta emot (NAT) trafik som ska till klienten via tunneln
		// och skicka vidare den i ett UDP-paket över internet till
		// klienten
		for(c = clients; c; c = c->next) {
			if(!FD_ISSET(c->fd, &rfds)) {
				if(c->lastseen + 3600 < time(NULL)) {
					client_del(c);
					break;
				}

				continue;
			}

			c->lastseen = time(NULL);
			len = read(c->fd, buf, sizeof(buf));
			if(len <= 0) {
				printf("[i] Disconnecting client@%s", inet_ntoa(c->clientip));
				fflush(stdout);
				perror("");
				client_del(c);
				break;
			}

			printf("[i] <== % 5d bytes via tun%d for client@%s\n", len, c->fd, inet_ntoa(c->clientip));
			memset(&sin, 0, sizeof(sin));
			sin.sin_port = htons(data_port);
			sin.sin_addr = c->clientip;
			ret = sendto(external_fd, buf, len, 0, (struct sockaddr *)&sin, sizeof(sin));
			printf("[i] ==> % 5d bytes to client@%s\n", ret, inet_ntoa(c->clientip));
			if(ret <= 0) {
				printf("[i] Disconnecting client@%s", inet_ntoa(c->clientip));
				fflush(stdout);
				perror("");
				client_del(c);
				break;
			}

		}


		// Ta emot trafik fran DNS
		if(FD_ISSET(external_fd, &rfds)) {
			sasize = sizeof(sin);
			memset(&sin, 0, sasize);
			len = recvfrom(external_fd, buf, sizeof(buf), 0,
					(struct sockaddr *)&sin, &sasize);

			printf("[i] DNS paket (%d bytes) från %s\n", len, inet_ntoa(sin.sin_addr));

			// Vi har tagit emot ett DNS-paket på port53
			// Försök koda av det och gör om originalpaketet till
			// ett giltigt DNS-svar.
			p = dns_decode_q(buf, len, tun_domain, &ret);
			if(!p) {
				printf("[i] DNS avkodning misslyckades.\n");
				continue;
			}

			// Skicka tillbaka svaret (redan fixat i dns_decode_q)
			sin.sin_port = htons(53);
			sendto(external_fd, buf, len, 0, (struct sockaddr *)&sin, sizeof(sin));
			printf("[i] DNS svar skickat\n");


			// Är det ett konfigureringspaket för ny klient?
			if(p[0] == 0x50) {
				sprintf(temp, "%d.%d.%d.%d", p[1], p[2], p[3], p[4]);
				c = client_new();
				c->clientip.s_addr = inet_addr(temp);
				printf("[i] Ny klient med IP %s fick tunnel tun%d\n", temp, c->fd);

				c->tun_right_ip.s_addr = tun_config(c->fd, 1500, 0, 0);

				// Konfigurera brandväggen
				{
					char cmdline[1000];
					printf("[i] Konfigurerar SNAT med iptables\n");
					sprintf(cmdline, "/sbin/iptables -A FORWARD -i tun%d -j ACCEPT", c->fd);
					printf("[i] %s\n", cmdline);
					system(cmdline);
					sprintf(cmdline, "/sbin/iptables -A FORWARD -o tun%d -j ACCEPT", c->fd);
					printf("[i] %s\n", cmdline);
					system(cmdline);
					sprintf(cmdline, "/sbin/iptables -t nat -A POSTROUTING -s %s -j MASQUERADE", inet_ntoa(c->tun_right_ip));

					printf("[i] %s\n", cmdline);
					system(cmdline);
				}

				// Bygg svarspaket med 0x50 + klientens IP leftside IP för tunneln (rightside på serversidan)
				temp[0] = 0x50;
				memcpy(temp + 1, &c->tun_right_ip, sizeof(c->tun_right_ip));
				len = 5;

				// Skicka konfigurationsinformation till klienten
				memset(&sin, 0, sizeof(sin));
				sin.sin_family = PF_INET;
				sin.sin_port = htons(data_port);
				sin.sin_addr = c->clientip;
				ret = sendto(external_fd, temp, len, 0, (struct sockaddr *)&sin, sizeof(sin));
				if(ret <= 0) {
					printf("[i] Disconnecting client@%s", inet_ntoa(c->clientip));
					fflush(stdout);
					perror("");
					client_del(c);
					break;
				}

				printf("[i] Konfigurationssvar (leftip %s)", inet_ntoa(c->tun_right_ip));
				printf(" skickat till %s\n", inet_ntoa(c->clientip));
			}
			else if((c = client_get_by_ipdata(p))) {
				c->lastseen = time(NULL);
				ret = write(c->fd, p, ret);
				printf("[i] ==> % 5d bytes till tun%d (klient@%s)\n", ret, c->fd, inet_ntoa(c->clientip));
			}
			else {
				memcpy(&sin.sin_addr, p + 12, sizeof(sin.sin_addr));
				printf("[d] Kunde inte hitta klienten med tunnel IP %s\n", inet_ntoa(sin.sin_addr));
			}

			free(p);
			

		}
	}

	close(external_fd);
	while(clients)
		client_del(clients);

	return 0;
}
