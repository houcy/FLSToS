/*
 * $Id: dns.c,v 1.3 2004/10/11 19:35:17 noah Exp $
 *
 */


#include "common.h"


// Max DNS label lengths (label1.label2.label3.serial.tun.domain.tld)
#define LABELSIZE	63


u_short serial;


char *dns_build_q(char *basedomain, char *data, int *dlen) {
	char *buf, *encoded, *p, serialbuf[7];
	int i, off, blen, pos;
	u_short u;
	HEADER h;


	// uucode data
	encoded = uuencode(data, *dlen);

	// calculate buffersize
	blen = sizeof(h);
	blen += 1 + strlen(encoded) + strlen(encoded)/LABELSIZE + 1;
	blen += 6;				// u_short
	blen += strlen(basedomain) + 1;		// tun.xxx.org.
	blen += 4;				// tail

	buf = (char *)malloc(blen);
	memset(buf, 0, blen);

	// setup dns header
	memset(&h, 0, sizeof(h));
	h.id = rand()%0xffff;
	h.qdcount = htons(1);
	h.opcode = 0;
	h.rd = 1;
	memcpy(buf, &h, sizeof(h));
	p = buf + sizeof(h);

	// serial
	if(!serial)
		serial = rand()%0xffff;
	sprintf(serialbuf, "%05u.", (u_short)serial++);

	// bygg hostname
	*p = '.';
	for(i = 0, off = 1; i < strlen(encoded); i++) {
		if(i && (i % LABELSIZE) == 0) {
			p[i+off] = '.';
			off++;
		}

		p[i+off] = encoded[i];
	}
	p[i+off] = '.';
	strcat(p, serialbuf);
	strcat(p, basedomain);

	// konvertera punkterna till längder på labels
	for(i = 1, pos = 0; p[i]; i++) {
		if(p[i] != '.')
			continue;
		p[pos] = i - pos - 1;
		pos = i;
	}

	p[pos] = i - pos - 1;



	*dlen = blen;
	blen = sizeof(h) + strlen(p) + 1;
	u = htons(1);	// Host address
	memcpy(buf+blen, &u, 2);
	blen += 2;
	u = htons(1);	// Internet address
	memcpy(buf+blen, &u, 2);
	blen += 2;

	// XXX - temp!
	for(i = 0; i < blen; i++)
		off ^= buf[i];

	*dlen = blen;
	return buf;
}


char *dns_decode_q(char *data, int dlen, char *basedomain, int *decoded_len) {
	char *buf, *decoded, *p, *dnsdata;
	int i, off, len;
	HEADER *h;

	dnsdata = data + sizeof(HEADER);

     	// Ta bort tunneldomänen samt serial (inkl. '.' före serial).
	p = strstr(dnsdata, basedomain);
	if(!p)
		return NULL;

	for(p -= 1; p >= dnsdata && *p != '.'; p--);
	*p = 0;
	

	// Gör om datat till en enda lång sträng
	// buffer som kommer hålla avkodat data
	buf = (char *)malloc(strlen(dnsdata));
	memset(buf, 0, strlen(dnsdata));

	// Gor om till en enda lång sträng
	for(i = len = 0, off = 0; dnsdata[i]; i += 1 + len, off++) {
		len = (u_char)dnsdata[i];
		memcpy(buf + i - off, dnsdata + 1 + i, len);
	}


	// uudecoda DNS-frågan (som är ett IP-datagram)
	decoded = uudecode(buf, decoded_len);

	// ..så vi kan skicka tillbaka samma data till servern
	// och ha svaret satt till "no such name"
	dnsdata[strlen(dnsdata)] = 0;
	h = (HEADER *)data;
	h->qr = 1;
	h->opcode = 0;
	h->aa = 1;
	h->tc = 0;
	h->rd = 1;
	h->ra = 1;
	h->ad = 0;
	h->rcode = 3;	// no such name
	
	return decoded;
}
