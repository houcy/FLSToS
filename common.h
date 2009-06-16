/*
 * $Id: common.h,v 1.3 2004/10/11 19:35:17 noah Exp $
 *
 */


#ifndef _COMMON_H__
#define _COMMON_H__

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <arpa/nameser_compat.h>
#include <arpa/nameser.h>


/* dns.c */
char *dns_build_q(char *, char *, int *);
char *dns_decode_q(char *, int, char *, int *);


/* tun.c */
int tun_get_device(void);
unsigned long tun_config(int tunid, int mtu, unsigned long leftip, int is_client);


/* uucode.c */
unsigned char* uuencode(unsigned char* ptr,int len);
unsigned char* uudecode(unsigned char* codestr,int* len);


#endif
