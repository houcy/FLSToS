CC = gcc
CFLAGS = -Wall -ggdb
LDFLAGS = 
TOSSERVER = tosserver
TOSCLIENT = tosclient

all: $(TOSSERVER) $(TOSCLIENT)

$(TOSSERVER): tosserver.o tun.o uucode.o dns.o

$(TOSCLIENT): tosclient.o tun.o uucode.o dns.o

tosserver.o:

tosclient.o:

tun.o:

uucode.o:

dns.o:

clean:
	rm -f tosserver tosclient *.o core
