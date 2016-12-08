CC = gcc
DEBUGFLAGS = -g -Wall
CFLAGS = -pthread -D_REENTRANT -D_XOPEN_SOURCE=500 
LDFLAGS = -lpthread 

all: client

client: btclient.o 
	$(CC) $(CFLAGS) -o client btclient.o 
btclient.o:  btclient.c 
	$(CC) $(CFLAGS) btclient.c -c
clean:
	rm -f *.o client
