CC = gcc  -I curl/include -L curl/lib  
DEBUGFLAGS = -g -Wall 
CFLAGS = -pthread -D_REENTRANT -D_XOPEN_SOURCE=500 
LDFLAGS = -lpthread 

all: btclient

btclient: btclient.o bencode.o
	$(CC) $(CFLAGS) -o btclient btclient.o bencode.o list.o -lssl -lcrypto -lm -lcurl
list.o: utils/list.c utils/list.h
	$(CC) $(CFLAGS) utils/list.c -c
btclient.o: btclient.c error.h
	$(CC) $(CFLAGS) btclient.c -c 
bencode.o: bencoding/bencode.c bencoding/bencode.h 
	$(CC) $(CFLAGS) bencoding/bencode.c -c
clean:
	rm -f *.o btclient
