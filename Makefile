CC = gcc
CFLAGS = -Wall -Wextra

all: server client

server: server.c common.o
	$(CC) $(CFLAGS) -o server server.c common.o

client: client.c common.o
	$(CC) $(CFLAGS) -o client client.c common.o

common.o: common.c common.h
	$(CC) $(CFLAGS) -c common.c

clean:
	rm -f server client common.o

