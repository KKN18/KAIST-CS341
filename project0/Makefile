# CS341 Network Project 0
# Jihwan Kim, KAIST

CC = gcc
CFLAGS = -W -Wall

all: client server

client.o:  client.c
	$(CC) $(CFLAGS) -c client.c

server.o: server.c
	$(CC) $(CFLAGS) -c server.c

client: client.o
	$(CC) $(CFLAGS) client.o -o client

server: server.o
	$(CC) $(CFLAGS) server.o -o server

clean:
	rm -f *~ client server *.o

