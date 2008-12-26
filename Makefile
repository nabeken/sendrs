CC = gcc
sendrs: sendrs.c
	$(CC) -D_GNU_SOURCE -o sendrs sendrs.c
