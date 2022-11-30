CC=gcc
CFLAGS=-Wall
UNAME=$(shell uname)

default: assymetric symetric

assymetric: assymetric.c
	$(CC) $(CFLAGS) -o binaries/$(UNAME)/assymetric assymetric.c -lm
	ln -fs binaries/$(UNAME)/assymetric .

symetric: symetric.c
	$(CC) $(CFLAGS) -o binaries/$(UNAME)/symetric symetric.c
	ln -fs binaries/$(UNAME)/symetric .
