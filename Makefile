CFLAGS = -g -Wall
LDFLAGS = -g
CC = gcc
LIBS_PATH = -L.
LDLIBS = $(LIBS_PATH) -lrsa -lm

test: test.c rsa.c rsa.h
	gcc -o test test.c rsa.c rsa.h

clean:
	rm -f *.o a.out rsa.o rsa librsa.a
