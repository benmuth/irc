CC = clang
CFLAGS = -g -I BearSSL/inc
LDFLAGS = -fuse-ld=wild
LIBS = BearSSL/build/libbearssl.a

irc: main.o trust_anchors.o
	$(CC) $(LDFLAGS) -o irc main.o trust_anchors.o $(LIBS)

main.o: main.c BearSSL/inc/bearssl_ssl.h
	$(CC) $(CFLAGS) -c main.c -o main.o

trust_anchors.o: trust_anchors.c BearSSL/inc/bearssl_x509.h
	$(CC) $(CFLAGS) -c trust_anchors.c -o trust_anchors.o

clean:
	rm -f irc main.o trust_anchors.o

.PHONY: clean
