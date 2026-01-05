CC = clang
# flags from https://nullprogram.com/blog/2023/04/29/
CFLAGS = -g -fdebug-info-for-profiling -fdebug-macro  -Wall -Wextra -Werror -pedantic -Wdouble-promotion -Wconversion -Wno-sign-conversion -I BearSSL/inc -I ~/code/c/bmm -fsanitize=address,undefined -fsanitize-trap
LDFLAGS = -fuse-ld=wild -fsanitize=address,undefined -fsanitize-trap
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
