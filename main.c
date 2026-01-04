#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "BearSSL/inc/bearssl_ssl.h"
#include "trust_anchors.c"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

// connects to IRC server over IRC via TLS
int host_connect(char *domain, struct addrinfo *info) {
  // from beej's guide to network programming

  // return status code (error number)
  int gai_err;
  // tell getaddrinfo what addresses you're interested in
  struct addrinfo hints;
  // addrinfo pointer for iteration through linked list
  struct addrinfo *p;

  int fd;

  // initialize hints to 0
  memset(&hints, 0, sizeof(hints));
  // we're looking for addresses supporting TCP over either IPv4 or v6, and we
  // want the IP to be filled in
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  // hints.ai_flags = AI_PASSIVE;

  if ((gai_err = getaddrinfo(domain, "6697", &hints, &info)) != 0) {
    fprintf(stderr, "gai error: %s\n", gai_strerror(gai_err));
    exit(1);
  }

  // printf("IP Addresses for %s\n", domain);

  char ipstr[INET6_ADDRSTRLEN];
  // iterate through addrinfos
  for (p = info; p != NULL; p = p->ai_next) {
    void *addr;
    char *ipver;
    struct sockaddr_in *ipv4;
    struct sockaddr_in6 *ipv6;

    // get pointer to address
    if (p->ai_family == AF_INET) {
      ipv4 = (struct sockaddr_in *)p->ai_addr;
      addr = &(ipv4->sin_addr);
      ipver = "IPv4";
    } else {
      ipv6 = (struct sockaddr_in6 *)p->ai_addr;
      addr = &(ipv6->sin6_addr);
      ipver = "IPv6";
    }

    fd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
    if (fd < 0) {
      printf("socket err: %d\n", errno);
      close(fd);
      continue;
    }
    if (connect(fd, p->ai_addr, p->ai_addrlen) < 0) {
      printf("connect err: %d\n", errno);
      close(fd);
      continue;
    }

    // convert the addr into a printable numeric form and write to ipstr
    // get the file descriptor for the socket
    inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
    printf("  %s: %s\n", ipver, ipstr);
    break;
  }

	if (p == NULL) {
		freeaddrinfo(info);
		fprintf(stderr, "ERROR: failed to connect\n");
		return -1;
	}
	freeaddrinfo(info);
	fprintf(stderr, "connected.\n");

  return fd;
}

static int sock_read(void *ctx, unsigned char *buf, size_t len) {
  for (;;) {
    ssize_t rlen;

    rlen = read(*(int *)ctx, buf, len);
    if (rlen <= 0) {
      if (rlen < 0 && errno == EINTR) {
        continue;
      }
      return -1;
    }
    return (int)rlen;
  }
}

static int sock_write(void *ctx, const unsigned char *buf, size_t len) {
  for (;;) {
    ssize_t wlen;
    wlen = write(*(int *)ctx, buf, len);
    if (wlen <= 0) {
      if (wlen < 0 && errno == EINTR) {
        continue;
      }
      return -1;
    }
    return (int)wlen;
  }
}

int main(int argc, char **argv) {
  br_ssl_client_context sc;
  br_x509_minimal_context xc;
  unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
  br_sslio_context ioc;

  char *host = "irc.libera.chat";

  // NOTE: binding not needed as a client program
  // avoid "Address already in use." errors when rerunning the program
  // int yes = 1;
  // setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  // int b_err;
  // if ((b_err = bind(s, info->ai_addr, info->ai_addrlen) != 0)) {
  //   fprintf(stderr, "bind error: %d\n", errno);
  // }

  // output struct for getaddrinfo
  struct addrinfo info;

  int fd = host_connect(host, &info);

  br_ssl_client_init_full(&sc, &xc, TAs, TAs_NUM);

  br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);

  br_ssl_client_reset(&sc, host, 0);

  br_sslio_init(&ioc, &sc.eng, sock_read, &fd, sock_write, &fd);

  // int c_err;
  // if ((c_err = connect(fd, info.ai_addr, sizeof(struct sockaddr))) != 0) {
  //   fprintf(stderr, "connect error: %d\n", errno);
  // }

  // close(fd);
  // freeaddrinfo(&info);

  return 0;
}
