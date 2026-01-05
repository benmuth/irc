#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define BMM_IMPLEMENTATION
#include "bmm.h"

#include "BearSSL/inc/bearssl_ssl.h"

// Trust anchors declared in trust_anchors.c
extern const br_x509_trust_anchor TAs[];
extern const size_t TAs_NUM;
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

  gai_err = getaddrinfo(domain, "6697", &hints, &info);
  if (gai_err != 0) {
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

    // no error on connection so we've found a working addrinfo
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

int send_msg(br_sslio_context *ioc, char *msg, size_t len) {
  br_sslio_write_all(ioc, msg, len);
  br_sslio_flush(ioc);
  return 0;
}

void register_conn(br_sslio_context *ioc) {
  char *msg = "NICK muscle_chestbrook\r\nUSER muscle_chestbrook 0 * :Muscle Chestbrook\r\n";
  send_msg(ioc, msg, bmm_strlen(msg));
  br_sslio_flush(ioc);
}

int main(void) {
  char *host = "irc.libera.chat";
  // output struct for getaddrinfo
  struct addrinfo info;

  // set up SSL connection
  int fd;
  br_ssl_client_context sc;
  br_x509_minimal_context xc;
  unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
  br_sslio_context ioc;
  {
    fd = host_connect(host, &info);

    br_ssl_client_init_full(&sc, &xc, TAs, TAs_NUM);
    br_ssl_engine_set_buffer(&sc.eng, iobuf, sizeof iobuf, 1);
    br_ssl_client_reset(&sc, host, 0);
    br_sslio_init(&ioc, &sc.eng, sock_read, &fd, sock_write, &fd);
  }


  // message formats
  // stream of bytes, separated by CRLF, UTF-8 encoded
  // only process a message once fully read until the CRLF
  // message structure:
  // 512 bytes max, unless there are tags, in which case allow 8191 additional
  // bytes
  // <message> = @<tags> :<source> command parameters
  // <tags> = <key>=<value>;<key>=<value>
  // don't send more than 15 parameters, but accept any number
  // ignore empty lines
  register_conn(&ioc);

  /*
   * Read the server's response. We use here a small 512-byte buffer,
   * but most of the buffering occurs in the client context: the
   * server will send full records (up to 16384 bytes worth of data
   * each), and the client context buffers one full record at a time.
   */
  for (;;) {
    int rlen;
    unsigned char tmp[512];

    rlen = br_sslio_read(&ioc, tmp, sizeof tmp);
    if (rlen < 0) {
      break;
    }
    fwrite(tmp, 1, rlen, stdout);
  }

  close(fd);

  return 0;
}
