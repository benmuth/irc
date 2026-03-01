#include <assert.h>
#include <cstdio>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>

#include "BearSSL/inc/bearssl_ssl.h"

// Trust anchors declared in trust_anchors.c
extern const br_x509_trust_anchor TAs[];
extern const size_t TAs_NUM;
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

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

///////////////////////////////////////
// Networking
///////////////////////////////////////

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

///////////////////////////////////////
// SSL
///////////////////////////////////////

typedef struct {
  br_ssl_client_context sc;
  br_x509_minimal_context xc;
  unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
  br_sslio_context ioc;
  int fd;
} SSL_Connection;

void setup_SSL(SSL_Connection *conn, char *host, struct addrinfo info) {
  conn->fd = host_connect(host, &info);
  br_ssl_client_init_full(&conn->sc, &conn->xc, TAs, TAs_NUM);
  br_ssl_engine_set_buffer(&conn->sc.eng, conn->iobuf, sizeof conn->iobuf, 1);
  br_ssl_client_reset(&conn->sc, host, 0);
  br_sslio_init(&conn->ioc, &conn->sc.eng, sock_read, &conn->fd, sock_write,
                &conn->fd);
}

void send_msg(br_sslio_context *ioc, char *msg, size_t len) {
  br_sslio_write_all(ioc, msg, len);
  br_sslio_flush(ioc);
}

///////////////////////////////////////
// IRC
///////////////////////////////////////

typedef struct {
  char *name;
  void (*handler)(br_sslio_context *ioc, char *str);
} Command_Handler;

void send_pong(br_sslio_context *ioc, char *token) {
  int buf_len = 8 + (int)strlen(token);
  char *pong_buffer = malloc(buf_len * sizeof(char));
  snprintf(pong_buffer, buf_len, "PONG %s\r\n", token);
  printf("%s\n", pong_buffer);
  printf("pong buffer len: %lu \n", strlen(pong_buffer));
  send_msg(ioc, pong_buffer, strlen(pong_buffer));
}

void handle_ping(br_sslio_context *ioc, char *msg) { send_pong(ioc, msg); }

Command_Handler handlers[] = {
    {"PING", handle_ping},
    {NULL, NULL},
};

void register_conn(br_sslio_context *ioc) {
  char *connection_message = "CAP LS 302\r\n"
                             "PASS password\r\n"
                             "NICK ben\r\n"
                             "USER ben 0 * :Ben M\r\n"
                             "CAP END\r\n";
  send_msg(ioc, connection_message, strlen(connection_message));
}

void send_quit(br_sslio_context *ioc) {
  char *quit = "QUIT :Gone to have lunch\r\n";
  send_msg(ioc, quit, strlen(quit));
}

void dispatch(br_sslio_context *ioc, char *msg) {
  for (int i = 0; handlers[i].name != NULL; i++) {
    // if we handle this command, then call the handler, passing in the rest of
    // the message after the command
    if (strncmp(msg, handlers[i].name, strlen(handlers[i].name)) == 0) {
      handlers[i].handler(ioc, &(msg[strlen(handlers[i].name) + 1]));
      return;
    }
  }
}

void strip_crlf(char *str, int max_len) {
  for (int i = 0; i < max_len - 1; ++i) {
    if (str[i] == '\r' && str[i + 1] == '\n') {
      str[i] = '\0';
      break;
    }
  }
}

void handle_message(br_sslio_context *ioc, char *msg) {
  // check if buffer starts with the source/prefix, consume it if so
  int i = 0;
  if (msg[i] == ':') {
    while (msg[i] != ' ') {
      assert(msg[i] != '\0');
      ++i;
    }
  }

  dispatch(ioc, &msg[i]);
}

int main(void) {
  // char *host = "irc.libera.chat";
  char *host = "testnet.ergo.chat";

  // output struct for getaddrinfo
  struct addrinfo info;

  // set up SSL connection
  SSL_Connection conn;
  setup_SSL(&conn, host, info);
  register_conn(&conn.ioc);

  int rlen;
  char input_buffer[100];
  char response_buffer[512];

  for (;;) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(conn.fd, &readfds);
    FD_SET(STDIN_FILENO, &readfds);

    if (select(conn.fd + 1, &readfds, NULL, NULL, NULL) > 0) {
      /*
       * Read the server's response. We use here a small 512-byte buffer,
       * but most of the buffering occurs in the client context: the
       * server will send full records (up to 16384 bytes worth of data
       * each), and the client context buffers one full record at a time.
       */
      if (FD_ISSET(conn.fd, &readfds)) {
        rlen =
            br_sslio_read(&conn.ioc, response_buffer, sizeof response_buffer);
        if (rlen < 0) {
          printf("breaking\n");
          break;
        }
        strip_crlf(response_buffer, sizeof(response_buffer));

        handle_message(&conn.ioc, response_buffer);

        fwrite(response_buffer, 1, rlen, stdout);
        fflush(stdout);
      }
      if (FD_ISSET(STDIN_FILENO, &readfds)) {
        fgets(input_buffer, sizeof(input_buffer), stdin);

        printf("%s\n", input_buffer);
        if (strchr(input_buffer, 'q') != NULL) {
          printf("quitting...\n");
          send_quit(&conn.ioc);
        }
      }
    }
  }

  close(conn.fd);

  return 0;
}
