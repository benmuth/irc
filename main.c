#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/types.h>

int main(int argc, char **argv) {
  // from beej's guide to network programming

  // return status code (error number)
  int gai_err;
  // tell getaddrinfo what addresses you're interested in
  struct addrinfo hints;
  // return struct for getaddrinfo
  struct addrinfo *info;
  // addrinfo pointer for iteration through linked list
  struct addrinfo *p;

  // initialize hints to 0
  memset(&hints, 0, sizeof(hints));
  // we're looking for addresses supporting TCP over either IPv4 or v6, and we
  // want the IP to be filled in
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if ((gai_err = getaddrinfo("irc.libera.chat", "6697", &hints, &info)) != 0) {
    fprintf(stderr, "gai error: %s\n", gai_strerror(gai_err));
    exit(1);
  }

  printf("IP Addresses for irc.libera.chat\n");

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

    // convert the addr into a printable numeric form and write to ipstr
    inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
    printf("  %s: %s\n", ipver, ipstr);
  }

  
  // get the file descriptor for the socket
  int s = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
  
  // avoid "Address already in use." errors when rerunning the program
  int yes = 1;
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  int b_err;
  if ((b_err = bind(s, info->ai_addr, info->ai_addrlen) != 0)) {
    fprintf(stderr, "bind error: %d\n", errno);
  }

  freeaddrinfo(info);

  return 0;
}
