#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "uthash.h"

/*
 * tracee_t struct types & functions.
 */
struct tracee_t {
  pid_t id;
  char headers[1024];
  UT_hash_handle hh;
};

static struct tracee_t *tracees = NULL;

static void add_tracee(struct tracee_t *s) {
  s->headers[0] = '\0';
  HASH_ADD_INT(tracees, id, s);
}

static struct tracee_t *find_tracee(int tracee_id) {
  struct tracee_t *t;
  HASH_FIND_INT(tracees, &tracee_id, t);  
  return t;
}

static void rmtracee(struct tracee_t *tracee) {
  HASH_DEL(tracees, tracee);
  free(tracee);
}

const char *fine_headers[] = {
  "x-ot-span-context",
  "x-request-id",
  "x-b3-traceid",
  "x-b3-spanid",
  "x-b3-parentspanid",
  "x-b3-sampled",
  "x-b3-flags"
};

void extract_headers(char *str, char *headers) {
  int chidx, hdidx, matchidx, i;
  chidx = 0;
  matchidx = 0;
  const char *cheader = NULL;
  char elected[1024] = {'\0'};
  int electedidx = 0;
  char cchar = '\0';

  // Try matching each tracing header.
  for(hdidx = 0; hdidx < 7; hdidx++) {
    cheader = fine_headers[hdidx];
    matchidx = 0;

    // Check each char.
    for(chidx = 0; chidx < strlen(str); chidx++) {
      cchar = str[chidx];

      // Get out before reaching HTTP data section.
      if(chidx > 0 && cchar == '\r' && str[chidx-1] == '\n' && str[chidx+1] == '\n') {
        continue;
      }

      // Don't care about this char.
      if(cchar == '\r') {
        continue;
      }

      // Line break: restart matching info.
      if(cchar == '\n') {
        matchidx = 0;
        continue;
      }

      // Matching already failed for current line.
      if(matchidx == -1) {
        continue;
      }

      // Still didn't match entire header.
      if(matchidx < strlen(cheader)) {
        if(tolower(cchar) == cheader[matchidx]) {
          ++matchidx;
        } else {
          matchidx = -1;
        }
      }

      // Matched entire header.
      else {
        // Copy header key.
        if(matchidx == strlen(cheader)) {
          for(i = 0; i < matchidx; i++) {
            headers[electedidx] = cheader[i];
            ++electedidx;
          }
        }

        // Copy header value (including ": ").
        headers[electedidx] = cchar;
        ++electedidx;
        ++matchidx;
        if(str[chidx+1] == '\r') {
          headers[electedidx] = '\r';
          headers[electedidx+1] = '\n';
          electedidx = electedidx + 2;
        }
      }
    }
  }
  // Fill headers with \0.
  for(i = electedidx; i < 1024; i++) {
    headers[i] = '\0';
  }
}

static int open_socks[1024] = {[0 ... 1023] = 0};

static ssize_t (*real_read)(int filedes, void *buffer, size_t size) = NULL;
static int (*real_close)(int filedes) = NULL;
static int (*real_accept)(int socket, struct sockaddr *addr, socklen_t *length_ptr) = NULL;
static int (*real_sendto)(int socket, void *buffer. size_t size, int flags, struct sockaddr *addr, socklen_t length) = NULL;

ssize_t read(int filedes, void *buffer, size_t size) {
  real_read = dlsym(RTLD_NEXT, "read"); // TODO INITIALIZE ONLY ONCE
  ssize_t ret = real_read(filedes, buffer, size);
  if(open_socks[filedes]) {
    printf("READ tid=%i fd=%i buffer=%s\n", syscall(__NR_gettid), filedes, buffer);
    struct tracee_t *tracee = malloc(sizeof(struct tracee_t)); // TODO FREE
    tracee->id = syscall(__NR_gettid);
    add_tracee(tracee);
    extract_headers(buffer, tracee->headers);
  }

  return ret;
}

int close(int fd) {
  real_close = dlsym(RTLD_NEXT, "close");
  open_socks[fd] = 0;

  return real_close(fd);
}

int accept(int socket, struct sockaddr *addr, socklen_t *length_ptr) {
  real_accept = dlsym(RTLD_NEXT, "accept");
  int fd = real_accept(socket, addr, length_ptr);
  printf("ACCEPT fd=%i\n", fd);
  if(fd > 0) {
    open_socks[fd] = 1;
  }

  return fd;
}

int sendto(int socket, void *buffer. size_t size, int flags, struct sockaddr *addr, socklen_t length) {
  real_sendto = dlsym(RTLD_NEXT, "sendto");
  int ret = real_sendto(socket, buffer, size, flags, addr, length);

  return ret;
}
