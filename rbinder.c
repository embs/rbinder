#include <ctype.h>
#include <errno.h>
#include <stdio.h>

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "uthash.h"

#define SCREAD(number)     (number == SYS_read)
#define SCSENDTO(number)   (number == SYS_sendto)
#define SCRECVFROM(number) (number == SYS_recvfrom)

#define SCENTRY(code) (code == -ENOSYS)

#ifdef __x86_64__
#define WORD_LENGTH 8
#else
#define WORD_LENGTH 4
#endif

#define REG_SC_NUMBER  (WORD_LENGTH * ORIG_RAX)
#define REG_SC_RETCODE (WORD_LENGTH * RAX)
#define REG_SC_FRSTARG (WORD_LENGTH * RDI)
#define REG_SC_SCNDARG (WORD_LENGTH * RSI)
#define REG_SC_THRDARG (WORD_LENGTH * RDX)

#define ARG_SCRW_BUFF     1
#define ARG_SCRW_BUFFSIZE 2

const int long_size = sizeof(long);

const char *fine_headers[] = {
  "x-ot-span-context",
  "x-request-id",
  "x-b3-traceid",
  "x-b3-spanid",
  "x-b3-parentspanid",
  "x-b3-sampled",
  "x-b3-flags"
};

/*
 * ptrace helper functions.
 */
void peekdata(pid_t child, long addr, char *str, int len) {
  char *laddr;
  int i, j;
  union u {
    long val;
    char chars[long_size];
  }data;
  i = 0;
  j = len / long_size;
  laddr = str;
  while(i < j) {
    data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
    memcpy(laddr, data.chars, long_size);
    ++i;
    laddr += long_size;
  }
  j = len % long_size;
  if(j != 0) {
    data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
    memcpy(laddr, data.chars, j);
  }
  str[len] = '\0';
}

void pokedata(pid_t child, long addr, char *str, int len) {
  char *laddr;
  int i, j;
  union u {
          long val;
          char chars[long_size];
  }data;
  i = 0;
  j = len / long_size;
  laddr = str;
  while(i < j) {
    memcpy(data.chars, laddr, long_size);
    ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
    ++i;
    laddr += long_size;
  }
  j = len % long_size;
  if(j != 0) {
      memcpy(data.chars, laddr, j);
      ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
  }
  ptrace(PTRACE_POKEUSER, child, 8 * RDX, len);
}

void trapsc(pid_t cid) {
  ptrace(PTRACE_SYSCALL, cid, NULL, 0);
}

void peek_syscall_thrargs(pid_t cid, long *params) {
  params[0] = ptrace(PTRACE_PEEKUSER, cid, REG_SC_FRSTARG, NULL);
  params[1] = ptrace(PTRACE_PEEKUSER, cid, REG_SC_SCNDARG, NULL);
  params[2] = ptrace(PTRACE_PEEKUSER, cid, REG_SC_THRDARG, NULL);
}

/*
 * Helper functions for handling requests.
 */
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

void inject_headers(char *str, char *headers, char *newstr, int newstrsize) {
  int i, j;
  int stridx = 0;
  int injected = 0;

  for(i = 0; i < newstrsize; i++) {
    newstr[i] = str[stridx];
    if(str[stridx] == '\n' && str[stridx+1] == '\r' && injected == 0) {
      for(j = 0; j < strlen(headers); j++) {
        newstr[i+1+j] = headers[j];
      }
      i += strlen(headers);
      injected = 1;
    }
    ++stridx;
  }
  newstr[newstrsize] = '\0';
}

int is_http_request(char *str) {
  char *httpmeths[9] = {
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"
  };
  int i;
  for(i = 0; i < 9; i++) {
    if(strncmp(str, httpmeths[i], strlen(httpmeths[i])) == 0) {
      return 1;
    }
  }
  return 0;
}

/*
 * tracee_t struct types & functions.
 */
struct tracee_t {
  pid_t id;
  char headers[1024];
  UT_hash_handle hh;
};

struct tracee_t *tracees = NULL;

void add_tracee(struct tracee_t *s) {
  s->headers[0] = '\0';
  HASH_ADD_INT(tracees, id, s);
}

struct tracee_t *find_tracee(int tracee_id) {
  struct tracee_t *t;
  HASH_FIND_INT(tracees, &tracee_id, t);  
  return t;
}

void rmtracee(struct tracee_t *tracee) {
  HASH_DEL(tracees, tracee);
  free(tracee);
}

/*
 * rbinder main function.  Call with cmd line args:
 *
 *     $ ./rbinder /usr/bin/python server.py
 */
int main(int argc, char **argv) {
  pid_t child, cid;
  int status, fd, i;
  void *buf;
  size_t len;
  long syscall_number, syscall_return;
  long params[3];
  char *str;
  struct tracee_t *tracee;

  child = fork();

  // Start server within traced thread (just like a gdb inferior).
  if(child == 0) {
    ptrace(PTRACE_TRACEME, NULL, NULL, NULL);
    kill(getpid(), SIGSTOP);
    execv(argv[1], argv + 1);
  }
  // Watch server syscalls for extracting incoming request tracing headers and
  // injecting them into outgoing requests performed while request is being
  // serviced.
  else {
    // Setup ptrace for tracing further children threads.
    cid = waitpid(-1, &status, __WALL);
    if(ptrace(PTRACE_SETOPTIONS, cid, 0, PTRACE_O_TRACEEXEC|PTRACE_O_EXITKILL|\
          PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK) < 0) {
      perror("ptrace(PTRACE_SETOPTIONS)");
      exit(1);
    }
    // Listen to next child syscall.
    trapsc(cid);

    while(1) {
      // Wait for tracees' activity.
      cid = waitpid(-1, &status, __WALL);

      syscall_number = ptrace(PTRACE_PEEKUSER, cid, REG_SC_NUMBER, NULL);
      syscall_return = ptrace(PTRACE_PEEKUSER, cid, REG_SC_RETCODE, NULL);

      // Skip if
      //   - enter-stop for any syscall other than SENDTO;
      //   - exit-stop for SENDTO; or
      //   - none tracees and syscall does not trigger tracee creation
      if((SCENTRY(syscall_return) && !SCSENDTO(syscall_number)) || \
          (!SCENTRY(syscall_return) && SCSENDTO(syscall_number)) || \
          (!SCREAD(syscall_number) && HASH_COUNT(tracees) == 0)) {
        trapsc(cid);
        continue;
      }

      // Extract headers from incoming request.
      if(SCREAD(syscall_number) || SCRECVFROM(syscall_number)) {
        peek_syscall_thrargs(cid, params);
        str = (char *)calloc(1, (params[ARG_SCRW_BUFFSIZE]+1) * sizeof(char));
        peekdata(cid, params[ARG_SCRW_BUFF], str, params[ARG_SCRW_BUFFSIZE]);

        if(!is_http_request(str)) {
          trapsc(cid);
          continue;
        }

        struct tracee_t tracee;
        tracee.id = cid;
        add_tracee(&tracee);
        extract_headers(str, tracee.headers);
        free(str);
      }

      // Inject headers into outgoing requests.
      if(SCSENDTO(syscall_number)) {
        tracee = find_tracee(cid);
        peek_syscall_thrargs(cid, params);
        str = (char *)calloc(1, (params[ARG_SCRW_BUFFSIZE]+1) * sizeof(char));
        peekdata(cid, params[ARG_SCRW_BUFF], str, params[ARG_SCRW_BUFFSIZE]);

        // Check if HTTP request.
        if(!is_http_request(str)) {
          trapsc(cid);
          continue;
        }

        int newstrsize = strlen(str) + strlen(tracee->headers);
        char newstr[newstrsize];
        inject_headers(str, tracee->headers, newstr, newstrsize);
        pokedata(cid, params[1], newstr, newstrsize);
      }

      // Listen to next child syscall.
      trapsc(cid);
    }
  }

  return 0;
}
