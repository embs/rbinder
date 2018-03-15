#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/wait.h>

const int long_size = sizeof(long);

void getdata(pid_t child, long addr, char *str, int len) {
  //printf("child: %i\n", child);
  //printf("addr: %i\n", addr);
  //printf("str: %s\n", *str);
  //printf("getdata(%i, %i, %s, %i)\n", child, addr, *str, len);
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

void putdata(pid_t child, long addr, char *str, int len) {
  printf("putdata(pid_t=%i, long=%i, char=%s, int=%i)\n", child, addr, str, len);
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

void printsyscall(pid_t cid, long syscall_number, long syscall_return) {
    printf("cid=%i syscall_number=%i syscall_return=%i\n",
           cid, syscall_number, syscall_return);
}

void printwaitstatus(int cid, long status, long eventmsg) {
  printf("cid=%i status=%ld eventmsg=%ld ", cid, status, eventmsg);
  if(status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8)))
    printf("PTRACE_EVENT_VFORK\n");
  else if(status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8)))
    printf("PTRACE_EVENT_FORK\n");
  else if(status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8)))
    printf("PTRACE_EVENT_CLONE\n");
  else if(status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8)))
    printf("PTRACE_EVENT_EXEC\n");
  else if(status>>8 == (SIGTRAP | (PTRACE_EVENT_EXIT<<8)))
    printf("PTRACE_EVENT_EXIT\n");
  else
    printf("\n");
}

void perrorexit(char *func) {
  perror(func);
  exit(1);
}

int main(int argc, char **argv) {
  int tracee_pid = atoi(argv[1]);

  if(ptrace(PTRACE_ATTACH, tracee_pid, 0, 0) < 0)
    perrorexit("ptrace(PTRACE_ATTACH)");

  if(ptrace(PTRACE_SETOPTIONS, tracee_pid, 0, PTRACE_O_TRACEEXEC|PTRACE_O_TRACEVFORK|PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK) < 0)
    perrorexit("ptrace(PTRACE_SETOPTIONS)");

  int cid, status;
  long syscall_number, syscall_return, eventmsg;
  long params[3];
  char *str;

  while(1) {
    cid = waitpid(-1, &status, __WALL);
    ptrace(PTRACE_GETEVENTMSG, cid, NULL, &eventmsg);
    printwaitstatus(cid, status, eventmsg);

    if(WIFEXITED(status)) {
      printf("EXITED\n");
      break;
    }
    //if(WIFSIGNALED(status)) {
    //  printf("SIGNALED\n");
    //}
    //if(WIFSTOPPED(status)) {
    //  printf("STOPPED\n");
    //}
    //if(WIFCONTINUED(status)) {
    //  printf("CONTINUED\n");
    //}

    syscall_number = ptrace(PTRACE_PEEKUSER, tracee_pid, 8 * ORIG_RAX, NULL);
    syscall_return = ptrace(PTRACE_PEEKUSER, tracee_pid, 8 * RAX, NULL);
    printsyscall(cid, syscall_number, syscall_return);

    //if(syscall_number == SYS_execve)
    //  printf("sys_execve\n");

    //if(syscall_number == SYS_accept)
    //  printf("sys_accept\n");

    //if(syscall_number == SYS_recvfrom)
    //  printf("sys_recvfrom\n");

    //if(syscall_number == SYS_sendto)
    //  printf("sys_sendto\n");

    if(syscall_number == SYS_write) {
    //  printf("\nsys_write\n");

      params[0] = ptrace(PTRACE_PEEKUSER, tracee_pid, 8 * RDI, NULL);
      params[1] = ptrace(PTRACE_PEEKUSER, tracee_pid, 8 * RSI, NULL);
      params[2] = ptrace(PTRACE_PEEKUSER, tracee_pid, 8 * RDX, NULL);

      //printf("params[0]: %i\n", params[0]);
      //printf("params[1]: %i\n", params[1]);
      //printf("params[2]: %i\n", params[2]);
      str = (char *)calloc(3, (params[2]+1) * sizeof(char));

      getdata(tracee_pid, params[1], str, params[2]);

      //printf("str: %s", str);

      //free(str);
      //char *newstr = "Eu que mando\n";
      //putdata(tracee_pid, params[1], newstr, strlen(newstr));
    }

    ptrace(PTRACE_SYSCALL, tracee_pid, NULL, 0);
  }

  return 0;
}
