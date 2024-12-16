#include "multiprocessing.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <seccomp.h>

void install_seccompx() {
  puts("Installing seccomp...");
  int syscall_blacklist[] = {SCMP_SYS(open),SCMP_SYS(openat),SCMP_SYS(execve),SCMP_SYS(fork),SCMP_SYS(vfork),SCMP_SYS(execveat)};
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if(!ctx) {
    perror("Seccomp failed.");
    _exit(-1);
  }
  seccomp_arch_add(ctx,SCMP_ARCH_X86_64);
  int len = sizeof(syscall_blacklist) / sizeof(int);
  for(int i = 0;i < len;i++) {
    if (seccomp_rule_add(ctx, SCMP_ACT_KILL, syscall_blacklist[i], 0) != 0) {
      perror("Failed to install filter");
      _exit(-1);
    }
  }
  seccomp_load(ctx);
  return;
};

void spawn_child(bool is_privileged,void(*handler)()) {
  puts("Starting child process...");
  pid_t pid = fork();
  if(pid==-1){
    puts("Fail to set up child.");
  }
  if(pid ==0) {
    if(!is_privileged)
      install_seccompx(); //if user is not an admin installing seccomp into child pocess
    puts("System is now secure.");
    handler();
  }
  else {
    int status;
    do {
      pid_t w = waitpid(pid, &status, WUNTRACED | WCONTINUED);
      if (w == -1) {
        perror("waitpid");
        _exit(-1);
      }
      if (WIFEXITED(status)) {
        printf("Child exited, status=%d\n", WEXITSTATUS(status));
      } else if (WIFSIGNALED(status)) {
        printf("Child killed by signal %d\n", WTERMSIG(status));
      } else if (WIFSTOPPED(status)) {
        printf("Child stopped by signal %d\n", WSTOPSIG(status));
      } else if (WIFCONTINUED(status)) {
                printf("continued\n");
      }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));  
  }
  return;
}
