#include <assert.h>
#include <bits/types.h>
#include <errno.h>
#include <linux/elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// XX: Linux's ptrace.h must be included after glibc's ptrace.h, otherwise
// compilation errors occur.

// clang-format off
#include <sys/ptrace.h>
#include <linux/ptrace.h>

/* cheap trick for reading syscall number / return value. */
#ifdef __amd64__
#define edi rdi
#define orig_eax orig_rax
#endif

#if defined(__amd64__) || defined(__i386__)
static struct pt_regs regs;

#define SYSCALL_NO regs.orig_eax
#define RETURN_VAL regs.edi
#elif defined(__aarch64__)
static struct user_pt_regs regs;
static int arm_syscallno;

#define SYSCALL_NO arm_syscallno;
#define RETURN_VAL regs.regs[0]
#else
#error Unsupported architecture
#endif

#if DEBUG
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG(...)
#endif

void dump_regs(pid_t child) {
  struct iovec io;
  io.iov_base = &regs;
  io.iov_len = sizeof(regs);

  if (ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &io) < 0) {
    perror("dump_regs: ptrace(PTRACE_GETREGSET, NT_PRSTATUS)");
  }
  assert(io.iov_len == sizeof(regs));

  #ifdef __aarch64__
  io.iov_base = &arm_syscallno;
  io.iov_len = sizeof(arm_syscallno);
  if(ptrace(PTRACE_GETREGSET, child, NT_ARM_SYSTEM_CALL, &io) < 0) {
    perror("dump_regs: ptrace(PTRACE_GETREGSET, NT_ARM_SYSTEM_CALL)");
  }
  assert(io.iov_len == sizeof(arm_syscallno));
  #endif
}

typedef struct {
  int success;
  int retcode;
} syscall_result;

syscall_result wait_for_syscall(pid_t child) {
  int status;
  while (1) {
    ptrace(PTRACE_SYSCALL, child, 0, 0);
    waitpid(child, &status, 0);
    if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80) {
      return (syscall_result){.success = 0, .retcode = 0};
    } else if (WIFEXITED(status)) {
      return (syscall_result){.success = 1, .retcode = WEXITSTATUS(status)};
    }
    // fprintf(stderr, "[stopped %d (%x)]\n", status, WSTOPSIG(status));
  }
}

unsigned long get_syscall_arg(int which) {
  switch (which) {
#if defined(__amd64__)
  case 0:
    return regs.rdi;
  case 1:
    return regs.rsi;
  case 2:
    return regs.rdx;
  case 3:
    return regs.r10;
  case 4:
    return regs.r8;
  case 5:
    return regs.r9;
#elif defined(__i386__)
  case 0:
    return regs.ebx;
  case 1:
    return regs.ecx;
  case 2:
    return regs.edx;
  case 3:
    return regs.esi;
  case 4:
    return regs.edi;
  case 5:
    return regs.ebp;
#elif defined(__aarch64__)
  default:
    assert(which <= 5);
    return regs.regs[which];
#else
#error Unsupported architecture
#endif
  }
  return -1L;
}

char *read_string(pid_t child, unsigned long addr) {
  char *val = malloc(4096);
  unsigned int allocated = 4096;
  int read = 0;
  unsigned long tmp;
  while (1) {
    if (read + sizeof tmp > allocated) {
      allocated *= 2;
      val = realloc(val, allocated);
    }
    tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
    if (errno != 0) {
      val[read] = 0;
      break;
    }
    memcpy(val + read, &tmp, sizeof tmp);
    if (memchr(&tmp, 0, sizeof tmp) != NULL)
      break;
    read += sizeof tmp;
  }
  return val;
}

char *check_for_files(pid_t child) {
  char *strval;
  int path_arg;
  unsigned long syscall_arg;
  int num = SYSCALL_NO;
  assert(errno == 0);

  // fprintf(stderr, "FAILED SYSCALL: %d\n", num);

  #if defined(__amd64__) || defined(__i386__)
  switch (num) {
  case 2: // open
  case 4: // stat
  case 6: // lstat
  case 59: // execve
    path_arg = 0;
    break;
  case 257: // openat
  case 262: // newfstatat
  case 332: // statx
    path_arg = 1;
    break;
  default:
    return NULL;
  }
  #elif defined(__aarch64__)
  switch(num) {
  case SYS_openat:
  case SYS_name_to_handle_at:
  case SYS_statx:
  case SYS_execveat:
  case SYS_newfstatat:
    path_arg = 1;
    break;
  case SYS_execve:
    path_arg = 0;
    break;

  default:
    return NULL;
  }
  #else
  #error Unsupported architecture
  #endif

  syscall_arg = get_syscall_arg(path_arg);
  DEBUG("syscall(%d, ..., %p, ...)\n", num, (void*) syscall_arg);
  if(syscall_arg != 0) {
    strval = read_string(child, syscall_arg);
    if (strlen(strval) > 0) {
      return strval;
    }
    free(strval);
  }
  assert(errno == 0);
  return NULL;
}

int do_trace(pid_t child, FILE *output) {
  int status;
  // int retval;

  waitpid(child, &status, 0);
  assert(WIFSTOPPED(status));
  ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

  for (;;) {
    char *path;
    syscall_result result = wait_for_syscall(child);

    if (result.success != 0) {
      fclose(output);
      return result.retcode;
    }

    dump_regs(child);
    // retval = RETURN_VAL;
    assert(errno == 0);

    path = check_for_files(child);
    if (path != NULL) {
      struct stat stats;
      if (stat(path, &stats) == 0) {
        fwrite("exists\t", sizeof(char), 7, output);
      } else {
        fwrite("missing\t", sizeof(char), 8, output);
        errno = 0;
      }
      fwrite(path, sizeof(char), strlen(path), output);
      fwrite("\n", sizeof(char), 1, output);
      free(path);
    }
  }
}

int do_child(int argc, char **argv) {
  char *args[argc + 1];
  int i;
  for (i = 0; i < argc; i++) {
    args[i] = argv[i];
  }
  args[argc] = NULL;

  ptrace(PTRACE_TRACEME);
  kill(getpid(), SIGSTOP);
  return execvp(args[0], args);
}

int main(int argc, char **argv) {
  pid_t child;
  int push = 2;
  FILE *output;

  if (argc < 3) {
    fprintf(stderr, "Usage: %s <output_path> <program> <args>\n", argv[0]);
    exit(1);
  }

  output = fopen(argv[1], "w");
  if (output == NULL) {
    fprintf(stderr, "Error opening %s for writing!\n", argv[1]);
    exit(2);
  }

  child = fork();
  if (child == 0) {
    return do_child(argc - push, argv + push);
  } else {
    return do_trace(child, output);
  }
}
