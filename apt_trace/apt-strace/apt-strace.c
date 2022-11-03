#include <sys/ptrace.h>
#include <bits/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

/* cheap trick for reading syscall number / return value. */
#ifdef __amd64__
#define eax rax
#define orig_eax orig_rax
#else
#endif

#define offsetof(a, b) __builtin_offsetof(a,b)
#define get_reg(child, name) __get_reg(child, offsetof(struct user, regs.name))

long __get_reg(pid_t child, int off) {
    long val = ptrace(PTRACE_PEEKUSER, child, off);
    assert(errno == 0);
    return val;
}

int wait_for_syscall(pid_t child) {
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        waitpid(child, &status, 0);
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
            return 0;
        if (WIFEXITED(status))
            return 1;
        // fprintf(stderr, "[stopped %d (%x)]\n", status, WSTOPSIG(status));
    }
}

long get_syscall_arg(pid_t child, int which) {
    switch (which) {
#ifdef __amd64__
    case 0: return get_reg(child, rdi);
    case 1: return get_reg(child, rsi);
    case 2: return get_reg(child, rdx);
    case 3: return get_reg(child, r10);
    case 4: return get_reg(child, r8);
    case 5: return get_reg(child, r9);
#else
    case 0: return get_reg(child, ebx);
    case 1: return get_reg(child, ecx);
    case 2: return get_reg(child, edx);
    case 3: return get_reg(child, esi);
    case 4: return get_reg(child, edi);
    case 5: return get_reg(child, ebp);
#endif
    default: return -1L;
    }
}

char *read_string(pid_t child, unsigned long addr) {
    char *val = malloc(4096);
    int allocated = 4096;
    int read = 0;
    unsigned long tmp;
    while (1) {
        if (read + sizeof tmp > allocated) {
            allocated *= 2;
            val = realloc(val, allocated);
        }
        tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
        if(errno != 0) {
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

char* check_for_files(pid_t child, int syscall_req) {
    char *strval;
    int path_arg;
    long syscall_arg;
    int num = get_reg(child, orig_eax);
    assert(errno == 0);

    // fprintf(stderr, "FAILED SYSCALL: %d\n", num);

    switch(num) {
    case 2:
        // open
        path_arg = 0;
        break;
    case 4:
    case 6:
        // stat and lstat
        path_arg = 0;
        break;
    case 59:
        // execve
        path_arg = 0;
        break;
    case 257:
        // openat
        path_arg = 1;
        break;
    case 332:
        // statx
        path_arg = 1;
        break;
    default:
        return NULL;
    }

    syscall_arg = get_syscall_arg(child, path_arg);
    strval = read_string(child, syscall_arg);
    if (strlen(strval) > 0) {
        return strval;
    }
    free(strval);
    return NULL;
}

int do_trace(pid_t child, int syscall_req, FILE* output) {
    int status;
    int retval;
    waitpid(child, &status, 0);
    assert(WIFSTOPPED(status));
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
    while(1) {
        char* path;

        if (wait_for_syscall(child) != 0) {
            break;
        }

        if (wait_for_syscall(child) != 0) {
            break;
        }

        retval = get_reg(child, eax);
        assert(errno == 0);

        path = check_for_files(child, syscall_req);
        if (path != NULL) {
            struct stat stats;
            if (stat(path, &stats) == 0) {
                fwrite("exists\t", sizeof(char), 7, output);
            } else {
                fwrite("missing\t", sizeof(char), 8, output);
            }
            fwrite(path, sizeof(char), strlen(path), output);
            fwrite("\n", sizeof(char), 1, output);
            free(path);
        }
    }
    fclose(output);
    return 0;
}

int do_child(int argc, char **argv) {
    char *args [argc+1];
    int i;
    for (i=0;i<argc;i++) {
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
    int syscall = -1;
    FILE* output;

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
        return do_child(argc-push, argv+push);
    } else {
        return do_trace(child, syscall, output);
    }
}
