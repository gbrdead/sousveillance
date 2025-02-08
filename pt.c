#define _GNU_SOURCE
#include <sched.h>

#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "chaff.h"
#include "rot13.h"


static const struct EncryptedString* volatile password = &passwords[FAKE_PASSWORD_INDEX];
static const struct EncryptedString* volatile volatile flag = &flags[FAKE_FLAG_INDEX];

__attribute__ ((always_inline))
static inline void switchToFake(void)
{
    password += (FAKE_PASSWORD_INDEX - REAL_PASSWORD_INDEX);
    flag += (FAKE_FLAG_INDEX - REAL_FLAG_INDEX);
}

__attribute__ ((always_inline))
static inline void switchToReal(void)
{
    password += (REAL_PASSWORD_INDEX - FAKE_PASSWORD_INDEX);
    flag += (REAL_FLAG_INDEX - FAKE_FLAG_INDEX);
}


static int isTraced(void)
{
    int result = 1;
    char statusFilePath[] = "/proc/self/status";
    char tracerPidFormat[] = "TracerPid:\t%d\n";

    FILE *statusFile = fopen(statusFilePath, "r");
    if (!statusFile)
    {
        goto error0;
    }

    char *line = NULL;
    size_t lineLength = 0;
    pid_t tracerPid;

    while (getline(&line, &lineLength, statusFile) >= 0)
    {
        if (sscanf(line, tracerPidFormat, &tracerPid) > 0)
        {
            result = tracerPid != 0;
            break;
        }
    }

    free(line);
    fclose(statusFile);
error0:
    return result;
}

static void debuggerWatcher(void)
{
    struct timespec sleepInterval = {0, 1000};   // 1 us

    while (1)
    {
        // Do not load the CPU too much, so that this thread is less likely to be detected accidentally (e.g. if a fan starts spinning audibly).
        // But check frequently enough so that the thread has a chance to exit before an attaching debugger pauses the process.
        nanosleep(&sleepInterval, NULL);

        if (isTraced())
        {
            switchToFake();
            break;
        }
    }
}

#define THREAD_STACK_SIZE 10240     // 1 KB seems to be not enough.

// Not called by main() - hopefully, it will look like unreachable code.
__attribute__ ((constructor))
static void preMain(void)
{
    if (!isTraced())
    {
        switchToReal();


//        pthread_t threadPid;
//        pthread_create(&threadPid, NULL, debuggerWatcher, NULL);
// The code below tries to emulate the commented code above. It starts the thread without linking to libpthread in order to avoid suspicion.

        const long threadAttr = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_IO | CLONE_SYSVSEM;
        uint8_t* stack = malloc(THREAD_STACK_SIZE * sizeof(uint8_t));   // The stack cannot be statically allocated for unknown reasons.
        if (!stack)
        {
            perror("malloc");
            exit(1);
        }
        uint8_t* stackTop = stack + THREAD_STACK_SIZE;

        asm goto     // syscall clone
        (
            "mov        $0x38, %%rax    \n"
            "mov        %0, %%rdi       \n"
            "mov        %1, %%rsi       \n"
            "syscall                    \n"
            // If we are in the new thread (and we still don't know this) we cannot access the local variables.
            // Thus, RAX cannot be saved to a local variable before being checked for 0.
            "test       %%rax, %%rax    \n"
            "jnz        %l[ret]         \n"
            // The local variables cannot be accessed below this line because now the stack is the new one (and it is empty).
            // RBP points in the stack of the main thread and must not be used.
            :
            : "g"(threadAttr), "g"(stackTop)
            : "cc", "rax", "rdi", "rsi", "rdx","r10", "r8", "r9", "rcx", "r11"
            : ret
        );

        debuggerWatcher();

        // The memory allocated for the stack will now leak because there is no safe way to call free().
        // The stack is required up to the very return from free().
        // In reality, libpthread uses system calls to allocate and free thread stacks.

        asm     // syscall exit
        (
            "sub        %%rdi, %%rdi    \n"
            "mov        $0x3c, %%rax    \n"
            "syscall                    \n"
            :
            :
            : "rax", "rdi", "rsi", "rdx", "r10", "rcx", "r11"
        );
        // Must not be reached because the stack is empty and there is nowhere to return to.

ret:    ;
        // The main thread continues here.
    }
}


int main(int argc, char *argv[])
{
    char *line = NULL;
    size_t n = 0;

    printf("Enter the password: ");
    ssize_t lineLength = getline(&line, &n, stdin);
    if (lineLength < 0)
    {
        perror("getline");
        exit(1);
    }
    line[lineLength-1] = '\0';

    char decryptedPassword[ENCRYPTED_STRING_MAX_SIZE];
    decryptString(password, decryptedPassword);
    if (strncmp(line, decryptedPassword, ENCRYPTED_STRING_MAX_SIZE * sizeof(char)) == 0)
    {
        char decryptedFlag[ENCRYPTED_STRING_MAX_SIZE];
        decryptString(flag, decryptedFlag);
        printf("The password is correct.\nThe flag is: %.*s\n", ENCRYPTED_STRING_MAX_SIZE, decryptedFlag);
    }
    else
    {
        printf("The password is wrong.\n");
    }
    free(line);

    return 0;
}
