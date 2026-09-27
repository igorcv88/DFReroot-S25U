#define _GNU_SOURCE

#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#define DFR_EXEC_USAGE 64
#define DFR_EXEC_DIGEST_MISMATCH 65
#define DFR_EXEC_FAILURE 66

extern char **environ;

/*
 * Open, hash and execute one file description.
 *
 * Hashing a pathname and asking ProcessBuilder to open it later leaves a
 * replacement window.  This launcher opens the candidate once, hashes that fd,
 * rewinds it, and gives the SAME fd to execveat(AT_EMPTY_PATH).  A rename or
 * replacement after open therefore cannot change the bytes that run.
 *
 * execveat also retains the opened file's basename as the Linux task comm.  For
 * the pinned file that remains dfreroot-ksud, preserving the paired module's
 * defense-in-depth task-name check without making that mutable name authority.
 */
int main(int argc, char **argv) {
    if (argc < 4 || strlen(argv[1]) != 64) {
        fprintf(stderr, "DFR_VERIFIED_EXEC_USAGE\n");
        return DFR_EXEC_USAGE;
    }

    const char *expected = argv[1];
    const char *path = argv[2];
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "DFR_VERIFIED_EXEC_OPEN errno=%d\n", errno);
        return DFR_EXEC_FAILURE;
    }

    char actual[65];
    if (dfr_sha256_fd_hex(fd, actual) != 0) {
        fprintf(stderr, "DFR_VERIFIED_EXEC_HASH errno=%d\n", errno);
        close(fd);
        return DFR_EXEC_FAILURE;
    }
    if (strcmp(actual, expected) != 0) {
        fprintf(stderr, "DFR_VERIFIED_EXEC_DIGEST_MISMATCH found=%s\n", actual);
        close(fd);
        return DFR_EXEC_DIGEST_MISMATCH;
    }
    if (lseek(fd, 0, SEEK_SET) != 0) {
        fprintf(stderr, "DFR_VERIFIED_EXEC_REWIND errno=%d\n", errno);
        close(fd);
        return DFR_EXEC_FAILURE;
    }

    /* argv[2] intentionally becomes argv[0] of ksud, matching direct exec. */
    syscall(__NR_execveat, fd, "", &argv[2], environ, AT_EMPTY_PATH);
    fprintf(stderr, "DFR_VERIFIED_EXEC_EXECVEAT errno=%d\n", errno);
    close(fd);
    return DFR_EXEC_FAILURE;
}
