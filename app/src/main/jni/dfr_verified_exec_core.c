#define _GNU_SOURCE

#include "dfr_verified_exec_core.h"

#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

static void set_err(int *err_out, int value)
{
    if (err_out) {
        *err_out = value;
    }
}

int dfr_verified_execveat(const char *path, const char *expected_hex,
                          char *const argv[], char *const envp[],
                          int *err_out, char found_hex[65])
{
    char actual[65];
    int fd;

    set_err(err_out, 0);
    if (!path || !expected_hex || strlen(expected_hex) != 64) {
        set_err(err_out, EINVAL);
        return DFR_VEXEC_ERR_OPEN;
    }

    /* Exactly one open of the mutable pathname. Everything after this point
     * refers to the file description, never to the name again. */
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        set_err(err_out, errno);
        return DFR_VEXEC_ERR_OPEN;
    }

    if (dfr_sha256_fd_hex(fd, actual) != 0) {
        set_err(err_out, errno);
        close(fd);
        return DFR_VEXEC_ERR_HASH;
    }
    if (found_hex) {
        memcpy(found_hex, actual, sizeof(actual));
    }
    if (strcmp(actual, expected_hex) != 0) {
        close(fd);
        return DFR_VEXEC_ERR_DIGEST;
    }
    if (lseek(fd, 0, SEEK_SET) != 0) {
        set_err(err_out, errno);
        close(fd);
        return DFR_VEXEC_ERR_REWIND;
    }

    /*
     * AT_EMPTY_PATH on the hashed descriptor. This also keeps the opened file's
     * basename as the task comm, which is what the paired KernelSU module reads
     * as its defense-in-depth check - a property tools/tests/test_verified_exec.sh
     * asserts, so that a future rewrite cannot drop it silently.
     *
     * O_CLOEXEC above does not interfere: execveat(AT_EMPTY_PATH) uses the
     * descriptor to name the image before the close-on-exec sweep.
     */
    syscall(__NR_execveat, fd, "", argv, envp, AT_EMPTY_PATH);
    set_err(err_out, errno);
    close(fd);
    return DFR_VEXEC_ERR_EXECVEAT;
}
