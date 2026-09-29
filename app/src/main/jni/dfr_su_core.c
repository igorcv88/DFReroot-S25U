#define _GNU_SOURCE

#include "dfr_su_core.h"

#include "dfr_verified_exec_core.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif

extern char **environ;

/*
 * The KernelSU client mechanics, read out of the pinned daemon's own
 * unstripped bytes (ksud-pa3q-S938BXXUCZZIC-dfreroot-v3.3.0):
 *
 *   ksucalls::init_driver_fd  syscall(__NR_reboot, 0xdeadbeef, 0xcafebabe, 0, &fd)
 *   cli::run (the su path)    ioctl(fd, _IO('K', 1))   then exec
 *
 * The magic reboot is safe on a kernel without the hook: sys_reboot rejects an
 * unknown magic1 with EINVAL and reboots nothing. It is not safe to guess at
 * these numbers, which is why they were taken from the binary that the pinned
 * kernel actually answers rather than from memory of upstream.
 */
#define DFR_KSU_REBOOT_MAGIC1 0xdeadbeefu
#define DFR_KSU_REBOOT_MAGIC2 0xcafebabeu
#define DFR_KSU_IOCTL_GRANT_ROOT 0x4b01u /* _IO('K', 1) */

struct dfr_su_child_status {
    int step;
    int err;
    char found_hex[65];
};

static int real_set_comm(const char *comm)
{
#ifdef PR_SET_NAME
    return prctl(PR_SET_NAME, (unsigned long)comm, 0UL, 0UL, 0UL);
#else
    (void)comm;
    errno = ENOSYS;
    return -1;
#endif
}

static int real_driver_fd(int *fd_out)
{
    int fd = -1;

    /* The kernel writes the installed descriptor back through the fourth
     * argument. A kernel that does not carry the hook leaves it untouched and
     * returns EINVAL, which is a refusal, not a reboot. */
    syscall(__NR_reboot, DFR_KSU_REBOOT_MAGIC1, DFR_KSU_REBOOT_MAGIC2, 0, &fd);
    if (fd < 0) {
        if (errno == 0) {
            errno = ENOTTY;
        }
        return -1;
    }
    *fd_out = fd;
    return 0;
}

static int real_grant_root(int driver_fd)
{
    return ioctl(driver_fd, DFR_KSU_IOCTL_GRANT_ROOT, (void *)0);
}

static int real_current_uid(void)
{
    return (int)getuid();
}

static int real_enter_init_mnt_ns(void)
{
    int fd = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
    int rc;

    if (fd < 0) {
        return -1;
    }
    rc = setns(fd, CLONE_NEWNS);
    close(fd);
    return rc;
}

const struct dfr_su_ops dfr_su_real_ops = {
    real_set_comm,
    real_driver_fd,
    real_grant_root,
    real_current_uid,
    real_enter_init_mnt_ns,
};

static void child_fail(int status_fd, int step, int err, const char *found_hex)
{
    struct dfr_su_child_status status;

    memset(&status, 0, sizeof(status));
    status.step = step;
    status.err = err;
    if (found_hex) {
        memcpy(status.found_hex, found_hex, sizeof(status.found_hex) - 1);
    }
    /* Best effort by construction: if the parent has gone, there is nobody to
     * tell, and the _exit below is still the right thing to do. */
    (void)!write(status_fd, &status, sizeof(status));
    _exit(127);
}

/*
 * Everything from here to exec runs between fork() and exec() in a process that
 * is a forked copy of system_server. No allocation, no libc call that may take
 * a lock the parent held: syscalls and write(2) only.
 */
static void child_main(const struct dfr_su_ops *ops, const char *comm,
                       char *const argv[], const char *pinned_hex,
                       int status_fd, int out_fd, int null_fd)
{
    char found[65];
    int driver_fd = -1;
    int err = 0;
    int rc;

    memset(found, 0, sizeof(found));

    if (dup2(null_fd, STDIN_FILENO) < 0 || dup2(out_fd, STDOUT_FILENO) < 0 ||
        dup2(out_fd, STDERR_FILENO) < 0) {
        child_fail(status_fd, DFR_SU_STEP_PIPE, errno, NULL);
    }

    if (ops->set_comm(comm) != 0) {
        child_fail(status_fd, DFR_SU_STEP_COMM, errno, NULL);
    }
    if (ops->driver_fd(&driver_fd) != 0) {
        child_fail(status_fd, DFR_SU_STEP_DRIVER_FD, errno, NULL);
    }
    if (ops->grant_root(driver_fd) != 0) {
        child_fail(status_fd, DFR_SU_STEP_GRANT, errno, NULL);
    }
    /*
     * A returned success is not evidence of root (AGENTS.md 3.5: a boolean is
     * not evidence). The credential change is observable, so observe it before
     * executing anything.
     */
    if (ops->current_uid() != 0) {
        child_fail(status_fd, DFR_SU_STEP_NOT_ROOT, 0, NULL);
    }
    /*
     * Mirror what the pinned daemon's own su path does after the grant: enter
     * init's mount namespace, so a lifecycle operation acts on the global mount
     * tree rather than on system_server's private view of it.
     */
    if (ops->enter_init_mnt_ns() != 0) {
        child_fail(status_fd, DFR_SU_STEP_MNT_NS, errno, NULL);
    }

    if (pinned_hex) {
        rc = dfr_verified_execveat(argv[0], pinned_hex, argv, environ, &err, found);
        if (rc == DFR_VEXEC_ERR_DIGEST) {
            child_fail(status_fd, DFR_SU_STEP_DIGEST, 0, found);
        }
        child_fail(status_fd, DFR_SU_STEP_EXEC, err, NULL);
    }

    execv(argv[0], argv);
    child_fail(status_fd, DFR_SU_STEP_EXEC, errno, NULL);
}

static long now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void set_result(struct dfr_su_result *res, int step, int err)
{
    res->step = step;
    res->err = err;
}

int dfr_su_spawn(const struct dfr_su_ops *ops, const char *comm,
                 char *const argv[], const char *pinned_hex,
                 long timeout_ms, int kill_on_timeout,
                 char *out, size_t out_cap, struct dfr_su_result *res)
{
    int status_pipe[2] = { -1, -1 };
    int out_pipe[2] = { -1, -1 };
    int null_fd = -1;
    int status_seen = 0;
    long deadline;
    pid_t pid;

    if (!ops || !comm || !argv || !argv[0] || !res || !out || out_cap == 0) {
        if (res) {
            memset(res, 0, sizeof(*res));
            set_result(res, DFR_SU_STEP_INTERNAL, EINVAL);
        }
        return -1;
    }
    memset(res, 0, sizeof(*res));
    out[0] = '\0';

    /* O_CLOEXEC on the status channel is the signal itself: a successful exec
     * closes it with no bytes written, which is how the parent learns that the
     * child got all the way through without a second handshake. */
    if (pipe2(status_pipe, O_CLOEXEC) != 0) {
        set_result(res, DFR_SU_STEP_PIPE, errno);
        return -1;
    }
    if (pipe(out_pipe) != 0) {
        set_result(res, DFR_SU_STEP_PIPE, errno);
        close(status_pipe[0]);
        close(status_pipe[1]);
        return -1;
    }
    null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd < 0) {
        set_result(res, DFR_SU_STEP_PIPE, errno);
        close(status_pipe[0]);
        close(status_pipe[1]);
        close(out_pipe[0]);
        close(out_pipe[1]);
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        set_result(res, DFR_SU_STEP_FORK, errno);
        close(status_pipe[0]);
        close(status_pipe[1]);
        close(out_pipe[0]);
        close(out_pipe[1]);
        close(null_fd);
        return -1;
    }
    if (pid == 0) {
        close(status_pipe[0]);
        close(out_pipe[0]);
        child_main(ops, comm, argv, pinned_hex, status_pipe[1], out_pipe[1], null_fd);
        _exit(127); /* not reached */
    }

    close(status_pipe[1]);
    close(out_pipe[1]);
    close(null_fd);

    deadline = now_ms() + (timeout_ms > 0 ? timeout_ms : 0);
    for (;;) {
        struct pollfd fds[2];
        long remaining = deadline - now_ms();
        int ready;

        if (status_pipe[0] < 0 && out_pipe[0] < 0) {
            break;
        }
        if (remaining <= 0) {
            set_result(res, DFR_SU_STEP_TIMEOUT, 0);
            break;
        }

        fds[0].fd = status_pipe[0];
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = out_pipe[0];
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        ready = poll(fds, 2, (int)(remaining > 1000 ? 1000 : remaining));
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            set_result(res, DFR_SU_STEP_INTERNAL, errno);
            break;
        }
        if (fds[0].fd >= 0 && (fds[0].revents & (POLLIN | POLLHUP))) {
            struct dfr_su_child_status status;
            ssize_t n = read(status_pipe[0], &status, sizeof(status));

            if (n == (ssize_t)sizeof(status)) {
                status_seen = 1;
                set_result(res, status.step, status.err);
                memcpy(res->found_hex, status.found_hex, sizeof(res->found_hex) - 1);
            }
            if (n <= 0 || n == (ssize_t)sizeof(status)) {
                close(status_pipe[0]);
                status_pipe[0] = -1;
            }
        }
        if (fds[1].fd >= 0 && (fds[1].revents & (POLLIN | POLLHUP))) {
            char buf[4096];
            ssize_t n = read(out_pipe[0], buf, sizeof(buf));

            if (n > 0) {
                size_t room = out_cap - 1 - res->out_len;
                size_t take = (size_t)n < room ? (size_t)n : room;

                if (take > 0) {
                    memcpy(out + res->out_len, buf, take);
                    res->out_len += take;
                    out[res->out_len] = '\0';
                }
                if (take < (size_t)n) {
                    res->truncated = 1;
                }
            } else {
                close(out_pipe[0]);
                out_pipe[0] = -1;
            }
        }
    }

    if (status_pipe[0] >= 0) {
        close(status_pipe[0]);
    }
    if (out_pipe[0] >= 0) {
        close(out_pipe[0]);
    }

    if (res->step == DFR_SU_STEP_TIMEOUT) {
        if (kill_on_timeout) {
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            res->reaped = 1;
        } else if (waitpid(pid, NULL, WNOHANG) == pid) {
            /* Do not kill a task that may already be the daemon carrying out
             * the lifecycle operation; still collect it if it has finished, so
             * a timeout does not leave a zombie inside system_server. */
            res->reaped = 1;
        }
        return -1;
    }

    for (;;) {
        int wstatus = 0;
        pid_t done = waitpid(pid, &wstatus, 0);

        if (done == pid) {
            res->reaped = 1;
            res->exit_code = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;
            break;
        }
        if (done < 0 && errno == EINTR) {
            continue;
        }
        break;
    }

    if (!status_seen && res->step == DFR_SU_OK) {
        return 0;
    }
    return -1;
}

void dfr_su_status_token(const struct dfr_su_result *res, char *buf, size_t cap)
{
    static const char *const names[] = {
        "OK", "PIPE", "FORK", "COMM", "DRIVER_FD", "GRANT", "NOT_ROOT",
        "MNT_NS", "EXEC", "DIGEST", "TIMEOUT", "INTERNAL"
    };
    const char *name;

    if (!buf || cap == 0) {
        return;
    }
    if (!res || res->step < 0 || res->step > DFR_SU_STEP_INTERNAL) {
        snprintf(buf, cap, "DFR_SU_STEP=INTERNAL errno=0");
        return;
    }
    name = names[res->step];
    if (res->step == DFR_SU_STEP_DIGEST) {
        snprintf(buf, cap, "DFR_SU_STEP=DIGEST found=%s", res->found_hex);
    } else if (res->step == DFR_SU_OK) {
        snprintf(buf, cap, "DFR_SU_STEP=OK exit=%d", res->exit_code);
    } else {
        snprintf(buf, cap, "DFR_SU_STEP=%s errno=%d", name, res->err);
    }
}
