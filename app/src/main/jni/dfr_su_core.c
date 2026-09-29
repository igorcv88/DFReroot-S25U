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
 * How the driver fd is obtained, and the condition under which the second half
 * of that is allowed to happen.
 *
 * The pinned daemon's own unstripped bytes (ksucalls::init_driver_fd) do two
 * things in order: scan /proc/self/fd for a link containing "[ksu_driver]",
 * and, only if none is there, issue a magic supercall
 * syscall(__NR_reboot, 0xdeadbeef, 0xcafebabe, 0, &fd).
 *
 * ## What the device did, and what actually caused it
 *
 * The first build to issue the supercall did not get a refusal: tapping Apply
 * Modules rebooted the device and dropped root. Two explanations were written
 * here before there was evidence for either, and both were wrong - first "no
 * supercall handler exists", then "the magic reboot reaches the real
 * sys_reboot". Samsung's /sys/class/sec/sec_hw_param/extra_info then produced
 * the panic record and refuted both:
 *
 *   TASK=dfreroot-ksud  PANIC="synchronous external abort"
 *   PC=allowed_for_su+0x12c/0x248 [kernelsu]
 *   [61.884299] KernelSU: ksu fd installed: 96 for pid 16452
 *   [61.884451] Internal error: synchronous external abort: 0000000096000010
 *
 * The supercall WORKED - the fd was installed for this very transport's forked
 * child, task name and all. What died 152 us later was the grant: the paired
 * module's DFR predicate called plain put_cred() on a credential that
 * CONFIG_KSU_SAMSUNG_KDP makes hypervisor-read-only, and that write is the
 * external abort. With panic_on_oops=1 and panic=-1 it became an instant
 * reboot with no log.
 *
 * ## So the condition is about the module, not about the syscall
 *
 * Asking a BROKEN module for the grant is what breaks the device. AGENTS.md
 * 3.6.1 therefore states the owner's decision as a condition rather than a
 * ban: the supercall may be issued only when a complete post-root record for
 * the CURRENT boot says the loaded module carries the fix
 * (transport_fix=kdp-cred-1, published by the paired module's ksud and checked
 * by PostRootStatus.transportFixAllowed()). Absent, stale, unknown or unreadable
 * marker is a refusal.
 *
 * Two properties keep that honest and are why transport_fix_allowed is a parameter
 * threaded down from Kotlin rather than anything decided in this file:
 *
 *   - the record lives at /data/system/dfreroot-post-root, which this layer
 *     does not read and must not guess at. A default computed here would be a
 *     default computed without evidence;
 *   - "the fd was missing" is NOT a second condition that can stand in for the
 *     first. That was precisely the reasoning that panicked the device - the
 *     scan found nothing, so the code asked. The child now refuses at
 *     DFR_SU_STEP_TRANSPORT_FIX_GATED before even the existing-fd path. That
 *     makes the stronger property true: without the marker, grant_root is
 *     unreachable regardless of how an fd arrived.
 *
 * tools/profile_binding_audit.py no longer asserts the call's absence; it
 * asserts this gate - that the only source naming the supercall is this file,
 * that the transport gate precedes both driver_fd and grant_root, and that the
 * Kotlin caller derives the flag from PostRootStatus.transportFixAllowed().
 */
#define DFR_KSU_DRIVER_LINK "[ksu_driver]"

/*
 * The supercall's own constants, from the same unstripped bytes. They are the
 * whole authorisation as far as the kernel is concerned: reboot_handler_pre()
 * is a kprobe on __arm64_sys_reboot that checks only these two magics and then
 * installs the fd via task_work. Nothing about the caller is examined here,
 * which is exactly why the gate has to be ours.
 */
#define DFR_KSU_SUPERCALL_MAGIC1 0xdeadbeefu
#define DFR_KSU_SUPERCALL_MAGIC2 0xcafebabeu

/*
 * The grant itself, read from the same bytes (cli::run, the su path): an ioctl
 * on a descriptor the kernel installed. Unlike the supercall above it is inert
 * without that descriptor - there is nothing to send it to - so it stays.
 */
#define DFR_KSU_IOCTL_GRANT_ROOT 0x4b01u /* _IO('K', 1) */

/* Matches the kernel's struct linux_dirent64 without pulling in a header that
 * does not expose it. getdents64 is used directly because this runs between
 * fork() and exec(), where opendir/readdir would allocate. */
struct dfr_dirent64 {
    unsigned long long d_ino;
    long long d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

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

static int dfr_parse_fd(const char *name, int *out)
{
    int value = 0;

    if (!*name) {
        return -1;
    }
    for (; *name; name++) {
        if (*name < '0' || *name > '9') {
            return -1;
        }
        value = value * 10 + (*name - '0');
        if (value > 65535) {
            return -1;
        }
    }
    *out = value;
    return 0;
}

/* Scan /proc/self/fd for a link naming the KernelSU driver. Separate from the
 * supercall on purpose: this observes, it never asks. */
static int real_scan_driver_fd(int *fd_out)
{
    char buf[4096];
    char link[256];
    int dir_fd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int found = -1;

    if (dir_fd < 0) {
        return -1;
    }
    for (;;) {
        long n = syscall(__NR_getdents64, dir_fd, buf, sizeof(buf));
        long off;

        if (n <= 0) {
            break;
        }
        for (off = 0; off < n;) {
            struct dfr_dirent64 *ent = (struct dfr_dirent64 *)(void *)(buf + off);
            ssize_t len;
            int candidate = -1;

            off += ent->d_reclen;
            if (dfr_parse_fd(ent->d_name, &candidate) != 0 || candidate == dir_fd) {
                continue;
            }
            len = readlinkat(dir_fd, ent->d_name, link, sizeof(link) - 1);
            if (len <= 0) {
                continue;
            }
            link[len] = '\0';
            if (strstr(link, DFR_KSU_DRIVER_LINK)) {
                found = candidate;
                break;
            }
        }
        if (found >= 0) {
            break;
        }
    }
    close(dir_fd);
    if (found < 0) {
        errno = ENOTTY;
        return -1;
    }
    *fd_out = found;
    return 0;
}

/*
 * Obtain the driver fd after child_main has authorised the entire transport
 * boundary. Keeping marker policy out of this acquisition routine is crucial:
 * the gate must dominate both the existing-fd shortcut and the later grant.
 */
static long real_supercall_driver_fd(int *fd_out)
{
    return syscall(__NR_reboot,
                   (long)(unsigned int)DFR_KSU_SUPERCALL_MAGIC1,
                   (long)(unsigned int)DFR_KSU_SUPERCALL_MAGIC2, 0L,
                   (void *)fd_out);
}

int dfr_acquire_driver_fd(const struct dfr_driver_fd_ops *ops, int *fd_out,
                          struct dfr_su_transport_diag *diag)
{
    int fd = -1;
    int call_errno;
    long rc;

    if (!ops || !ops->scan || !ops->supercall || !fd_out || !diag) {
        errno = EINVAL;
        return -1;
    }
    diag->fd_source = DFR_SU_FD_SOURCE_NONE;
    diag->supercall_rc = DFR_SU_SUPERCALL_NOT_ISSUED;
    diag->supercall_errno = 0;

    if (ops->scan(fd_out) == 0) {
        diag->fd_source = DFR_SU_FD_SOURCE_EXISTING;
        return 0;
    }

    rc = ops->supercall(&fd);
    call_errno = (rc != 0) ? errno : 0;
    diag->supercall_rc = rc;
    diag->supercall_errno = call_errno;
    /*
     * rc is deliberately NOT a gate on the scan below, and this is the whole
     * subtlety of the call. reboot_handler_pre() is a *pre*-handler: it queues
     * the install and returns 0 without suppressing the syscall, so the real
     * sys_reboot runs afterwards and its verdict says nothing about whether
     * the install happened. A failure there can mean the call never reached
     * the handler, or that it did and the fd is already installed. task_work
     * runs on the return to userspace, so by the time control is back here the
     * install has happened if it was going to.
     *
     * An earlier version returned immediately on rc != 0 and never looked.
     * That collapses two different facts into one token - "filtered before the
     * handler" and "handler installed an fd, then the syscall failed" - which
     * is what AGENTS.md 3.7 forbids, and it would have sent the next physical
     * run after the wrong question. Observe first, decide after.
     *
     * A returned success is not evidence the fd exists either (AGENTS.md 3.5),
     * so the scan is authoritative in both directions and the out-parameter is
     * only a fallback, trusted just when the call itself reported success.
     */
    if (ops->scan(fd_out) == 0) {
        diag->fd_source = DFR_SU_FD_SOURCE_SUPERCALL_POSTSCAN;
        return 0;
    }
    if (rc == 0 && fd >= 0) {
        *fd_out = fd;
        diag->fd_source = DFR_SU_FD_SOURCE_SUPERCALL_OUTPARAM;
        return 0;
    }
    /*
     * No fd, by observation. Report the syscall's own errno when it failed, so
     * the step token still names what the kernel said; ENOTTY stays the
     * "call succeeded and produced nothing" case.
     */
    errno = call_errno ? call_errno : ENOTTY;
    return -1;
}

static const struct dfr_driver_fd_ops real_driver_fd_ops = {
    real_scan_driver_fd,
    real_supercall_driver_fd,
};

static int real_driver_fd(int *fd_out, struct dfr_su_transport_diag *diag)
{
    return dfr_acquire_driver_fd(&real_driver_fd_ops, fd_out, diag);
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

static void child_write_all(int fd, const char *text, size_t len)
{
    while (len > 0) {
        ssize_t written = write(fd, text, len);

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        text += written;
        len -= (size_t)written;
    }
}

#define CHILD_WRITE_LITERAL(fd, literal) \
    child_write_all((fd), (literal), sizeof(literal) - 1)

static void child_write_long(int fd, long value)
{
    char digits[32];
    unsigned long magnitude;
    size_t pos = sizeof(digits);

    if (value < 0) {
        CHILD_WRITE_LITERAL(fd, "-");
        magnitude = (unsigned long)(-(value + 1)) + 1UL;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[--pos] = (char)('0' + magnitude % 10UL);
        magnitude /= 10UL;
    } while (magnitude != 0);
    child_write_all(fd, digits + pos, sizeof(digits) - pos);
}

static void child_emit_transport_diag(int out_fd,
                                      const struct dfr_su_transport_diag *diag)
{
    CHILD_WRITE_LITERAL(out_fd, "FD_SOURCE=");
    switch (diag->fd_source) {
    case DFR_SU_FD_SOURCE_EXISTING:
        CHILD_WRITE_LITERAL(out_fd, "EXISTING\n");
        break;
    case DFR_SU_FD_SOURCE_SUPERCALL_POSTSCAN:
        CHILD_WRITE_LITERAL(out_fd, "SUPERCALL_POSTSCAN\n");
        break;
    case DFR_SU_FD_SOURCE_SUPERCALL_OUTPARAM:
        CHILD_WRITE_LITERAL(out_fd, "SUPERCALL_OUTPARAM\n");
        break;
    default:
        CHILD_WRITE_LITERAL(out_fd, "NONE\n");
        break;
    }
    CHILD_WRITE_LITERAL(out_fd, "SUPERCALL_RC=");
    if (diag->supercall_rc == DFR_SU_SUPERCALL_NOT_ISSUED) {
        CHILD_WRITE_LITERAL(out_fd, "NOT_ISSUED\n");
    } else {
        child_write_long(out_fd, diag->supercall_rc);
        CHILD_WRITE_LITERAL(out_fd, "\n");
    }
    CHILD_WRITE_LITERAL(out_fd, "SUPERCALL_ERRNO=");
    child_write_long(out_fd, diag->supercall_errno);
    CHILD_WRITE_LITERAL(out_fd, "\n");
}

/*
 * Everything from here to exec runs between fork() and exec() in a process that
 * is a forked copy of system_server. No allocation, no libc call that may take
 * a lock the parent held: syscalls and write(2) only.
 */
static void child_main(const struct dfr_su_ops *ops, const char *comm,
                       char *const argv[], const char *pinned_hex,
                       int transport_fix_allowed,
                       int status_fd, int out_fd, int null_fd)
{
    struct dfr_su_transport_diag diag = {
        DFR_SU_FD_SOURCE_NONE, DFR_SU_SUPERCALL_NOT_ISSUED, 0
    };
    char found[65];
    int driver_fd = -1;
    int err = 0;
    int rc;
    int uid;

    memset(found, 0, sizeof(found));

    if (dup2(null_fd, STDIN_FILENO) < 0 || dup2(out_fd, STDOUT_FILENO) < 0 ||
        dup2(out_fd, STDERR_FILENO) < 0) {
        child_fail(status_fd, DFR_SU_STEP_PIPE, errno, NULL);
    }

    if (ops->set_comm(comm) != 0) {
        child_fail(status_fd, DFR_SU_STEP_COMM, errno, NULL);
    }
    /* The marker authorises the complete paired transport/grant predicate.
     * Keep this before even an existing-fd scan so an inherited descriptor can
     * never turn absence of evidence into permission to call grant_root(). */
    if (!transport_fix_allowed) {
        child_emit_transport_diag(out_fd, &diag);
        child_fail(status_fd, DFR_SU_STEP_TRANSPORT_FIX_GATED, EPERM, NULL);
    }
    if (ops->driver_fd(&driver_fd, &diag) != 0) {
        int driver_errno = errno;

        child_emit_transport_diag(out_fd, &diag);
        child_fail(status_fd, DFR_SU_STEP_DRIVER_FD, driver_errno, NULL);
    }
    child_emit_transport_diag(out_fd, &diag);
    if (ops->grant_root(driver_fd) != 0) {
        child_fail(status_fd, DFR_SU_STEP_GRANT, errno, NULL);
    }
    CHILD_WRITE_LITERAL(out_fd, "GRANT_RESULT=PASS\n");
    /*
     * A returned success is not evidence of root (AGENTS.md 3.5: a boolean is
     * not evidence). The credential change is observable, so observe it before
     * executing anything.
     */
    uid = ops->current_uid();
    CHILD_WRITE_LITERAL(out_fd, "UID_AFTER_GRANT=");
    child_write_long(out_fd, uid);
    CHILD_WRITE_LITERAL(out_fd, "\n");
    if (uid != 0) {
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
    CHILD_WRITE_LITERAL(out_fd, "INIT_MNT_NS=PASS\n");

    if (pinned_hex) {
        CHILD_WRITE_LITERAL(out_fd, "PINNED_DIGEST_BIND=ENTER\n");
        CHILD_WRITE_LITERAL(out_fd, "EXEC_HANDOFF=ENTER\n");
        rc = dfr_verified_execveat(argv[0], pinned_hex, argv, environ, &err, found);
        if (rc == DFR_VEXEC_ERR_DIGEST) {
            child_fail(status_fd, DFR_SU_STEP_DIGEST, 0, found);
        }
        child_fail(status_fd, DFR_SU_STEP_EXEC, err, NULL);
    }

    CHILD_WRITE_LITERAL(out_fd, "EXEC_HANDOFF=ENTER\n");
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
                 long timeout_ms, int kill_on_timeout, int transport_fix_allowed,
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
        child_main(ops, comm, argv, pinned_hex, transport_fix_allowed,
                   status_pipe[1], out_pipe[1], null_fd);
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
        "OK", "PIPE", "FORK", "COMM", "TRANSPORT_FIX_GATED",
        "DRIVER_FD", "GRANT", "NOT_ROOT",
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
