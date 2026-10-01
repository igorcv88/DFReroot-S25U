/*
 * Host test for the soft-reboot root transport's parent side.
 *
 * The privileged half cannot run here - there is no KernelSU on a build host -
 * so it sits behind struct dfr_su_ops and is faked. What IS exercised is
 * everything that decides an outcome: the fork, the two channels, the output
 * cap, the deadline, the reaping, and one case per refusal step. A gate that
 * cannot fail is not a gate (AGENTS.md 5), so every step gets a negative case.
 */
#define _GNU_SOURCE

#include "dfr_su_core.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
static int fake_uid;
static int fail_step;
/* Whether the fake driver_fd op should behave like the real one: refuse with
 * EPERM when the supercall is not authorised. */
static int fake_fd_source;
static volatile int *fake_driver_calls;
static volatile int *fake_grant_calls;

static void check(int ok, const char *what)
{
    printf("%s  %s\n", ok ? "ok   " : "FAIL ", what);
    if (!ok) {
        failures++;
    }
}

/*
 * The quarantine is NOT faked for the positive cases: the real implementation
 * is unprivileged, so the host suite runs the code the device runs. The fake
 * exists only to produce the refusal, which no host condition can provoke -
 * and a gate that cannot fail is not a gate (AGENTS.md 5).
 */
static int fake_fd_quarantine(int *method_out)
{
    if (fail_step == DFR_SU_STEP_FD_QUARANTINE) {
        *method_out = DFR_SU_FDQ_NONE;
        errno = EMFILE;
        return -1;
    }
    return dfr_fd_quarantine(method_out);
}

static int fake_set_comm(const char *comm)
{
    (void)comm;
    if (fail_step == DFR_SU_STEP_COMM) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

/* When set, the fake acquisition hands back a descriptor for this path, opened
 * O_CLOEXEC on purpose: the exec must see it only because child_main clears the
 * flag deliberately. Unset, the cheap stand-in is used, as for every case that
 * is not about the exception. */
static const char *fake_driver_fd_path;

static int fake_driver_fd(int *fd_out, struct dfr_su_transport_diag *diag)
{
    (*fake_driver_calls)++;
    diag->fd_source = fake_fd_source;
    diag->supercall_rc = DFR_SU_SUPERCALL_NOT_ISSUED;
    diag->supercall_errno = 0;
    if (fail_step == DFR_SU_STEP_DRIVER_FD) {
        /* ENOTTY, not EPERM: this stands for "the scan found nothing and the
         * supercall was allowed but produced nothing", which must NOT be
         * reported as the gate. */
        errno = ENOTTY;
        return -1;
    }
    if (fake_driver_fd_path) {
        int fd = open(fake_driver_fd_path, O_RDONLY | O_CLOEXEC);

        if (fd < 0) {
            return -1;
        }
        *fd_out = fd;
        return 0;
    }
    *fd_out = STDERR_FILENO;
    return 0;
}

static int fake_grant_root(int fd)
{
    (void)fd;
    (*fake_grant_calls)++;
    if (fail_step == DFR_SU_STEP_GRANT) {
        errno = ENOTTY;
        return -1;
    }
    return 0;
}

static int fake_current_uid(void)
{
    return fake_uid;
}

static int fake_enter_init_mnt_ns(void)
{
    if (fail_step == DFR_SU_STEP_MNT_NS) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

static const struct dfr_su_ops fake_ops = {
    fake_fd_quarantine, fake_set_comm, fake_driver_fd, fake_grant_root,
    fake_current_uid, fake_enter_init_mnt_ns,
};

static void reset(void)
{
    fake_uid = 0;
    fail_step = -1;
    fake_fd_source = DFR_SU_FD_SOURCE_EXISTING;
    fake_driver_fd_path = NULL;
    *fake_driver_calls = 0;
    *fake_grant_calls = 0;
}

static int acquire_scan_calls;
static int acquire_scan_success_on;
static long acquire_supercall_rc;
static int acquire_supercall_errno;
static int acquire_supercall_fd;
static int acquire_supercall_calls;

static int acquire_scan(int *fd_out)
{
    acquire_scan_calls++;
    if (acquire_scan_calls == acquire_scan_success_on) {
        *fd_out = 42;
        return 0;
    }
    errno = ENOTTY;
    return -1;
}

static long acquire_supercall(int *fd_out)
{
    acquire_supercall_calls++;
    *fd_out = acquire_supercall_fd;
    errno = acquire_supercall_errno;
    return acquire_supercall_rc;
}

static const struct dfr_driver_fd_ops acquire_ops = {
    acquire_scan, acquire_supercall,
};

static void reset_acquire(void)
{
    acquire_scan_calls = 0;
    acquire_scan_success_on = -1;
    acquire_supercall_rc = -1;
    acquire_supercall_errno = EPERM;
    acquire_supercall_fd = -1;
    acquire_supercall_calls = 0;
}

static int run_gated(char *const argv[], const char *pinned, long timeout_ms,
                     int kill_on_timeout, int supercall_allowed, char *out,
                     size_t cap, struct dfr_su_result *res)
{
    return dfr_su_spawn(&fake_ops, "dfreroot-ksud", argv, pinned, timeout_ms,
                        kill_on_timeout, supercall_allowed, out, cap, res);
}

/*
 * The existing cases all run with the supercall permitted, because they are
 * about the steps AFTER the fd is obtained. The gate has its own cases below.
 */
static int run(char *const argv[], const char *pinned, long timeout_ms,
               int kill_on_timeout, char *out, size_t cap,
               struct dfr_su_result *res)
{
    return run_gated(argv, pinned, timeout_ms, kill_on_timeout, 1, out, cap,
                     res);
}

int main(void)
{
    struct dfr_su_result res;
    char out[256];
    char token[128];
    char *echo_argv[] = { (char *)"/bin/sh", (char *)"-c",
                          (char *)"echo uid=0; echo second", NULL };
    char *sleep_argv[] = { (char *)"/bin/sh", (char *)"-c",
                           (char *)"sleep 30", NULL };
    char *rc_argv[] = { (char *)"/bin/sh", (char *)"-c", (char *)"exit 7", NULL };
    char *missing_argv[] = { (char *)"/nonexistent/dfr", NULL };
    int steps[] = { DFR_SU_STEP_COMM, DFR_SU_STEP_DRIVER_FD, DFR_SU_STEP_GRANT,
                    DFR_SU_STEP_MNT_NS };
    size_t i;

    fake_driver_calls = mmap(NULL, sizeof(*fake_driver_calls),
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    fake_grant_calls = mmap(NULL, sizeof(*fake_grant_calls),
                            PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (fake_driver_calls == MAP_FAILED || fake_grant_calls == MAP_FAILED) {
        perror("mmap");
        return 2;
    }

    reset();
    check(run(echo_argv, NULL, 5000, 1, out, sizeof(out), &res) == 0,
          "a granted child runs and is reaped");
    check(res.step == DFR_SU_OK && res.reaped && res.exit_code == 0,
          "success is reported as OK with the child's exit code");
    check(strstr(out, "FD_SOURCE=EXISTING") &&
              strstr(out, "SUPERCALL_RC=NOT_ISSUED") &&
              strstr(out, "SUPERCALL_ERRNO=0") &&
              strstr(out, "uid=0") && strstr(out, "second"),
          "stdout is captured across multiple writes");
    dfr_su_status_token(&res, token, sizeof(token));
    check(strcmp(token, "DFR_SU_STEP=OK exit=0") == 0, "the OK token is stable");

    reset();
    check(run(rc_argv, NULL, 5000, 1, out, sizeof(out), &res) == 0 &&
              res.exit_code == 7,
          "a non-zero exit status is propagated, not flattened");

    /* One negative case per privileged step. Each must name ITSELF: this is the
     * only diagnostic a physical run will produce. */
    for (i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
        char what[256];

        reset();
        fail_step = steps[i];
        check(run(echo_argv, NULL, 5000, 1, out, sizeof(out), &res) == -1 &&
                  res.step == steps[i] && res.err != 0,
              "a refusal names its own step and errno");
        dfr_su_status_token(&res, token, sizeof(token));
        snprintf(what, sizeof(what), "step %d renders a distinct token (%s)",
                 steps[i], token);
        check(strstr(token, "DFR_SU_STEP=") == token && !strstr(token, "=OK"),
              what);
    }

    /* The one that is not an errno: the ioctl succeeded and the caller is still
     * not root. A returned success is not evidence (AGENTS.md 3.5). */
    reset();
    fake_uid = 1000;
    check(run(echo_argv, NULL, 5000, 1, out, sizeof(out), &res) == -1 &&
              res.step == DFR_SU_STEP_NOT_ROOT,
          "a grant that leaves uid 1000 refuses instead of executing");
    check(!strstr(out, "uid=0"), "nothing was executed after a false grant");

    reset();
    check(run(missing_argv, NULL, 5000, 1, out, sizeof(out), &res) == -1 &&
              res.step == DFR_SU_STEP_EXEC && res.err == ENOENT,
          "a failed exec is reported as EXEC with the real errno");

    reset();
    check(run(sleep_argv, NULL, 300, 1, out, sizeof(out), &res) == -1 &&
              res.step == DFR_SU_STEP_TIMEOUT && res.reaped,
          "a child that outlives the deadline is TIMEOUT, and killed when asked");

    reset();
    check(run(echo_argv, NULL, 5000, 1, out, 8, &res) == 0 && res.truncated &&
              strlen(out) == 7,
          "output is capped and the truncation is recorded, not hidden");

    /* The digest path: argv[0] is a real file whose bytes are not the pin. */
    reset();
    {
        char *pinned_argv[] = { (char *)"/bin/sh", NULL };
        const char *wrong =
            "0000000000000000000000000000000000000000000000000000000000000000";

        check(run(pinned_argv, wrong, 5000, 1, out, sizeof(out), &res) == -1 &&
                  res.step == DFR_SU_STEP_DIGEST,
              "a pinned exec whose bytes differ refuses before executing");
        check(strlen(res.found_hex) == 64,
              "the digest actually found is reported back");
        dfr_su_status_token(&res, token, sizeof(token));
        check(strstr(token, "DFR_SU_STEP=DIGEST found=") == token,
              "the digest refusal names the bytes it saw");
    }

    /*
     * Cases inherited from tools/tests/test_soft_reboot_shell.sh, which drove the
     * shell that used to hash and exec a pathname. That shell is gone; the same
     * questions are asked of the descriptor-bound exec that replaced it.
     */
    reset();
    {
        char *gone_argv[] = { (char *)"/nonexistent/dfr", NULL };
        const char *any =
            "0000000000000000000000000000000000000000000000000000000000000000";

        check(run(gone_argv, any, 5000, 1, out, sizeof(out), &res) == -1 &&
                  res.step == DFR_SU_STEP_EXEC && res.err == ENOENT,
              "a pinned daemon that is not there refuses, and is not a digest "
              "verdict");
    }

    reset();
    if (geteuid() != 0) {
        char path[] = "/tmp/dfr_su_test_unreadableXXXXXX";
        int fd = mkstemp(path);

        if (fd >= 0) {
            char *unreadable_argv[] = { path, NULL };
            const char *any =
                "0000000000000000000000000000000000000000000000000000000000000000";

            close(fd);
            chmod(path, 0);
            check(run(unreadable_argv, any, 5000, 1, out, sizeof(out), &res) == -1 &&
                      res.step == DFR_SU_STEP_EXEC && res.err == EACCES,
                  "a pinned daemon that cannot be read refuses; an unreadable "
                  "artefact never counts as agreement");
            unlink(path);
        }
    } else {
        printf("skip   unreadable case (running as root)\n");
    }


    /*
     * The descriptor boundary. This is the one case in this file that asks a
     * question about the device's actual failure rather than about a step's
     * bookkeeping: after a soft reboot, descriptors belonging to the destroyed
     * system_server were still open in this transport's descendants, the old
     * lmkd channel among them (dfr_su_core.h records the inode and the fd
     * numbers). The property that has to hold is not "the lmkd socket is
     * closed" - naming one descriptor would be the same defect in a smaller
     * costume - but that NOTHING arbitrary crosses the exec.
     *
     * So the parent opens the two shapes the device showed, without
     * FD_CLOEXEC, exactly as system_server's own code would leave them, and
     * the exec'd process is asked to list what it holds. The stray regular
     * file is identifiable by its unique path; the stray socket by its inode,
     * which is how it was identified on the device too.
     */
    reset();
    {
        char stray_path[] = "/tmp/dfr_su_test_strayXXXXXX";
        char driver_path[] = "/tmp/dfr_su_test_driverXXXXXX";
        int stray_fd = mkstemp(stray_path);
        int driver_seed = mkstemp(driver_path);
        int sv[2] = { -1, -1 };
        struct stat sb;
        char socket_marker[64] = "";
        char *list_argv[] = { (char *)"/bin/sh", (char *)"-c",
                              (char *)"ls -l /proc/$$/fd", NULL };
        char big[8192];

        check(stray_fd >= 0 && driver_seed >= 0 &&
                  socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0,
              "the stray descriptors under test could be created");
        close(driver_seed);
        if (stray_fd >= 0 && sv[0] >= 0 && fstat(sv[0], &sb) == 0) {
            snprintf(socket_marker, sizeof(socket_marker), "socket:[%llu]",
                     (unsigned long long)sb.st_ino);
            /* No FD_CLOEXEC on either, deliberately: a descriptor whose owner
             * already marked it needs no boundary, and the ones that caused
             * this bug are precisely the ones nobody marked. */
            check(!(fcntl(stray_fd, F_GETFD) & FD_CLOEXEC) &&
                      !(fcntl(sv[0], F_GETFD) & FD_CLOEXEC),
                  "the strays start without FD_CLOEXEC, as system_server's do");

            fake_driver_fd_path = driver_path;
            check(run(list_argv, NULL, 5000, 1, big, sizeof(big), &res) == 0 &&
                      res.step == DFR_SU_OK,
                  "a child with a quarantined table still reaches the exec");
            check(strstr(big, "FD_QUARANTINE=CLOSE_RANGE") ||
                      strstr(big, "FD_QUARANTINE=PROC_SCAN"),
                  "the mechanism that sanitised the table is named in the log");
            check(!res.truncated,
                  "the descriptor listing was captured whole, so an absence "
                  "below is an absence and not a truncation");
            check(strstr(big, stray_path) == NULL,
                  "an inherited regular-file descriptor does not survive the "
                  "exec");
            check(socket_marker[0] && strstr(big, socket_marker) == NULL,
                  "an inherited unix socket does not survive the exec - the "
                  "shape the old lmkd channel had");
            /* The named exception, proven as an exception: the fake opened it
             * O_CLOEXEC, so it can only be here because child_main cleared the
             * flag on purpose. */
            check(strstr(big, "DRIVER_FD_KEEP=PASS") != NULL,
                  "the driver descriptor's exception is recorded");
            check(strstr(big, driver_path) != NULL,
                  "the KernelSU driver descriptor is the one exception, and it "
                  "does survive, so the daemon issues no supercall of its own");
            /* The positive control for the two absences above: stdin is this
             * child's own /dev/null, so a listing naming it is a listing that
             * really enumerated the table. Without this, a command that printed
             * nothing would pass both absence checks. */
            check(strstr(big, "/dev/null") != NULL,
                  "the listing enumerated a real descriptor table, so the "
                  "absences above are absences and not an empty listing");
            close(stray_fd);
            close(sv[0]);
            close(sv[1]);
        }
        unlink(stray_path);
        unlink(driver_path);
    }

    /* And the refusal. Nothing may be executed with a table this code could not
     * account for; "most of it was sanitised" is not a sanitised table. */
    reset();
    fail_step = DFR_SU_STEP_FD_QUARANTINE;
    check(run(echo_argv, NULL, 5000, 1, out, sizeof(out), &res) == -1 &&
              res.step == DFR_SU_STEP_FD_QUARANTINE && res.err == EMFILE,
          "a table that cannot be quarantined refuses at FD_QUARANTINE");
    check(!strstr(out, "uid=0") && *fake_driver_calls == 0 &&
              *fake_grant_calls == 0,
          "the refusal precedes the grant and executes nothing");
    check(strstr(out, "FD_QUARANTINE=NONE") != NULL,
          "the refusal says no mechanism spoke, rather than leaving a gap");
    dfr_su_status_token(&res, token, sizeof(token));
    check(strcmp(token, "DFR_SU_STEP=FD_QUARANTINE errno=24") == 0 ||
              strstr(token, "DFR_SU_STEP=FD_QUARANTINE errno=") == token,
          "the quarantine refusal renders its own token");

    /* The real implementation on its own, away from the fork: it must name a
     * mechanism, and it must never report success with NONE. */
    {
        int method = DFR_SU_FDQ_CLOSE_RANGE;

        check(dfr_fd_quarantine(NULL) == -1 && errno == EINVAL,
              "the quarantine refuses a call it cannot report through");
        check(dfr_fd_quarantine(&method) == 0 &&
                  (method == DFR_SU_FDQ_CLOSE_RANGE ||
                   method == DFR_SU_FDQ_PROC_SCAN),
              "the quarantine names the mechanism it used");
    }

    /*
     * The real driver-fd lookup, which is no longer privileged and therefore
     * runs here. It must find nothing on a host with no KernelSU, and it must
     * say so by returning an error rather than by handing back a stale fd - a
     * grant ioctl sent to an arbitrary descriptor is not a refusal.
     */
    /* Exercise the real acquisition algorithm without issuing reboot(2). */
    {
        struct dfr_su_transport_diag diag;
        int fd = -1;

        reset_acquire();
        acquire_scan_success_on = 1;
        check(dfr_acquire_driver_fd(&acquire_ops, &fd, &diag) == 0 &&
                  diag.fd_source == DFR_SU_FD_SOURCE_EXISTING &&
                  acquire_supercall_calls == 0,
              "an existing driver fd is named EXISTING without a supercall");

        reset_acquire();
        acquire_scan_success_on = 2;
        check(dfr_acquire_driver_fd(&acquire_ops, &fd, &diag) == 0 &&
                  diag.fd_source == DFR_SU_FD_SOURCE_SUPERCALL_POSTSCAN &&
                  diag.supercall_rc == -1 && diag.supercall_errno == EPERM,
              "EPERM plus a post-call fd continues as SUPERCALL_POSTSCAN");

        reset_acquire();
        check(dfr_acquire_driver_fd(&acquire_ops, &fd, &diag) == -1 &&
                  errno == EPERM && diag.fd_source == DFR_SU_FD_SOURCE_NONE &&
                  diag.supercall_rc == -1 && diag.supercall_errno == EPERM,
              "EPERM plus no post-call fd remains DRIVER_FD evidence");

        reset_acquire();
        acquire_supercall_rc = 0;
        acquire_supercall_errno = 0;
        acquire_supercall_fd = 77;
        check(dfr_acquire_driver_fd(&acquire_ops, &fd, &diag) == 0 && fd == 77 &&
                  diag.fd_source == DFR_SU_FD_SOURCE_SUPERCALL_OUTPARAM,
              "a successful out-parameter is named SUPERCALL_OUTPARAM");
    }

    /*
     * The gate of AGENTS.md 3.6.1, both directions plus the two ways it could
     * be mistaken for something else. A gate that cannot fail is not a gate,
     * and a gate whose refusal is indistinguishable from a kernel refusal
     * tells the next physical run nothing (AGENTS.md 3.7).
     */
    reset();
    check(run_gated(echo_argv, NULL, 5000, 1, 0, out, sizeof(out), &res) == -1 &&
              res.step == DFR_SU_STEP_TRANSPORT_FIX_GATED,
          "marker absent plus an existing fd refuses at TRANSPORT_FIX_GATED");
    check(*fake_driver_calls == 0 && *fake_grant_calls == 0,
          "the absent marker reaches neither fd acquisition nor grant_root");
    check(strstr(out, "FD_SOURCE=NONE") &&
              strstr(out, "SUPERCALL_RC=NOT_ISSUED"),
          "the gated path records that no supercall was issued");
    dfr_su_status_token(&res, token, sizeof(token));
    check(strstr(token, "DFR_SU_STEP=TRANSPORT_FIX_GATED") == token,
          "the gated refusal renders its own token, not DRIVER_FD's");

    reset();
    check(run_gated(echo_argv, NULL, 5000, 1, 1, out, sizeof(out), &res) == 0 &&
              res.step == DFR_SU_OK && *fake_grant_calls == 1,
          "marker present plus an existing fd reaches one grant");

    reset();
    fake_fd_source = DFR_SU_FD_SOURCE_NONE;
    check(run_gated(echo_argv, NULL, 5000, 1, 0, out, sizeof(out), &res) == -1 &&
              res.step == DFR_SU_STEP_TRANSPORT_FIX_GATED &&
              *fake_driver_calls == 0 && *fake_grant_calls == 0,
          "marker absent plus no fd issues no supercall and no grant");

    /*
     * The two failures must stay distinguishable. A driver_fd op that fails
     * for its own reason while the supercall was withheld must still report
     * DRIVER_FD - collapsing it into the gate would blame the marker for a
     * kernel refusal.
     */
    reset();
    fail_step = DFR_SU_STEP_DRIVER_FD;
    check(run_gated(echo_argv, NULL, 5000, 1, 1, out, sizeof(out), &res) == -1 &&
              res.step == DFR_SU_STEP_DRIVER_FD && res.err == ENOTTY,
          "an authorised driver-fd failure is not relabelled as the gate");

    /*
     * Note on what is NOT asserted here: the fake op runs in the forked child,
     * so no variable it sets can be read back in this process. The two cases
     * above are the propagation proof - the same run refuses or proceeds
     * purely on the flag's value, which it could not do if the flag were
     * dropped or overridden on the way down.
     */

    reset();
    check(run(NULL, NULL, 5000, 1, out, sizeof(out), &res) == -1 &&
              res.step == DFR_SU_STEP_INTERNAL,
          "a malformed call refuses rather than forking");

    if (failures) {
        printf("\nsu_core_test FAILED: %d\n", failures);
        return 1;
    }
    munmap((void *)fake_driver_calls, sizeof(*fake_driver_calls));
    munmap((void *)fake_grant_calls, sizeof(*fake_grant_calls));
    printf("\nsu_core_test passed\n");
    return 0;
}
