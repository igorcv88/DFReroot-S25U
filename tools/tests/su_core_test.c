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
#include <sys/stat.h>
#include <unistd.h>

static int failures;
static int fake_uid;
static int fail_step;
/* Whether the fake driver_fd op should behave like the real one: refuse with
 * EPERM when the supercall is not authorised. */
static int fake_fd_needs_supercall;

static void check(int ok, const char *what)
{
    printf("%s  %s\n", ok ? "ok   " : "FAIL ", what);
    if (!ok) {
        failures++;
    }
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

static int fake_driver_fd(int *fd_out, int supercall_allowed)
{
    if (fail_step == DFR_SU_STEP_DRIVER_FD) {
        /* ENOTTY, not EPERM: this stands for "the scan found nothing and the
         * supercall was allowed but produced nothing", which must NOT be
         * reported as the gate. */
        errno = ENOTTY;
        return -1;
    }
    if (fake_fd_needs_supercall && !supercall_allowed) {
        /* Exactly what real_driver_fd() does when the marker withheld it. */
        errno = EPERM;
        return -1;
    }
    *fd_out = STDERR_FILENO;
    return 0;
}

static int fake_grant_root(int fd)
{
    (void)fd;
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
    fake_set_comm, fake_driver_fd, fake_grant_root, fake_current_uid,
    fake_enter_init_mnt_ns,
};

static void reset(void)
{
    fake_uid = 0;
    fail_step = -1;
    fake_fd_needs_supercall = 0;
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

    reset();
    check(run(echo_argv, NULL, 5000, 1, out, sizeof(out), &res) == 0,
          "a granted child runs and is reaped");
    check(res.step == DFR_SU_OK && res.reaped && res.exit_code == 0,
          "success is reported as OK with the child's exit code");
    check(strstr(out, "uid=0") && strstr(out, "second"),
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
    check(strlen(out) == 0, "nothing was executed, so nothing was captured");

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
     * The real driver-fd lookup, which is no longer privileged and therefore
     * runs here. It must find nothing on a host with no KernelSU, and it must
     * say so by returning an error rather than by handing back a stale fd - a
     * grant ioctl sent to an arbitrary descriptor is not a refusal.
     */
    {
        int fd = 12345;

        /*
         * supercall_allowed = 0 on a build host is the interesting direction:
         * it must refuse WITHOUT issuing the syscall. Passing 1 here would
         * issue a real reboot(2) on the host, which is why this only ever
         * asserts the gated side. The permitted side is covered by the fake
         * op, where the syscall is not real.
         */
        check(dfr_su_real_ops.driver_fd(&fd, 0) == -1 && fd == 12345,
              "the real driver-fd lookup refuses with the supercall withheld "
              "and leaves fd_out untouched");
        check(errno == EPERM,
              "and it refuses with EPERM, the errno the gate reserves");
    }

    /*
     * The gate of AGENTS.md 3.6.1, both directions plus the two ways it could
     * be mistaken for something else. A gate that cannot fail is not a gate,
     * and a gate whose refusal is indistinguishable from a kernel refusal
     * tells the next physical run nothing (AGENTS.md 3.7).
     */
    reset();
    fake_fd_needs_supercall = 1;
    check(run_gated(echo_argv, NULL, 5000, 1, 0, out, sizeof(out), &res) == -1 &&
              res.step == DFR_SU_STEP_SUPERCALL_GATED,
          "with no transport_fix marker the child refuses at SUPERCALL_GATED");
    check(strlen(out) == 0,
          "and nothing was executed, so nothing was captured");
    dfr_su_status_token(&res, token, sizeof(token));
    check(strstr(token, "DFR_SU_STEP=SUPERCALL_GATED") == token,
          "the gated refusal renders its own token, not DRIVER_FD's");

    reset();
    fake_fd_needs_supercall = 1;
    check(run_gated(echo_argv, NULL, 5000, 1, 1, out, sizeof(out), &res) == 0 &&
              res.step == DFR_SU_OK,
          "with the marker present the same run proceeds");

    reset();
    fake_fd_needs_supercall = 0;
    check(run_gated(echo_argv, NULL, 5000, 1, 0, out, sizeof(out), &res) == 0 &&
              res.step == DFR_SU_OK,
          "a task that already holds the fd never reaches the gate");

    /*
     * The two failures must stay distinguishable. A driver_fd op that fails
     * for its own reason while the supercall was withheld must still report
     * DRIVER_FD - collapsing it into the gate would blame the marker for a
     * kernel refusal.
     */
    reset();
    fail_step = DFR_SU_STEP_DRIVER_FD;
    check(run_gated(echo_argv, NULL, 5000, 1, 0, out, sizeof(out), &res) == -1 &&
              res.step == DFR_SU_STEP_DRIVER_FD && res.err == ENOTTY,
          "a non-gate driver-fd failure is not relabelled as the gate");

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
    printf("\nsu_core_test passed\n");
    return 0;
}
