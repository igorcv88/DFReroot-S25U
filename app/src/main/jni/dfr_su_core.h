/*
 * dfr_su_core.h - the soft-reboot root transport, after the exec was refuted.
 *
 * ## Why this exists at all
 *
 * The previous transport executed a staged helper and let that helper ask the
 * paired KernelSU module for root. The device refused it: a process at
 * u:r:system_server:s0 - which is every component of this app, because the
 * manifest sets android:process="system" - cannot execve a file under /data.
 * Proven for apk_data_file and for system_data_file, reproduced outside the app
 * with runcon; see docs/S25U_ZZIC_COMPATIBILITY.md, "The exec proof came back
 * negative".
 *
 * That refutes the SHAPE of the transport, not its authorization boundary. The
 * paired module's predicate reads `current`:
 *
 *   uid == euid == 1000, caller SID == u:r:system_server:s0,
 *   real_parent SID == u:r:system_server:s0, comm == "dfreroot-ksud"
 *
 * A plain fork() of a thread inside system_server satisfies the uid, the caller
 * SID and the real-parent SID with nothing executed. Only the task name is
 * missing, and that module documents the name as defense in depth rather than
 * authority, precisely because it is mutable - so prctl(PR_SET_NAME) supplies
 * it. The grant therefore happens BEFORE any exec, and the exec that follows
 * runs from the domain KernelSU's own profile installs, which does execute from
 * /data (observed: a root shell on this device reports u:r:ksu:s0 and runs the
 * same file that system_server is refused).
 *
 * ## What is not yet known
 *
 * The client mechanics below were read out of the pinned daemon's own
 * unstripped bytes, not guessed: the driver fd comes from
 * syscall(__NR_reboot, 0xdeadbeef, 0xcafebabe, 0, &fd) and the grant is
 * ioctl(fd, _IO('K', 1)). What those bytes cannot say is whether the KERNEL
 * gates the fd install by the same allowed_for_su() the DFR patch extends, or
 * by manager/allowlist identity that a system_server child does not have. If it
 * is the latter, this refuses at DFR_SU_STEP_DRIVER_FD and nothing is executed.
 * That is the point of naming every step: one physical run then says which
 * boundary refused, instead of "the transport failed".
 */
#ifndef DFR_SU_CORE_H
#define DFR_SU_CORE_H

#include <stddef.h>

/*
 * Steps, in the order the child performs them. Every refusal names one: a
 * collapsed "it did not work" is what AGENTS.md 3.7 forbids, and here it would
 * also destroy the only diagnostic the next run can produce.
 */
enum dfr_su_step {
    DFR_SU_OK = 0,
    DFR_SU_STEP_PIPE,       /* could not build the status/output channel */
    DFR_SU_STEP_FORK,
    DFR_SU_STEP_COMM,       /* prctl(PR_SET_NAME) */
    DFR_SU_STEP_DRIVER_FD,  /* the KernelSU driver fd was not installed */
    DFR_SU_STEP_GRANT,      /* the grant ioctl was refused */
    DFR_SU_STEP_NOT_ROOT,   /* the ioctl returned success without uid 0 */
    DFR_SU_STEP_MNT_NS,     /* could not enter init's mount namespace */
    DFR_SU_STEP_EXEC,
    DFR_SU_STEP_DIGEST,     /* the pinned daemon's bytes are not the pinned ones */
    DFR_SU_STEP_TIMEOUT,
    DFR_SU_STEP_INTERNAL
};

/*
 * The privileged syscalls behind one interface, so the parent-side machinery
 * (fork, pipes, capping, deadline, reaping) is exercised on a host with no
 * KernelSU - including the failure of each individual step, which is otherwise
 * only reachable on hardware. AGENTS.md 5 requires exactly this shape.
 */
struct dfr_su_ops {
    int (*set_comm)(const char *comm);        /* 0, or -1 with errno */
    int (*driver_fd)(int *fd_out);            /* 0, or -1 with errno */
    int (*grant_root)(int driver_fd);         /* 0, or -1 with errno */
    int (*current_uid)(void);
    int (*enter_init_mnt_ns)(void);           /* 0, or -1 with errno */
};

/* The real device implementation. */
extern const struct dfr_su_ops dfr_su_real_ops;

struct dfr_su_result {
    int step;       /* enum dfr_su_step */
    int err;        /* errno for a failed step; 0 otherwise */
    int exit_code;  /* the child's exit status, valid when reaped is 1 */
    int reaped;
    size_t out_len; /* bytes placed in out, always NUL-terminated */
    int truncated;
    char found_hex[65]; /* digest actually seen, for DFR_SU_STEP_DIGEST */
};

/*
 * Fork, become root, and exec argv.
 *
 * argv must be fully built before the call: nothing between fork() and exec()
 * may allocate. When pinned_hex is non-NULL, argv[0] is executed through
 * dfr_verified_execveat(), so the digest is bound to the file description that
 * runs; when it is NULL, argv[0] is exec'd directly (used for the probe shell,
 * which is a /system binary and not the artefact under identity control).
 *
 * kill_on_timeout is deliberately a parameter rather than a policy: killing a
 * hung probe shell is housekeeping, and killing a task that may already be
 * ksud mid-soft-reboot is not.
 *
 * Returns 0 when the child was started and reaped normally, -1 otherwise; the
 * verdict is always in res->step, which the caller must read either way.
 */
int dfr_su_spawn(const struct dfr_su_ops *ops, const char *comm,
                 char *const argv[], const char *pinned_hex,
                 long timeout_ms, int kill_on_timeout,
                 char *out, size_t out_cap, struct dfr_su_result *res);

/* Stable, greppable token for a result: the app logs it verbatim, and the
 * repository's rule is that a reader never has to guess what a verdict meant. */
void dfr_su_status_token(const struct dfr_su_result *res, char *buf, size_t cap);

#endif /* DFR_SU_CORE_H */
