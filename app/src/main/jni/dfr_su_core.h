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
 * ## What the device answered, and what the answer changed
 *
 * The first build to try this rebooted the device instead of refusing. Three
 * rounds of reasoning named causes they could not evidence. Samsung's
 * /sys/class/sec/sec_hw_param/extra_info then produced the panic record and
 * settled it: the magic supercall WORKED - "ksu fd installed: 96 for pid
 * 16452" - and the kernel died 152 us later at
 * allowed_for_su+0x12c/0x248 [kernelsu], on a put_cred() that
 * CONFIG_KSU_SAMSUNG_KDP makes an illegal write. The transport was not the
 * fault; the module it asked was.
 *
 * So the complete transport/grant path is allowed only when AGENTS.md 3.6.1's
 * evidence is present: a complete post-root record for the CURRENT boot must
 * say the loaded module carries transport_fix=kdp-cred-1. The earlier gate was
 * too narrow: a child that already held [ksu_driver] skipped the supercall gate
 * and could still enter the unsafe grant predicate. transport_fix_allowed is
 * therefore checked before *any* driver-fd path, and with it 0 the child
 * refuses at DFR_SU_STEP_TRANSPORT_FIX_GATED without scanning, asking, or
 * granting.
 *
 * "The fd was missing" is deliberately NOT a second condition that can stand
 * in for the marker. That reasoning - the scan found nothing, so ask - is what
 * panicked the device, and dfr_su_core.c is written so the call cannot be
 * reached by it.
 *
 * ## Why the child quarantines the descriptor table
 *
 * The fork above is a fork of system_server, so the child starts life holding
 * system_server's whole descriptor table: Binder, the logging sockets, the
 * HAL channels, and the control socket to lmkd. Every one of those that its
 * owner did not mark FD_CLOEXEC survives the exec below and lives on for as
 * long as the daemon does.
 *
 * That is not hypothetical here. After an Apply Modules on this device the
 * lmkd endpoint of the generation of system_server that the soft reboot
 * destroyed (inode 47482, lmkd fd 16) was still open as fd 148 in the
 * descendants of this transport - busybox, the root manager's daemon,
 * zygisk_lsposed, nsdaemon-zygote. The peer of a socket belonging to a dead
 * system_server cannot be collected while a descriptor for it exists, so the
 * old channel stayed half-alive across the restart. Roughly an hour later
 * lmkd's main thread left do_epoll_wait for sock_alloc_send_pskb and never
 * came back, its own watchdog began firing every two seconds, and the new
 * system_server then blocked in LmkdConnection.write while holding
 * ActivityManagerProcLock - which is what the user experiences as the device
 * going dark with only the power key still vibrating.
 *
 * Whether the leaked descriptor is what put lmkd in that state is NOT
 * established, and this file must not claim it is: a stable run showed the
 * same two endpoints and never failed. What IS established is that descriptors
 * from a privileged process leave through this exec, and the repository's rule
 * is that the transport does not get to be the layer whose correctness nobody
 * can state. So the boundary is hermetic by construction rather than by
 * knowing which descriptor mattered: no descriptor crosses the exec unless
 * this file names it and says why.
 *
 * Exactly one is named - the KernelSU driver descriptor, see dfr_su_core.c.
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
    DFR_SU_STEP_FD_QUARANTINE, /* the inherited descriptor table could not be
                                * made hermetic across the exec */
    DFR_SU_STEP_COMM,       /* prctl(PR_SET_NAME) */
    DFR_SU_STEP_TRANSPORT_FIX_GATED, /* the paired transport/grant predicate
                                      * was not authorised for this boot */
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
 * How the descriptor table was made hermetic. Two mechanisms, named apart
 * because they are different evidence: close_range(2) is one syscall that
 * covers every descriptor that exists, while the /proc scan enumerates them
 * and is only as complete as /proc/self/fd. A reader of the log must never
 * have to guess which one spoke (AGENTS.md 3.7).
 */
enum dfr_su_fd_quarantine_method {
    DFR_SU_FDQ_NONE = 0,
    DFR_SU_FDQ_CLOSE_RANGE,
    DFR_SU_FDQ_PROC_SCAN
};

/*
 * Mark every descriptor at or above DFR_SU_FD_QUARANTINE_FLOOR close-on-exec.
 *
 * Marking, not closing: everything between fork() and exec() still needs the
 * status pipe, the output pipe and - on the EXISTING path - an inherited
 * [ksu_driver] descriptor, so closing here would break the grant the exec
 * depends on. FD_CLOEXEC moves the closure to the one boundary that matters.
 *
 * Returns 0 and names the mechanism in method_out, or -1 with errno and
 * DFR_SU_FDQ_NONE. There is no partial success: a table this cannot account
 * for is reported as a failure, because "most of it was sanitised" is the
 * absence of evidence about the rest (AGENTS.md 2).
 */
#define DFR_SU_FD_QUARANTINE_FLOOR 3

int dfr_fd_quarantine(int *method_out);

enum dfr_su_fd_source {
    DFR_SU_FD_SOURCE_NONE = 0,
    DFR_SU_FD_SOURCE_EXISTING,
    DFR_SU_FD_SOURCE_SUPERCALL_POSTSCAN,
    DFR_SU_FD_SOURCE_SUPERCALL_OUTPARAM
};

struct dfr_su_transport_diag {
    int fd_source;       /* enum dfr_su_fd_source */
    long supercall_rc;   /* DFR_SU_SUPERCALL_NOT_ISSUED when no call occurred */
    int supercall_errno; /* captured independently from supercall_rc */
};

#define DFR_SU_SUPERCALL_NOT_ISSUED (-2147483647L - 1L)

/* Injectable acquisition core. This is the PR #39 branch under host test:
 * even an EPERM syscall result is followed by an unconditional fd scan. */
struct dfr_driver_fd_ops {
    int (*scan)(int *fd_out);
    long (*supercall)(int *fd_out); /* -1 with errno, or the raw syscall rc */
};

int dfr_acquire_driver_fd(const struct dfr_driver_fd_ops *ops, int *fd_out,
                          struct dfr_su_transport_diag *diag);

/*
 * The privileged syscalls behind one interface, so the parent-side machinery
 * (fork, pipes, capping, deadline, reaping) is exercised on a host with no
 * KernelSU - including the failure of each individual step, which is otherwise
 * only reachable on hardware. AGENTS.md 5 requires exactly this shape.
 */
struct dfr_su_ops {
    /* First, because nothing else in the child may run with a descriptor table
     * it has not accounted for. Injectable for the same reason as the rest: a
     * gate that cannot fail is not a gate (AGENTS.md 5), and the real
     * implementation is unprivileged, so the host suite exercises both it and
     * its refusal. */
    int (*fd_quarantine)(int *method_out);
    int (*set_comm)(const char *comm);        /* 0, or -1 with errno */
    int (*driver_fd)(int *fd_out, struct dfr_su_transport_diag *diag);
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
 * transport_fix_allowed is a parameter for a stronger reason: it is the gate of
 * AGENTS.md 3.6.1, and the evidence behind it (a post-root record naming
 * transport_fix, for the current boot) lives where this layer cannot see it.
 * A default computed here would be a default computed without evidence. 0
 * means the child refuses at DFR_SU_STEP_TRANSPORT_FIX_GATED before any
 * existing-fd, supercall, or grant path can be reached.
 *
 * Returns 0 when the child was started and reaped normally, -1 otherwise; the
 * verdict is always in res->step, which the caller must read either way.
 */
int dfr_su_spawn(const struct dfr_su_ops *ops, const char *comm,
                 char *const argv[], const char *pinned_hex,
                 long timeout_ms, int kill_on_timeout, int transport_fix_allowed,
                 char *out, size_t out_cap, struct dfr_su_result *res);

/* Stable, greppable token for a result: the app logs it verbatim, and the
 * repository's rule is that a reader never has to guess what a verdict meant. */
void dfr_su_status_token(const struct dfr_su_result *res, char *buf, size_t cap);

#endif /* DFR_SU_CORE_H */
