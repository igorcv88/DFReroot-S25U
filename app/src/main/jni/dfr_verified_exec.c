#define _GNU_SOURCE

#include "dfr_verified_exec_core.h"

#include <stdio.h>
#include <string.h>

#define DFR_EXEC_USAGE 64
#define DFR_EXEC_DIGEST_MISMATCH 65
#define DFR_EXEC_FAILURE 66

extern char **environ;

/*
 * Host-side harness for dfr_verified_execveat().
 *
 * This is NOT how the device obtains root any more, and it is deliberately no
 * longer packaged into the APK: a process at u:r:system_server:s0 - which is
 * every component of this app, because the manifest sets
 * android:process="system" - cannot execve a file under /data. That was proven
 * physically for both apk_data_file and system_data_file (see
 * docs/S25U_ZZIC_COMPATIBILITY.md, "The exec proof came back negative"), so
 * shipping this as an executable would ship 439 KB that cannot run.
 *
 * The core it wraps is still load-bearing: the transport calls it inside a
 * forked child that has already been granted root. Keeping this main() is what
 * makes that core testable with no device, which is the only reason it exists.
 */
int main(int argc, char **argv)
{
    int err = 0;
    char found[65];
    int rc;

    if (argc < 4 || strlen(argv[1]) != 64) {
        fprintf(stderr, "DFR_VERIFIED_EXEC_USAGE\n");
        return DFR_EXEC_USAGE;
    }

    /* argv[2] intentionally becomes argv[0] of the target, matching a direct
     * exec of that path. */
    rc = dfr_verified_execveat(argv[2], argv[1], &argv[2], environ, &err, found);
    switch (rc) {
    case DFR_VEXEC_ERR_OPEN:
        fprintf(stderr, "DFR_VERIFIED_EXEC_OPEN errno=%d\n", err);
        return DFR_EXEC_FAILURE;
    case DFR_VEXEC_ERR_HASH:
        fprintf(stderr, "DFR_VERIFIED_EXEC_HASH errno=%d\n", err);
        return DFR_EXEC_FAILURE;
    case DFR_VEXEC_ERR_DIGEST:
        fprintf(stderr, "DFR_VERIFIED_EXEC_DIGEST_MISMATCH found=%s\n", found);
        return DFR_EXEC_DIGEST_MISMATCH;
    case DFR_VEXEC_ERR_REWIND:
        fprintf(stderr, "DFR_VERIFIED_EXEC_REWIND errno=%d\n", err);
        return DFR_EXEC_FAILURE;
    default:
        fprintf(stderr, "DFR_VERIFIED_EXEC_EXECVEAT errno=%d\n", err);
        return DFR_EXEC_FAILURE;
    }
}
