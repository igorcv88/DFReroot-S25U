/*
 * dfr_verified_exec_core.h - bind a digest to the bytes that actually run.
 *
 * Hashing a pathname and executing that pathname afterwards is two lookups of a
 * mutable name (AGENTS.md 3.5.1). /data/adb/ksud has held the root manager's own
 * build and the pinned daemon at different times on this device, so the window
 * is real. The core below opens the candidate ONCE, hashes that open file
 * description, rewinds it and hands the SAME descriptor to
 * execveat(AT_EMPTY_PATH): a replacement of the pathname after open(2) cannot
 * change the bytes that are launched.
 *
 * It lives apart from any caller because two of them need it and they cannot be
 * tested the same way: the standalone launcher is exercised on the host by
 * tools/tests/test_verified_exec.sh, while the JNI transport's copy runs inside
 * a forked child that has just been granted root on the device.
 */
#ifndef DFR_VERIFIED_EXEC_CORE_H
#define DFR_VERIFIED_EXEC_CORE_H

/* Failure reasons. Kept distinct because they mean different things to the
 * caller: a digest mismatch is the gate doing its job, everything else is a
 * fault in reaching the file at all. */
#define DFR_VEXEC_ERR_OPEN     (-1)
#define DFR_VEXEC_ERR_HASH     (-2)
#define DFR_VEXEC_ERR_DIGEST   (-3)
#define DFR_VEXEC_ERR_REWIND   (-4)
#define DFR_VEXEC_ERR_EXECVEAT (-5)

/*
 * On success this does not return. On failure it returns one of the codes
 * above, writes errno (0 for a digest mismatch) to *err_out when non-NULL, and
 * copies the digest actually found into found_hex when non-NULL.
 *
 * Async-signal-safe: no allocation, so it is callable between fork() and exec().
 */
int dfr_verified_execveat(const char *path, const char *expected_hex,
                          char *const argv[], char *const envp[],
                          int *err_out, char found_hex[65]);

#endif /* DFR_VERIFIED_EXEC_CORE_H */
