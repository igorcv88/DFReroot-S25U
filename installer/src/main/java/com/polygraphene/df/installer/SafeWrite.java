package com.polygraphene.df.installer;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * Transactional replacement of /data/system/packages.xml, and the transactional
 * backup that has to exist before it.
 *
 * <h3>Why this class exists</h3>
 *
 * The v2.0.2-zzic physical run on SM-S938B (S938BXXUCZZIC) exposed two real
 * defects in the previous inline implementation:
 *
 * <ol>
 *   <li><b>Metadata was inferred from the wrong file.</b> The old writeBack()
 *       created the backup with {@code File.copyTo} and then read the desired
 *       uid/gid/mode back out of <em>the backup it had just created</em>. A
 *       freshly created file in a root-run process is {@code root:root 0644},
 *       so those were the values reapplied to the final packages.xml. The
 *       device's real packages.xml is {@code system:system 0660}
 *       {@code u:object_r:system_data_file:s0}, and after the rename swap it
 *       came out {@code root:root 0644}. The only trustworthy source of the
 *       metadata is the original file, stat'd BEFORE anything is written.</li>
 *   <li><b>A zero-byte backup was accepted.</b> The old code only asked
 *       {@code bak.exists()} and logged "backup already exists, keeping". The
 *       run produced a 0-byte {@code packages.xml.bak-df-installer}, which
 *       makes the rollback path worse than having no backup at all: it looks
 *       like a safety net and restores nothing. A backup is now created
 *       atomically and verified by size AND digest before the original may be
 *       touched, and an existing backup that is empty, truncated or unparsable
 *       is a hard failure rather than a reassuring log line.</li>
 * </ol>
 *
 * <h3>Why it is pure Java against an interface</h3>
 *
 * Everything here is decisions: which metadata is authoritative, what makes a
 * backup valid, when to roll back. None of that needs Android, and all of it
 * needs tests. {@link FileOps} is the only thing that touches the filesystem,
 * so the host suite (tools/tests/SafeWriteTest.java) drives the exact code the
 * device runs against an in-memory filesystem, including the EPERM-then-rename
 * path that no unit test could otherwise reach.
 */
public final class SafeWrite {

    private SafeWrite() { }

    public static final String BACKUP_SUFFIX = ".bak-df-installer";
    public static final String BACKUP_TMP_SUFFIX = ".bak-df-installer.tmp";
    public static final String NEW_SUFFIX = ".new-df-installer";
    public static final String ROLLBACK_SUFFIX = ".rollback-df-installer";

    /** Ownership, permission bits, SELinux label and size of one file. */
    public static final class Meta {
        public final int uid;
        public final int gid;
        /** Permission bits only, masked to 07777 by the implementation. */
        public final int mode;
        public final long size;
        /** SELinux label, or null when this process could not read one. */
        public final String context;

        public Meta(int uid, int gid, int mode, long size, String context) {
            this.uid = uid;
            this.gid = gid;
            this.mode = mode;
            this.size = size;
            this.context = context;
        }

        @Override public String toString() {
            return "uid=" + uid + " gid=" + gid
                + " mode=0" + Integer.toOctalString(mode)
                + " size=" + size
                + " context=" + (context == null ? "UNKNOWN" : context);
        }
    }

    /** The only filesystem surface. Implemented on Android by AndroidFileOps. */
    public interface FileOps {
        boolean exists(String path);
        Meta stat(String path) throws IOException;
        byte[] read(String path) throws IOException;
        /** Create/truncate, write every byte, then fsync the file descriptor. */
        void writeAndSync(String path, byte[] data) throws IOException;
        void chmod(String path, int mode) throws IOException;
        void chown(String path, int uid, int gid) throws IOException;
        /** rename(2): must be atomic within the filesystem. */
        void rename(String from, String to) throws IOException;
        /** Best-effort unlink; never throws. */
        void deleteQuietly(String path);
        /** Reset the SELinux label to the policy default. False if unavailable. */
        boolean restorecon(String path);
        /** Force an explicit SELinux label. False if unavailable. */
        boolean setContext(String path, String context);
        /** True if `image` parses as a structurally plausible packages.xml. */
        boolean parses(byte[] image);
    }

    /** Raised for every fail-closed refusal in here, so callers can tell them apart. */
    public static class SafeWriteException extends RuntimeException {
        public SafeWriteException(String message) { super(message); }
        public SafeWriteException(String message, Throwable cause) { super(message, cause); }
    }

    public static String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(data);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : d) sb.append(Character.forDigit((b >> 4) & 0xf, 16))
                               .append(Character.forDigit(b & 0xf, 16));
            return sb.toString();
        } catch (Exception e) {
            throw new SafeWriteException("SHA-256 unavailable: " + e, e);
        }
    }

    /**
     * Replace {@code xmlPath} with {@code patched}, preserving the original
     * file's uid/gid/mode/SELinux label exactly, after a verified backup exists.
     *
     * <p>Order is load-bearing:
     * <pre>
     *   stat+read the ORIGINAL   (the only source of truth for metadata)
     *     -> transactional backup, verified by size and digest
     *       -> direct write, else write-new + rename(2) swap
     *         -> reapply the ORIGINAL metadata
     *           -> re-stat and verify; any divergence rolls back and throws
     * </pre>
     *
     * @throws SafeWriteException on any refusal. When it is thrown after the
     *         file was already replaced, the rollback has been attempted and
     *         its outcome is in {@code log} and in the message.
     */
    public static void writeBack(FileOps ops, String xmlPath, byte[] patched,
                                 StringBuilder log) {
        // ---- 0. ground truth, captured before anything is written ----------
        Meta orig;
        byte[] origBytes;
        try {
            orig = ops.stat(xmlPath);
            origBytes = ops.read(xmlPath);
        } catch (IOException e) {
            throw new SafeWriteException(
                "cannot stat/read " + xmlPath + " before writing: " + e, e);
        }
        if (origBytes.length == 0) {
            throw new SafeWriteException(xmlPath + " is empty; refusing to back up "
                + "and replace a file that already has no content");
        }
        if (orig.size != origBytes.length) {
            // Someone else is writing it right now. Pinning metadata from a
            // moving target is exactly the class of bug this rewrite fixes.
            throw new SafeWriteException("size changed while reading " + xmlPath
                + " (stat=" + orig.size + " read=" + origBytes.length + ")");
        }
        String origSha = sha256(origBytes);
        log.append("[DFR][INSTALLER] ORIGINAL_METADATA ").append(orig).append('\n');
        log.append("[DFR][INSTALLER] ORIGINAL_SHA256=").append(origSha).append('\n');

        // ---- 1. a verified backup must exist before the original moves -----
        ensureBackup(ops, xmlPath, origBytes, origSha, orig, log);

        // ---- 2. replace the content ----------------------------------------
        String patchedSha = sha256(patched);
        boolean done = false;
        try {
            ops.writeAndSync(xmlPath, patched);
            done = true;
            log.append("[+] direct write ok\n");
        } catch (IOException e) {
            // EPERM here is expected on this firmware and is not an error yet:
            // overwriting the existing inode is denied while creating a new file
            // in the same directory is allowed, so rename(2) is the real path.
            log.append("[!] direct write failed: ").append(e).append('\n');
        }
        if (!done) {
            String newPath = xmlPath + NEW_SUFFIX;
            ops.deleteQuietly(newPath);
            try {
                ops.writeAndSync(newPath, patched);
                byte[] back = ops.read(newPath);
                if (!sha256(back).equals(patchedSha)) {
                    ops.deleteQuietly(newPath);
                    throw new SafeWriteException("staged " + newPath
                        + " does not read back byte-identical; refusing to swap it in");
                }
            } catch (IOException e) {
                ops.deleteQuietly(newPath);
                throw new SafeWriteException("cannot stage " + newPath + ": " + e, e);
            }
            // The swapped-in inode carries ITS OWN metadata, so the original's
            // uid/gid/mode/label go on before the rename, not after.
            applyMeta(ops, newPath, orig, log);
            try {
                ops.rename(newPath, xmlPath);
            } catch (IOException e) {
                log.append("[x] rename swap failed: ").append(e).append('\n');
                log.append("    patched image kept at ").append(newPath).append('\n');
                log.append("    the original is intact, and a verified backup is at ")
                   .append(xmlPath).append(BACKUP_SUFFIX).append('\n');
                throw new SafeWriteException("rename swap failed: " + e, e);
            }
            log.append("[+] rename swap ok\n");
        }

        // ---- 3. reassert and VERIFY the original metadata -------------------
        applyMeta(ops, xmlPath, orig, log);
        List<String> problems = verifyAgainst(ops, xmlPath, orig, patchedSha, log);
        if (!problems.isEmpty()) {
            String why = String.join("; ", problems);
            log.append("[x] POST_WRITE_VERIFY=FAIL ").append(why).append('\n');
            rollback(ops, xmlPath, origBytes, origSha, orig, log);
            throw new SafeWriteException(
                "packages.xml did not come out as it went in (" + why
                + "); rolled back, see the log");
        }
        log.append("[DFR][INSTALLER] POST_WRITE_VERIFY=PASS ").append(orig).append('\n');
        log.append("[+] wrote ").append(patched.length)
           .append(" bytes (TEXT xml; PMS re-reads either format)\n");
    }

    /**
     * Guarantee a byte-exact, parsable backup of the original.
     *
     * <p>A backup that already exists is NEVER overwritten - it is the pristine
     * pre-injection image and a second run must not replace it with an already
     * injected one - but it is validated, and an invalid one is fatal.
     */
    private static void ensureBackup(FileOps ops, String xmlPath, byte[] origBytes,
                                     String origSha, Meta orig, StringBuilder log) {
        String bak = xmlPath + BACKUP_SUFFIX;
        if (ops.exists(bak)) {
            byte[] existing;
            Meta bm;
            try {
                bm = ops.stat(bak);
                existing = ops.read(bak);
            } catch (IOException e) {
                throw new SafeWriteException("a backup exists at " + bak
                    + " but cannot be read (" + e + "); refusing to modify "
                    + xmlPath + " with no usable rollback", e);
            }
            if (existing.length == 0) {
                throw new SafeWriteException("the existing backup " + bak
                    + " is ZERO BYTES. It restores nothing, so continuing would "
                    + "leave no way back. Move or delete it after checking you "
                    + "have a good copy of packages.xml, then re-run.");
            }
            if (bm.size != existing.length) {
                throw new SafeWriteException("the existing backup " + bak
                    + " is truncated or still being written (stat=" + bm.size
                    + " read=" + existing.length + ")");
            }
            if (!ops.parses(existing)) {
                throw new SafeWriteException("the existing backup " + bak
                    + " does not parse as packages.xml; it cannot be restored");
            }
            log.append("[DFR][INSTALLER] BACKUP_PRESERVED=").append(bak)
               .append(" size=").append(existing.length)
               .append(" sha256=").append(sha256(existing)).append('\n');
            log.append("[DFR][INSTALLER] BACKUP_VALID=PASS (pristine pre-injection image kept)\n");
            return;
        }

        // Create it transactionally: a backup only becomes visible under its
        // real name once its bytes have been verified, so an interrupted run
        // leaves either no backup or a complete one, never a half of one.
        if (!ops.parses(origBytes)) {
            throw new SafeWriteException(xmlPath
                + " does not parse; refusing to take it as a backup baseline");
        }
        String tmp = xmlPath + BACKUP_TMP_SUFFIX;
        ops.deleteQuietly(tmp);
        try {
            ops.writeAndSync(tmp, origBytes);
            byte[] back = ops.read(tmp);
            if (back.length != origBytes.length || !sha256(back).equals(origSha)) {
                ops.deleteQuietly(tmp);
                throw new SafeWriteException("backup staged at " + tmp
                    + " does not read back byte-identical to " + xmlPath);
            }
        } catch (IOException e) {
            ops.deleteQuietly(tmp);
            throw new SafeWriteException("cannot stage the backup at " + tmp + ": " + e, e);
        }
        applyMeta(ops, tmp, orig, log);
        try {
            ops.rename(tmp, bak);
        } catch (IOException e) {
            ops.deleteQuietly(tmp);
            throw new SafeWriteException("cannot put the backup in place at "
                + bak + ": " + e, e);
        }
        try {
            Meta after = ops.stat(bak);
            if (after.size != origBytes.length) {
                throw new SafeWriteException("backup " + bak + " is " + after.size
                    + " bytes, expected " + origBytes.length);
            }
        } catch (IOException e) {
            throw new SafeWriteException("cannot stat the backup " + bak
                + " after creating it: " + e, e);
        }
        log.append("[DFR][INSTALLER] BACKUP_CREATED=").append(bak)
           .append(" size=").append(origBytes.length)
           .append(" sha256=").append(origSha).append('\n');
        log.append("[DFR][INSTALLER] BACKUP_VALID=PASS (verified byte-for-byte)\n");
    }

    /** chmod + chown + restore the original SELinux label, best-effort per step. */
    private static void applyMeta(FileOps ops, String path, Meta want, StringBuilder log) {
        try {
            ops.chmod(path, want.mode);
        } catch (IOException e) {
            log.append("[!] chmod ").append(path).append(": ").append(e).append('\n');
        }
        try {
            ops.chown(path, want.uid, want.gid);
        } catch (IOException e) {
            log.append("[!] chown ").append(path).append(": ").append(e).append('\n');
        }
        ops.restorecon(path);
        // restorecon applies the POLICY default, which is not necessarily the
        // label the file actually had. The original's label is what must come
        // back, so set it explicitly when the two differ.
        if (want.context != null) {
            String now = currentContext(ops, path);
            if (now == null || !now.equals(want.context)) {
                ops.setContext(path, want.context);
            }
        }
    }

    private static String currentContext(FileOps ops, String path) {
        try {
            return ops.stat(path).context;
        } catch (IOException e) {
            return null;
        }
    }

    /** Every way the written file can differ from what was promised. */
    private static List<String> verifyAgainst(FileOps ops, String xmlPath, Meta orig,
                                              String patchedSha, StringBuilder log) {
        List<String> problems = new ArrayList<String>();
        Meta post;
        byte[] postBytes;
        try {
            post = ops.stat(xmlPath);
            postBytes = ops.read(xmlPath);
        } catch (IOException e) {
            problems.add("cannot re-stat/read " + xmlPath + ": " + e);
            return problems;
        }
        if (post.uid != orig.uid) problems.add("uid=" + post.uid + " want " + orig.uid);
        if (post.gid != orig.gid) problems.add("gid=" + post.gid + " want " + orig.gid);
        if (post.mode != orig.mode) {
            problems.add("mode=0" + Integer.toOctalString(post.mode)
                + " want 0" + Integer.toOctalString(orig.mode));
        }
        if (orig.context == null) {
            // Nothing was known to restore. Say so rather than calling it a pass.
            log.append("[DFR][INSTALLER] SELINUX_VERIFY=UNKNOWN "
                + "(the original label could not be read; nothing to compare)\n");
        } else if (post.context == null) {
            // The original HAD a label, so failing to read the new one means the
            // one restoration that mattered cannot be confirmed.
            problems.add("SELinux label unreadable after the write, "
                + "original was " + orig.context);
        } else if (!post.context.equals(orig.context)) {
            problems.add("context=" + post.context + " want " + orig.context);
        } else {
            log.append("[DFR][INSTALLER] SELINUX_VERIFY=PASS ").append(post.context).append('\n');
        }
        String postSha = sha256(postBytes);
        if (!postSha.equals(patchedSha)) {
            problems.add("content sha256=" + postSha + " want " + patchedSha);
        }
        return problems;
    }

    /** Put the original bytes and metadata back. Never throws; reports in `log`. */
    private static void rollback(FileOps ops, String xmlPath, byte[] origBytes,
                                 String origSha, Meta orig, StringBuilder log) {
        log.append("[DFR][INSTALLER] ROLLBACK=ATTEMPT\n");
        boolean restored = false;
        try {
            ops.writeAndSync(xmlPath, origBytes);
            restored = true;
        } catch (IOException e) {
            log.append("[!] rollback direct write failed: ").append(e).append('\n');
        }
        if (!restored) {
            String tmp = xmlPath + ROLLBACK_SUFFIX;
            ops.deleteQuietly(tmp);
            try {
                ops.writeAndSync(tmp, origBytes);
                applyMeta(ops, tmp, orig, log);
                ops.rename(tmp, xmlPath);
                restored = true;
            } catch (IOException e) {
                ops.deleteQuietly(tmp);
                log.append("[!] rollback rename swap failed: ").append(e).append('\n');
            }
        }
        if (!restored) {
            log.append("[DFR][INSTALLER] ROLLBACK=FAILED. Restore by hand from ")
               .append(xmlPath).append(BACKUP_SUFFIX)
               .append(" BEFORE rebooting.\n");
            return;
        }
        applyMeta(ops, xmlPath, orig, log);
        try {
            byte[] now = ops.read(xmlPath);
            if (sha256(now).equals(origSha)) {
                log.append("[DFR][INSTALLER] ROLLBACK=PASS (original restored byte-for-byte)\n");
            } else {
                log.append("[DFR][INSTALLER] ROLLBACK=FAILED (content differs). Restore by hand from ")
                   .append(xmlPath).append(BACKUP_SUFFIX).append(" BEFORE rebooting.\n");
            }
        } catch (IOException e) {
            log.append("[DFR][INSTALLER] ROLLBACK=UNVERIFIED (").append(e)
               .append("). Check ").append(xmlPath).append(" by hand BEFORE rebooting.\n");
        }
    }

    /**
     * Read-only report on the backup, for Gate H. Returns a PASS/FAIL/ABSENT
     * line; it never creates or repairs anything.
     */
    public static String describeBackup(FileOps ops, String xmlPath) {
        String bak = xmlPath + BACKUP_SUFFIX;
        if (!ops.exists(bak)) {
            return "BACKUP_PRESENT=ABSENT path=" + bak + " (created on first write)";
        }
        try {
            Meta m = ops.stat(bak);
            byte[] b = ops.read(bak);
            if (b.length == 0) {
                return "BACKUP_PRESENT=PASS BACKUP_VALID=FAIL path=" + bak
                    + " size=0 (zero-byte backup: it restores nothing; "
                    + "the next write will refuse until it is dealt with)";
            }
            if (m.size != b.length) {
                return "BACKUP_PRESENT=PASS BACKUP_VALID=FAIL path=" + bak
                    + " stat_size=" + m.size + " read_size=" + b.length + " (truncated)";
            }
            if (!ops.parses(b)) {
                return "BACKUP_PRESENT=PASS BACKUP_VALID=FAIL path=" + bak
                    + " size=" + b.length + " (does not parse as packages.xml)";
            }
            return "BACKUP_PRESENT=PASS BACKUP_VALID=PASS path=" + bak
                + " size=" + b.length + " sha256=" + sha256(b) + " " + m;
        } catch (IOException e) {
            return "BACKUP_PRESENT=PASS BACKUP_VALID=FAIL path=" + bak
                + " (unreadable: " + e + ")";
        }
    }
}
