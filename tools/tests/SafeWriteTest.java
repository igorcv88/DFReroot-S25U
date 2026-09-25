import com.polygraphene.df.installer.SafeWrite;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Host regression suite for the DFInstaller packages.xml write path.
 *
 * Every case below is a situation the v2.0.2-zzic physical run either produced
 * or could have produced on SM-S938B / S938BXXUCZZIC. The filesystem is a
 * LinkedHashMap, so the EPERM-on-direct-write path - the one that actually ran
 * on the device, and the one that lost the file's metadata - is reachable in a
 * test instead of only on hardware.
 *
 *   javac -d out installer/src/main/java/com/polygraphene/df/installer/SafeWrite.java \
 *         tools/tests/SafeWriteTest.java && java -cp out SafeWriteTest
 *
 * See tools/tests/run_installer_tests.sh.
 */
public class SafeWriteTest {

    // ---------------------------------------------------------------- harness
    static int total = 0;
    static int failed = 0;

    static void check(boolean cond, String fmt, Object... args) {
        total++;
        String msg = String.format(fmt, args);
        if (cond) {
            System.out.println("  ok   - " + msg);
        } else {
            failed++;
            System.out.println("  FAIL - " + msg);
        }
    }

    /** In-memory filesystem with injectable denials, modelled on the device. */
    static class FakeFs implements SafeWrite.FileOps {
        static class Node {
            byte[] data;
            int uid, gid, mode;
            String context;
            Node(byte[] d, int uid, int gid, int mode, String ctx) {
                this.data = d; this.uid = uid; this.gid = gid;
                this.mode = mode; this.context = ctx;
            }
        }
        final Map<String, Node> files = new LinkedHashMap<String, Node>();
        /** Paths whose direct overwrite is denied (the device's EPERM). */
        final List<String> denyOverwrite = new ArrayList<String>();
        /** Paths that may not be created at all. */
        final List<String> denyCreate = new ArrayList<String>();
        final List<String> denyRename = new ArrayList<String>();
        /** Set to make stat() report a size that disagrees with the content. */
        String lyingSizePath = null;
        long lyingSize = 0;
        /** uid/gid/mode a *newly created* file gets: root:root 0644, as on device. */
        int newUid = 0, newGid = 0, newMode = 0644;
        String defaultContext = "u:object_r:system_data_file:s0";
        boolean selinuxAvailable = true;
        final List<String> log = new ArrayList<String>();

        public boolean exists(String path) { return files.containsKey(path); }

        public SafeWrite.Meta stat(String path) throws IOException {
            Node n = files.get(path);
            if (n == null) throw new IOException("ENOENT " + path);
            long size = path.equals(lyingSizePath) ? lyingSize : n.data.length;
            return new SafeWrite.Meta(n.uid, n.gid, n.mode, size,
                selinuxAvailable ? n.context : null);
        }

        public byte[] read(String path) throws IOException {
            Node n = files.get(path);
            if (n == null) throw new IOException("ENOENT " + path);
            return n.data.clone();
        }

        public void writeAndSync(String path, byte[] data) throws IOException {
            if (files.containsKey(path) && denyOverwrite.contains(path))
                throw new IOException("EPERM overwrite " + path);
            if (!files.containsKey(path) && denyCreate.contains(path))
                throw new IOException("EACCES create " + path);
            log.add("write " + path);
            Node n = files.get(path);
            if (n == null) {
                files.put(path, new Node(data.clone(), newUid, newGid, newMode, defaultContext));
            } else {
                n.data = data.clone();
            }
        }

        public void chmod(String path, int mode) throws IOException {
            Node n = files.get(path);
            if (n == null) throw new IOException("ENOENT " + path);
            n.mode = mode;
        }

        public void chown(String path, int uid, int gid) throws IOException {
            Node n = files.get(path);
            if (n == null) throw new IOException("ENOENT " + path);
            n.uid = uid; n.gid = gid;
        }

        public void rename(String from, String to) throws IOException {
            if (denyRename.contains(from)) throw new IOException("EPERM rename " + from);
            Node n = files.remove(from);
            if (n == null) throw new IOException("ENOENT " + from);
            log.add("rename " + from + " -> " + to);
            files.put(to, n);
        }

        public void deleteQuietly(String path) { files.remove(path); }

        public boolean restorecon(String path) {
            Node n = files.get(path);
            if (n == null || !selinuxAvailable) return false;
            n.context = defaultContext;
            return true;
        }

        public boolean setContext(String path, String context) {
            Node n = files.get(path);
            if (n == null || !selinuxAvailable) return false;
            n.context = context;
            return true;
        }

        public boolean parses(byte[] image) {
            String s = new String(image, StandardCharsets.UTF_8);
            return s.contains("<packages>") && s.contains("</packages>");
        }
    }

    // ------------------------------------------------------------- test data
    static final String XML = "/data/system/packages.xml";
    static final String BAK = XML + SafeWrite.BACKUP_SUFFIX;

    static byte[] pristine() {
        return ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
            + "<packages>\n"
            + "  <shared-user name=\"android.uid.system\" userId=\"1000\">\n"
            + "    <sigs count=\"1\"><cert index=\"0\" key=\"3082dead\" /></sigs>\n"
            + "  </shared-user>\n"
            + "</packages>\n").getBytes(StandardCharsets.UTF_8);
    }

    static byte[] injected() {
        return ("<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n"
            + "<packages>\n"
            + "  <shared-user name=\"android.uid.system\" userId=\"1000\">\n"
            + "    <sigs count=\"1\"><cert index=\"0\" key=\"3082dead\" />\n"
            + "      <pastSigs count=\"3\"><cert index=\"0\" key=\"3082beef\" flags=\"2\" />"
            + "</pastSigs></sigs>\n"
            + "  </shared-user>\n"
            + "</packages>\n").getBytes(StandardCharsets.UTF_8);
    }

    /**
     * The device's real state: packages.xml owned system:system, mode 0660,
     * labelled u:object_r:system_data_file:s0.
     */
    static FakeFs zzicFs() {
        FakeFs fs = new FakeFs();
        fs.files.put(XML, new FakeFs.Node(pristine(), 1000, 1000, 0660,
            "u:object_r:system_data_file:s0"));
        return fs;
    }

    static String run(FakeFs fs, byte[] patched, StringBuilder log) {
        try {
            SafeWrite.writeBack(fs, XML, patched, log);
            return null;
        } catch (RuntimeException e) {
            return e.getMessage() == null ? e.toString() : e.getMessage();
        }
    }

    // ----------------------------------------------------------------- cases

    /** [1] The device's own metadata survives the happy path. */
    static void testMetadataPreservedDirect() {
        System.out.println("[1] direct write preserves 1000:1000 0660");
        FakeFs fs = zzicFs();
        StringBuilder log = new StringBuilder();
        String err = run(fs, injected(), log);
        FakeFs.Node f = fs.files.get(XML);
        check(err == null, "no refusal (%s)", String.valueOf(err));
        check(f.uid == 1000 && f.gid == 1000, "uid:gid = %d:%d (want 1000:1000)", f.uid, f.gid);
        check(f.mode == 0660, "mode = 0%s (want 0660)", Integer.toOctalString(f.mode));
        check("u:object_r:system_data_file:s0".equals(f.context),
            "context = %s", f.context);
        check(new String(f.data, StandardCharsets.UTF_8).contains("pastSigs"),
            "content is the patched image");
        check(log.toString().contains("POST_WRITE_VERIFY=PASS"), "verify line emitted");
    }

    /**
     * [2] THE v2.0.2 BUG. Direct overwrite is denied, so the rename swap runs;
     * the new inode is created root:root 0644, and the old code took ITS
     * metadata (via the backup) as the target. The final file must still be
     * 1000:1000 0660 with the original label.
     */
    static void testMetadataPreservedRenameSwap() {
        System.out.println("[2] EPERM direct write + rename swap preserves metadata");
        FakeFs fs = zzicFs();
        fs.denyOverwrite.add(XML);
        StringBuilder log = new StringBuilder();
        String err = run(fs, injected(), log);
        FakeFs.Node f = fs.files.get(XML);
        check(err == null, "no refusal (%s)", String.valueOf(err));
        check(log.toString().contains("rename swap ok"), "the rename path was taken");
        check(f.uid == 1000 && f.gid == 1000,
            "uid:gid = %d:%d (want 1000:1000, NOT the new inode's 0:0)", f.uid, f.gid);
        check(f.mode == 0660,
            "mode = 0%s (want 0660, NOT the new inode's 0644)", Integer.toOctalString(f.mode));
        check("u:object_r:system_data_file:s0".equals(f.context), "context = %s", f.context);
        check(!fs.files.containsKey(XML + SafeWrite.NEW_SUFFIX), "no staging file left behind");
    }

    /** [3] No backup yet: one is created, byte-exact, with the original's metadata. */
    static void testBackupCreated() {
        System.out.println("[3] missing backup is created with the right bytes");
        FakeFs fs = zzicFs();
        byte[] before = fs.files.get(XML).data.clone();
        StringBuilder log = new StringBuilder();
        String err = run(fs, injected(), log);
        check(err == null, "no refusal (%s)", String.valueOf(err));
        FakeFs.Node b = fs.files.get(BAK);
        check(b != null, "backup exists at %s", BAK);
        check(b != null && java.util.Arrays.equals(b.data, before),
            "backup is byte-identical to the pristine original");
        check(b != null && b.uid == 1000 && b.gid == 1000 && b.mode == 0660,
            "backup carries the original metadata (%s)",
            b == null ? "absent" : b.uid + ":" + b.gid + " 0" + Integer.toOctalString(b.mode));
        check(log.toString().contains("BACKUP_CREATED"), "BACKUP_CREATED line emitted");
        check(!fs.files.containsKey(XML + SafeWrite.BACKUP_TMP_SUFFIX),
            "no staging backup left behind");
    }

    /** [4] A valid existing backup is the pristine image and must be kept. */
    static void testBackupPreserved() {
        System.out.println("[4] valid existing backup is preserved, never overwritten");
        FakeFs fs = zzicFs();
        byte[] pristineBak = pristine();
        fs.files.put(BAK, new FakeFs.Node(pristineBak, 1000, 1000, 0660,
            "u:object_r:system_data_file:s0"));
        // second run: packages.xml is ALREADY injected, so overwriting the
        // backup would replace the pristine image with an injected one.
        fs.files.get(XML).data = injected();
        StringBuilder log = new StringBuilder();
        String err = run(fs, injected(), log);
        check(err == null, "no refusal (%s)", String.valueOf(err));
        check(java.util.Arrays.equals(fs.files.get(BAK).data, pristineBak),
            "backup still holds the PRISTINE image, not the injected one");
        check(log.toString().contains("BACKUP_PRESERVED"), "BACKUP_PRESERVED line emitted");
    }

    /** [5] The exact artefact the physical run produced: a 0-byte backup. */
    static void testZeroByteBackupIsFatal() {
        System.out.println("[5] zero-byte backup is a hard failure");
        FakeFs fs = zzicFs();
        fs.files.put(BAK, new FakeFs.Node(new byte[0], 0, 0, 0644, "u:object_r:system_data_file:s0"));
        byte[] before = fs.files.get(XML).data.clone();
        StringBuilder log = new StringBuilder();
        String err = run(fs, injected(), log);
        check(err != null && err.contains("ZERO BYTES"),
            "refused with a zero-byte message (%s)", String.valueOf(err));
        check(java.util.Arrays.equals(fs.files.get(XML).data, before),
            "packages.xml was NOT touched");
        check(fs.log.isEmpty(), "nothing was written at all (%s)", fs.log);
    }

    /** [6] A backup whose stat size disagrees with its content is truncated. */
    static void testTruncatedBackupIsFatal() {
        System.out.println("[6] truncated backup is a hard failure");
        FakeFs fs = zzicFs();
        byte[] half = java.util.Arrays.copyOf(pristine(), 40);
        fs.files.put(BAK, new FakeFs.Node(half, 1000, 1000, 0660, "u:object_r:system_data_file:s0"));
        fs.lyingSizePath = BAK;
        fs.lyingSize = pristine().length;
        byte[] before = fs.files.get(XML).data.clone();
        String err = run(fs, injected(), new StringBuilder());
        check(err != null && err.contains("truncated"),
            "refused as truncated (%s)", String.valueOf(err));
        check(java.util.Arrays.equals(fs.files.get(XML).data, before),
            "packages.xml was NOT touched");
    }

    /** [7] A backup that is intact in size but is not a packages.xml. */
    static void testCorruptBackupIsFatal() {
        System.out.println("[7] unparsable backup is a hard failure");
        FakeFs fs = zzicFs();
        fs.files.put(BAK, new FakeFs.Node("not xml at all".getBytes(StandardCharsets.UTF_8),
            1000, 1000, 0660, "u:object_r:system_data_file:s0"));
        byte[] before = fs.files.get(XML).data.clone();
        String err = run(fs, injected(), new StringBuilder());
        check(err != null && err.contains("does not parse"),
            "refused as unparsable (%s)", String.valueOf(err));
        check(java.util.Arrays.equals(fs.files.get(XML).data, before),
            "packages.xml was NOT touched");
    }

    /** [8] If the backup cannot be created, nothing is modified. */
    static void testBackupCreationFailureBlocksWrite() {
        System.out.println("[8] a backup that cannot be staged blocks the write");
        FakeFs fs = zzicFs();
        fs.denyCreate.add(XML + SafeWrite.BACKUP_TMP_SUFFIX);
        byte[] before = fs.files.get(XML).data.clone();
        String err = run(fs, injected(), new StringBuilder());
        check(err != null && err.contains("cannot stage the backup"),
            "refused (%s)", String.valueOf(err));
        check(java.util.Arrays.equals(fs.files.get(XML).data, before),
            "packages.xml was NOT touched");
        check(!fs.files.containsKey(BAK), "no backup left behind");
    }

    /** [9] A rename swap that fails leaves the original intact and says so. */
    static void testRenameFailureLeavesOriginal() {
        System.out.println("[9] failed rename swap leaves the original intact");
        FakeFs fs = zzicFs();
        fs.denyOverwrite.add(XML);
        fs.denyRename.add(XML + SafeWrite.NEW_SUFFIX);
        byte[] before = fs.files.get(XML).data.clone();
        StringBuilder log = new StringBuilder();
        String err = run(fs, injected(), log);
        check(err != null && err.contains("rename swap failed"),
            "refused (%s)", String.valueOf(err));
        check(java.util.Arrays.equals(fs.files.get(XML).data, before),
            "packages.xml still holds the pristine bytes");
        check(fs.files.containsKey(BAK), "the verified backup was still created first");
    }

    /**
     * [10] Metadata that cannot be restored must roll back, not ship. Here
     * chown is impossible because the file vanished between write and verify;
     * the simpler and more realistic case is a chown that silently no-ops, so
     * the fake is told to keep the new inode's owner.
     */
    static void testVerifyFailureRollsBack() {
        System.out.println("[10] unrestorable metadata rolls back instead of shipping");
        FakeFs fs = new FakeFs() {
            @Override public void chown(String path, int uid, int gid) {
                // a kernel/policy that accepts the call and changes nothing
            }
        };
        fs.files.put(XML, new FakeFs.Node(pristine(), 1000, 1000, 0660,
            "u:object_r:system_data_file:s0"));
        fs.denyOverwrite.add(XML);   // force the rename swap onto a 0:0 inode
        StringBuilder log = new StringBuilder();
        String err = run(fs, injected(), log);
        check(err != null && err.contains("did not come out as it went in"),
            "refused (%s)", String.valueOf(err));
        check(log.toString().contains("ROLLBACK=PASS"),
            "rolled back and verified it (%s)", log.toString().contains("ROLLBACK=PASS"));
        check(new String(fs.files.get(XML).data, StandardCharsets.UTF_8).contains("<packages>")
                && !new String(fs.files.get(XML).data, StandardCharsets.UTF_8).contains("pastSigs"),
            "packages.xml holds the ORIGINAL content again");
    }

    /** [11] An empty packages.xml is never used as a backup baseline. */
    static void testEmptyOriginalRefused() {
        System.out.println("[11] empty packages.xml is refused as a baseline");
        FakeFs fs = new FakeFs();
        fs.files.put(XML, new FakeFs.Node(new byte[0], 1000, 1000, 0660,
            "u:object_r:system_data_file:s0"));
        String err = run(fs, injected(), new StringBuilder());
        check(err != null && err.contains("is empty"), "refused (%s)", String.valueOf(err));
        check(!fs.files.containsKey(BAK), "no backup of an empty file was made");
    }

    /** [12] Without SELinux the label cannot be restored OR verified: say so. */
    static void testSelinuxUnavailableIsNotAPass() {
        System.out.println("[12] unreadable SELinux label is UNKNOWN, not PASS");
        FakeFs fs = zzicFs();
        fs.selinuxAvailable = false;
        StringBuilder log = new StringBuilder();
        String err = run(fs, injected(), log);
        check(err == null, "the write still completes (%s)", String.valueOf(err));
        check(log.toString().contains("SELINUX_VERIFY=UNKNOWN"),
            "reported UNKNOWN rather than claiming a label was restored");
        check(!log.toString().contains("SELINUX_VERIFY=PASS"), "no false PASS");
    }

    /** [13] A label that comes back different from the original is a refusal. */
    static void testWrongLabelRollsBack() {
        System.out.println("[13] a changed SELinux label rolls back");
        FakeFs fs = new FakeFs() {
            @Override public boolean setContext(String path, String context) {
                return false;   // policy refuses an explicit relabel
            }
        };
        fs.files.put(XML, new FakeFs.Node(pristine(), 1000, 1000, 0660,
            "u:object_r:apex_module_data_file:s0"));   // non-default label
        fs.defaultContext = "u:object_r:system_data_file:s0";
        StringBuilder log = new StringBuilder();
        String err = run(fs, injected(), log);
        check(err != null && err.contains("context="), "refused on the label (%s)",
            String.valueOf(err));
        check(log.toString().contains("ROLLBACK"), "rollback was attempted");
    }

    /** [14] describeBackup reports what is really there, for Gate H. */
    static void testDescribeBackup() {
        System.out.println("[14] Gate H backup description");
        FakeFs fs = zzicFs();
        check(SafeWrite.describeBackup(fs, XML).contains("BACKUP_PRESENT=ABSENT"),
            "absent backup reported as ABSENT");
        fs.files.put(BAK, new FakeFs.Node(new byte[0], 0, 0, 0644, "u:object_r:system_data_file:s0"));
        String d = SafeWrite.describeBackup(fs, XML);
        check(d.contains("BACKUP_VALID=FAIL") && d.contains("size=0"),
            "zero-byte backup reported as FAIL (%s)", d);
        fs.files.put(BAK, new FakeFs.Node(pristine(), 1000, 1000, 0660,
            "u:object_r:system_data_file:s0"));
        d = SafeWrite.describeBackup(fs, XML);
        check(d.contains("BACKUP_VALID=PASS") && d.contains("sha256="),
            "good backup reported as PASS with a digest (%s)", d);
    }

    /** [15] The mode comparison must not be fooled by the file-type bits. */
    static void testModeMaskIsPermissionsOnly() {
        System.out.println("[15] mode comparison uses permission bits only");
        FakeFs fs = zzicFs();
        fs.files.get(XML).mode = 0660;
        fs.newMode = 0600;
        fs.denyOverwrite.add(XML);
        String err = run(fs, injected(), new StringBuilder());
        check(err == null, "no refusal (%s)", String.valueOf(err));
        check(fs.files.get(XML).mode == 0660, "mode restored to 0660 from a 0600 inode (0%s)",
            Integer.toOctalString(fs.files.get(XML).mode));
    }

    public static void main(String[] args) {
        System.out.println("DFInstaller SafeWrite regression suite\n");
        testMetadataPreservedDirect();
        testMetadataPreservedRenameSwap();
        testBackupCreated();
        testBackupPreserved();
        testZeroByteBackupIsFatal();
        testTruncatedBackupIsFatal();
        testCorruptBackupIsFatal();
        testBackupCreationFailureBlocksWrite();
        testRenameFailureLeavesOriginal();
        testVerifyFailureRollsBack();
        testEmptyOriginalRefused();
        testSelinuxUnavailableIsNotAPass();
        testWrongLabelRollsBack();
        testDescribeBackup();
        testModeMaskIsPermissionsOnly();
        System.out.printf("%n%d/%d checks passed, %d failed%n", total - failed, total, failed);
        System.exit(failed == 0 ? 0 : 1);
    }
}
