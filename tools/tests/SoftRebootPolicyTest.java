import com.polygraphene.df.reroot.AutoRootPolicy;
import com.polygraphene.df.reroot.SoftRebootPolicy;
import com.polygraphene.df.reroot.SoftRebootDispatchGuard;
import com.polygraphene.df.reroot.SoftRebootPolicy.Candidate;
import com.polygraphene.df.reroot.SoftRebootPolicy.Decision;
import com.polygraphene.df.reroot.SoftRebootPolicy.Inputs;

/**
 * Host tests for the "Apply Modules (Soft Reboot)" precheck.
 *
 * Every element gets its negative case, because a gate that cannot fail is not a
 * gate (AGENTS.md section 5). None of these states can be produced on demand on a
 * device: a notification minted in a previous boot, a post-root record from
 * another boot, a lock left by a dispatch that already happened, a /data/adb/ksud
 * the root manager replaced with its own build.
 */
public class SoftRebootPolicyTest {

    static final String BOOT = "2e447aaf-dc02-4cb7-851c-d79f73f94282";
    static final String OTHER_BOOT = "a9ddee12-4011-481c-a0b5-9ed50c880301";
    static final String PINNED =
            "d0cb516da0047b1b918f84adf8ce7a389c6285de9282cd6301514a40849af7fc";
    static final String MANAGER =
            "99aaa607e9c9da6a0e898366ecf0a14dd67224ea726d952d1ce575e62d3b5c41";
    static final String STAGED = "/data/system/dfreroot-ksud";
    static final String ADB = "/data/adb/ksud";

    static int pass = 0;
    static int fail = 0;

    static String postRoot(String bootId) {
        return "state=POST_ROOT_COMPLETE\n"
                + "boot_id=" + bootId + "\n"
                + "ksu_version=32601\n"
                + "uapi_version=2\n"
                + "runtime_mode=late-load\n"
                + "selinux=1\n";
    }

    /** A fully valid request: this is the only shape that may be allowed. */
    static Inputs ok() {
        Inputs in = new Inputs();
        in.currentBootId = BOOT;
        in.requestBootId = BOOT;
        in.postRootRecord = postRoot(BOOT);
        in.liveSelinux = 1;
        in.lockRecord = null;
        in.pinnedKsudSha256 = PINNED;
        in.candidates.add(new Candidate(STAGED, PINNED));
        in.candidates.add(new Candidate(ADB, MANAGER));
        return in;
    }

    static void allow(String name, Inputs in, String expectPath) {
        Decision d = SoftRebootPolicy.evaluate(in);
        if (d.allow && expectPath.equals(d.binaryPath)) {
            pass++;
            System.out.println("  ok   - " + name + " (" + d.binaryPath + ")");
        } else {
            fail++;
            System.out.println("  FAIL - " + name + ": allow=" + d.allow
                    + " path=" + d.binaryPath + " reason=" + d.reason);
        }
    }

    static void refuse(String name, Inputs in) {
        Decision d = SoftRebootPolicy.evaluate(in);
        if (!d.allow && d.binaryPath == null && d.reason != null && !d.reason.isEmpty()) {
            pass++;
            System.out.println("  ok   - " + name + " -> " + d.reason);
        } else {
            fail++;
            System.out.println("  FAIL - " + name + ": expected a named refusal, got allow="
                    + d.allow + " path=" + d.binaryPath);
        }
    }

    public static void main(String[] args) {
        System.out.println("[T] SoftRebootPolicy");

        allow("a fully verified same-boot request is dispatched", ok(), STAGED);

        // The staged copy is preferred, but the rule is the DIGEST, not the path:
        // whichever candidate carries the pinned bytes is the one invoked.
        Inputs onlyAdbIsPinned = ok();
        onlyAdbIsPinned.candidates.clear();
        onlyAdbIsPinned.candidates.add(new Candidate(STAGED, MANAGER));
        onlyAdbIsPinned.candidates.add(new Candidate(ADB, PINNED));
        allow("the pinned digest decides, not the path", onlyAdbIsPinned, ADB);

        Inputs stagedGone = ok();
        stagedGone.candidates.clear();
        stagedGone.candidates.add(new Candidate(STAGED, null));
        stagedGone.candidates.add(new Candidate(ADB, PINNED));
        allow("an unreadable candidate is skipped, not fatal", stagedGone, ADB);

        refuse("no inputs at all", null);

        Inputs noBoot = ok();
        noBoot.currentBootId = "";
        refuse("current boot_id unavailable", noBoot);

        Inputs noRequestBoot = ok();
        noRequestBoot.requestBootId = "  ";
        refuse("request carries no boot_id", noRequestBoot);

        // The action is boot-scoped evidence: a notification minted last boot must
        // not ask an unrooted boot to re-apply modules.
        Inputs staleRequest = ok();
        staleRequest.requestBootId = OTHER_BOOT;
        refuse("request minted in another boot", staleRequest);

        Inputs noPostRoot = ok();
        noPostRoot.postRootRecord = null;
        refuse("no post-root record", noPostRoot);

        Inputs unreadablePostRoot = ok();
        unreadablePostRoot.postRootRecord = AutoRootPolicy.RECORD_UNREADABLE;
        refuse("post-root record exists but unreadable", unreadablePostRoot);

        Inputs stalePostRoot = ok();
        stalePostRoot.postRootRecord = postRoot(OTHER_BOOT);
        refuse("post-root record from another boot", stalePostRoot);

        // uapi_version is the field ensure_uapi_version_matched() compares, so a
        // record that disagrees with it is exactly the case where ksud would skip
        // the soft reboot and still exit 0.
        Inputs wrongUapi = ok();
        wrongUapi.postRootRecord = postRoot(BOOT).replace("uapi_version=2", "uapi_version=1");
        refuse("post-root record reports a different KernelSU UAPI", wrongUapi);

        Inputs permissive = ok();
        permissive.liveSelinux = 0;
        refuse("live SELinux is permissive", permissive);

        Inputs selinuxUnreadable = ok();
        selinuxUnreadable.liveSelinux = -1;
        refuse("live SELinux unreadable", selinuxUnreadable);

        Inputs alreadyClaimed = ok();
        alreadyClaimed.lockRecord = SoftRebootPolicy.formatLock(BOOT, 1L);
        refuse("a soft reboot attempt was already claimed in this boot", alreadyClaimed);

        Inputs legacyCurrentBoot = ok();
        legacyCurrentBoot.lockRecord = "boot_id=" + BOOT
                + "\nphase=DISPATCHED\ndispatched_at_ms=1\n";
        refuse("a current-boot legacy lock still fails closed", legacyCurrentBoot);

        Inputs lockUnreadable = ok();
        lockUnreadable.lockRecord = AutoRootPolicy.RECORD_UNREADABLE;
        refuse("the lock exists but is unreadable", lockUnreadable);

        Inputs lockGarbage = ok();
        lockGarbage.lockRecord = "boot_id=" + BOOT + "\nphase=CLAIMED\n";
        refuse("the lock is missing a field", lockGarbage);

        Inputs lockUnknownKey = ok();
        lockUnknownKey.lockRecord = SoftRebootPolicy.formatLock(BOOT, 1L) + "extra=1\n";
        refuse("the lock carries an unknown key", lockUnknownKey);

        // Last boot's lock says nothing about this one.
        Inputs oldLock = ok();
        oldLock.lockRecord = SoftRebootPolicy.formatLock(OTHER_BOOT, 1L);
        allow("a lock naming another boot does not lock this one", oldLock, STAGED);

        Inputs oldLegacyLock = ok();
        oldLegacyLock.lockRecord = "boot_id=" + OTHER_BOOT
                + "\nphase=DISPATCHED\ndispatched_at_ms=1\n";
        allow("a legacy lock naming another boot does not lock this one",
                oldLegacyLock, STAGED);

        Inputs noPinned = ok();
        noPinned.pinnedKsudSha256 = "";
        refuse("no pinned digest to compare against", noPinned);

        // The observed field case: the root manager replaced /data/adb/ksud with
        // its own libksud.so and nothing staged is present either.
        Inputs managerOnly = ok();
        managerOnly.candidates.clear();
        managerOnly.candidates.add(new Candidate(ADB, MANAGER));
        refuse("only the root manager's ksud is present", managerOnly);

        Inputs noCandidates = ok();
        noCandidates.candidates.clear();
        refuse("no candidate binaries at all", noCandidates);

        Inputs allUnreadable = ok();
        allUnreadable.candidates.clear();
        allUnreadable.candidates.add(new Candidate(STAGED, null));
        allUnreadable.candidates.add(new Candidate(ADB, null));
        refuse("every candidate unreadable", allUnreadable);

        // Digest comparison must not be case-sensitive in the direction that
        // REFUSES a true match, but must still be exact about the value.
        Inputs upperCase = ok();
        upperCase.candidates.clear();
        upperCase.candidates.add(new Candidate(STAGED, PINNED.toUpperCase()));
        allow("an upper-case digest of the same bytes matches", upperCase, STAGED);

        Inputs nearMiss = ok();
        nearMiss.candidates.clear();
        nearMiss.candidates.add(new Candidate(STAGED, PINNED.substring(0, 63) + "b"));
        refuse("a one-character digest difference refuses", nearMiss);

        // --- precheck: everything decidable WITHOUT a root shell ---------------
        // It exists because no candidate digest can be read by this app at all: the
        // chain consumes the staged daemon and installs it under /data/adb, which is
        // 0700 root. The digests come from `su -c sha256sum`, so the shell has to be
        // obtained first - and the cheap refusals must therefore come before it, or a
        // notification minted in another boot would make the device ask for root only
        // to be refused.
        System.out.println("");
        System.out.println("[T] SoftRebootPolicy.precheck");

        Inputs noCands = ok();
        noCands.candidates.clear();
        Decision p1 = SoftRebootPolicy.precheck(noCands);
        if (p1.allow && p1.binaryPath == null) {
            pass++;
            System.out.println("  ok   - passes with no candidates at all (they come later)");
        } else {
            fail++;
            System.out.println("  FAIL - precheck needs candidates: " + p1.reason);
        }

        // Every unprivileged refusal must still fire here, or the receiver would
        // reach for a root shell on a request it should have rejected outright.
        String[][] cases = {
            {"stale request boot", "requestBootId"},
            {"post-root from another boot", "postRoot"},
            {"permissive SELinux", "selinux"},
            {"already dispatched this boot", "lock"},
        };
        for (String[] c : cases) {
            Inputs in = ok();
            in.candidates.clear();
            switch (c[1]) {
                case "requestBootId": in.requestBootId = OTHER_BOOT; break;
                case "postRoot": in.postRootRecord = postRoot(OTHER_BOOT); break;
                case "selinux": in.liveSelinux = 0; break;
                case "lock": in.lockRecord = SoftRebootPolicy.formatLock(BOOT, 1L); break;
                default: break;
            }
            Decision d = SoftRebootPolicy.precheck(in);
            if (!d.allow && d.reason != null && !d.reason.isEmpty()) {
                pass++;
                System.out.println("  ok   - refuses before asking for root: " + c[0]);
            } else {
                fail++;
                System.out.println("  FAIL - precheck allowed " + c[0]);
            }
        }

        // precheck must never hand back a binary: choosing one needs the digests,
        // and the digests need the shell precheck runs before.
        Decision p2 = SoftRebootPolicy.precheck(ok());
        if (p2.binaryPath == null) {
            pass++;
            System.out.println("  ok   - precheck never selects a binary");
        } else {
            fail++;
            System.out.println("  FAIL - precheck selected " + p2.binaryPath);
        }

        System.out.println("");
        System.out.println("[T] SoftRebootDispatchGuard");
        SoftRebootDispatchGuard guard = new SoftRebootDispatchGuard();
        SoftRebootDispatchGuard.Lease preClaim = guard.tryAcquire();
        preClaim.close();
        SoftRebootDispatchGuard.Lease retry = guard.tryAcquire();
        if (retry != null) {
            pass++;
            System.out.println("  ok   - a pre-claim refusal releases the guard");
        } else {
            fail++;
            System.out.println("  FAIL - pre-claim refusal left the guard held");
        }
        if (guard.tryAcquire() == null) {
            pass++;
            System.out.println("  ok   - concurrent pre-claim taps stay serialized");
        } else {
            fail++;
            System.out.println("  FAIL - concurrent tap acquired the held guard");
        }
        retry.markDurableClaimed();
        retry.close();
        if (guard.tryAcquire() == null) {
            pass++;
            System.out.println("  ok   - durable claim keeps future attempts refused");
        } else {
            fail++;
            System.out.println("  FAIL - durable claim released the guard");
        }

        System.out.println("");
        System.out.println("SoftRebootPolicyTest: " + pass + "/" + (pass + fail) + " passed");
        if (fail != 0) System.exit(1);
    }
}
