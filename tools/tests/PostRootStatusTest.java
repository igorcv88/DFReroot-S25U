import com.polygraphene.df.reroot.PostRootStatus;

public final class PostRootStatusTest {
    private static int checks;

    private static void expect(boolean condition, String label) {
        checks++;
        if (!condition) throw new AssertionError(label);
    }

    private static String record(String bootId) {
        return "state=POST_ROOT_COMPLETE\n"
                + "boot_id=" + bootId + "\n"
                + "ksu_version=32601\n"
                + "uapi_version=2\n"
                + "runtime_mode=late-load\n"
                + "selinux=1\n";
    }

    private static void refused(String value, String bootId, int liveSelinux, String label) {
        expect(!PostRootStatus.evaluate(value, bootId, liveSelinux).complete, label);
    }

    public static void main(String[] args) {
        String boot = "0643a5e2-9a44-4bb9-b7a4-31a3b255e3ac";
        expect(PostRootStatus.evaluate(record(boot), boot, 1).complete, "exact record passes");
        refused(record("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), boot, 1,
                "stale boot_id is refused");
        refused("state POST_ROOT_COMPLETE\n", boot, 1, "malformed status is refused");
        refused(record(boot).replace("POST_ROOT_COMPLETE", "BOOTSTRAP_HANDOFF"), boot, 1,
                "non-complete state is refused");
        refused(record(boot).replace("selinux=1", "selinux=0"), boot, 1,
                "recorded SELinux != 1 is refused");
        refused(record(boot), boot, 0, "live SELinux != 1 is refused");
        refused(record(boot).replace("ksu_version=32601", "ksu_version=0"), boot, 1,
                "invalid KernelSU version is refused");
        refused(record(boot).replace("uapi_version=2", "uapi_version=0"), boot, 1,
                "invalid UAPI version is refused");
        refused(record(boot).replace("runtime_mode=late-load", "runtime_mode=lkm"), boot, 1,
                "invalid runtime mode is refused");
        refused(record(boot) + "selinux=1\n", boot, 1, "duplicate key is refused");
        refused(record(boot) + "extra=value\n", boot, 1, "unknown key is refused");
        refused(null, boot, 1, "absent record is refused");

        /*
         * transport_fix: optional to PARSE, required to ACT.
         *
         * The previous pair writes no such line and still roots this device
         * correctly, so a record without it must stay complete - requiring it
         * here would refuse a good post-root state and break the chain on every
         * device that has not rebuilt. What it gates is one question, asked by
         * transportFixAllowed(), and there the default is no.
         */
        String fixed = record(boot) + "transport_fix="
                + PostRootStatus.EXPECTED_TRANSPORT_FIX + "\n";
        expect(PostRootStatus.evaluate(fixed, boot, 1).complete,
                "a record carrying the fix marker still parses as complete");
        expect(PostRootStatus.EXPECTED_TRANSPORT_FIX.equals(
                        PostRootStatus.evaluate(fixed, boot, 1).transportFix),
                "the marker is reported back to the caller");
        expect(PostRootStatus.evaluate(record(boot), boot, 1).complete
                        && PostRootStatus.evaluate(record(boot), boot, 1).transportFix == null,
                "a record from the previous pair is complete with no marker");

        expect(PostRootStatus.transportFixAllowed(PostRootStatus.evaluate(fixed, boot, 1)),
                "the supercall is allowed only with the exact marker");
        expect(!PostRootStatus.transportFixAllowed(
                        PostRootStatus.evaluate(record(boot), boot, 1)),
                "no marker means no supercall");
        expect(!PostRootStatus.transportFixAllowed(PostRootStatus.evaluate(
                        record(boot) + "transport_fix=kdp-cred-0\n", boot, 1)),
                "an unknown marker means no supercall");
        expect(!PostRootStatus.transportFixAllowed(PostRootStatus.evaluate(
                        fixed, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 1)),
                "the marker from another boot means no supercall");
        expect(!PostRootStatus.transportFixAllowed(
                        PostRootStatus.evaluate(fixed, boot, 0)),
                "a marker with SELinux not enforcing means no supercall");
        expect(!PostRootStatus.transportFixAllowed(null),
                "a null verdict means no transport/grant permission");
        refused(record(boot) + "transport_fix=a\ntransport_fix=b\n", boot, 1,
                "a duplicated marker is refused outright");

        System.out.println("PostRootStatusTest: " + checks + "/" + checks + " passed");
    }
}
