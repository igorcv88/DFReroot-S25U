import com.polygraphene.df.reroot.EarlyBootProbePolicy;

public class EarlyBootProbePolicyTest {
    static int pass;
    static int fail;

    static void expect(boolean value, String name) {
        if (value) {
            pass++;
            System.out.println("  ok   - " + name);
        } else {
            fail++;
            System.out.println("  FAIL - " + name);
        }
    }

    public static void main(String[] args) {
        String boot = "boot-a";
        String record = EarlyBootProbePolicy.formatArm(
                boot, 0x44465245, "dfr-early-boot-probe", 15000, 1, 100, 200);
        EarlyBootProbePolicy.Arm arm = EarlyBootProbePolicy.parseArm(record);
        expect(arm != null && arm.jobId == 0x44465245,
                "a complete scheduled arm record parses");
        expect(EarlyBootProbePolicy.parseArm(record + "unknown=1\n") == null,
                "an unknown arm key refuses");
        expect(EarlyBootProbePolicy.parseArm(record + "job_id=7\n") == null,
                "a duplicate arm key refuses");
        expect(EarlyBootProbePolicy.parseArm(
                        record.replace("schedule_result=1", "schedule_result=0")) == null,
                "a failed schedule result cannot become an armed record");
        expect(EarlyBootProbePolicy.parseArm(record.replace("job_id=1145459269", "job_id=x"))
                        == null,
                "a malformed numeric arm field refuses");
        expect(EarlyBootProbePolicy.STATE_FIRED_SAME_BOOT.equals(
                        EarlyBootProbePolicy.fireState(arm, boot)),
                "same-boot callback is classified explicitly");
        expect(EarlyBootProbePolicy.LOCKED_UNKNOWN.equals(
                        EarlyBootProbePolicy.lockedBootState(arm, boot, null, -1, 500)),
                "same-boot callback is never promoted to pre-locked PASS");
        expect(EarlyBootProbePolicy.LOCKED_PENDING.equals(
                        EarlyBootProbePolicy.lockedBootState(arm, "boot-b", null, -1, 500)),
                "absence of the locked marker stays PENDING until timestamp comparison");
        expect(EarlyBootProbePolicy.POST_LOCKED.equals(
                        EarlyBootProbePolicy.lockedBootState(
                                arm, "boot-b", "boot-b", 400, 500)),
                "new-boot callback after the locked marker is POST_LOCKED");
        expect(EarlyBootProbePolicy.LOCKED_UNKNOWN.equals(
                        EarlyBootProbePolicy.lockedBootState(
                                arm, "boot-b", "", -1, 500)),
                "an unreadable locked marker remains UNKNOWN");

        System.out.println("EarlyBootProbePolicyTest: " + pass + "/" + (pass + fail)
                + " passed");
        if (fail != 0) System.exit(1);
    }
}
