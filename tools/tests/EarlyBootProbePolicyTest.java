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

    /** The exact record DfrEarlyBootJobService writes, as a test fixture. */
    static String probeRecord(String firedBootId, String fireState, String lockedState,
                              String callbackElapsedMs) {
        return "state=EARLY_JOB_FIRED\n"
                + "fire_state=" + fireState + "\n"
                + "locked_boot_state=" + lockedState + "\n"
                + "networkstack_state=NETWORKSTACK_READY\n"
                + "armed_boot_id=boot-a\n"
                + "fired_boot_id=" + firedBootId + "\n"
                + "same_boot=0\n"
                + "job_id=1145459269\n"
                + "namespace=dfr-early-boot-probe\n"
                + "callback_namespace=dfr-early-boot-probe\n"
                + "namespace_binding=PASS\n"
                + "callback_elapsed_ms=" + callbackElapsedMs + "\n"
                + "readiness_elapsed_ms=520\n"
                + "marker_write_elapsed_ms=530\n"
                + "callback_wallclock_ms=1700000000000\n"
                + "stopped=0\n"
                + "pid=1000\nppid=1\nuid=1000\neuid=1000\n"
                + "selinux=u:r:system_server:s0\n"
                + "sys_boot_completed=UNKNOWN\n"
                + "user_unlocked=0\n"
                + "bootanim_exit=UNKNOWN\n"
                + "networkstack_proc=PASS\n"
                + "ams_process_record=PASS\n"
                + "application_thread=PASS\n"
                + "schedule_receiver_12=PASS\n";
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

        // --- the result the whole experiment exists to observe ---------------
        expect(EarlyBootProbePolicy.PRE_LOCKED.equals(
                        EarlyBootProbePolicy.lockedBootState(
                                arm, "boot-b", "boot-b", 600, 500)),
                "a new-boot callback before the locked marker is PRE_LOCKED");

        // A clock that could not be read orders nothing, in either direction.
        expect(EarlyBootProbePolicy.LOCKED_UNKNOWN.equals(
                        EarlyBootProbePolicy.lockedBootState(
                                arm, "boot-b", "boot-b", 600, -1)),
                "an unreadable callback clock is UNKNOWN, never PRE_LOCKED");
        expect(EarlyBootProbePolicy.LOCKED_UNKNOWN.equals(
                        EarlyBootProbePolicy.lockedBootState(
                                arm, "boot-b", null, -1, -1)),
                "an unreadable callback clock is not left PENDING for finalization");

        // --- strict probe parsing -------------------------------------------
        String probe = probeRecord("boot-b", EarlyBootProbePolicy.STATE_FIRED_NEW_BOOT,
                EarlyBootProbePolicy.LOCKED_PENDING, "500");
        EarlyBootProbePolicy.Probe parsed = EarlyBootProbePolicy.parseProbe(probe);
        expect(parsed != null && parsed.callbackElapsedMs == 500
                        && "boot-b".equals(parsed.firedBootId),
                "a complete callback record parses");
        expect(EarlyBootProbePolicy.parseProbe(probe + "unknown=1\n") == null,
                "an unknown probe key refuses");
        expect(EarlyBootProbePolicy.parseProbe(probe + "callback_elapsed_ms=9\n") == null,
                "a duplicate callback_elapsed_ms refuses");
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("networkstack_proc=PASS\n", "")) == null,
                "a missing probe key refuses");
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("stopped=0\n", "")) == null,
                "a record that cannot say whether the job was stopped refuses");
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("callback_elapsed_ms=500", "callback_elapsed_ms=x"))
                        == null,
                "a malformed callback timestamp refuses");
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("fire_state=EARLY_JOB_FIRED_NEW_BOOT",
                                "fire_state=EARLY_JOB_TOTALLY_FINE")) == null,
                "an unrecognised fire_state refuses");
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("locked_boot_state=EARLY_JOB_LOCKED_BOOT_PENDING",
                                "locked_boot_state=PASS")) == null,
                "an unrecognised locked_boot_state refuses");
        EarlyBootProbePolicy.Probe unknownClock = EarlyBootProbePolicy.parseProbe(
                probeRecord("boot-b", EarlyBootProbePolicy.STATE_FIRED_NEW_BOOT,
                        EarlyBootProbePolicy.LOCKED_PENDING, "UNKNOWN"));
        expect(unknownClock != null && unknownClock.callbackElapsedMs < 0,
                "a recorded UNKNOWN callback clock parses as a non-comparable value");

        // --- convergence: the verdict depends on timestamps, not thread order -
        expect(EarlyBootProbePolicy.PRE_LOCKED.equals(
                        EarlyBootProbePolicy.finalizeState(parsed, "boot-b", 600)),
                "job-first then receiver: a later locked marker finalizes PRE_LOCKED");
        expect(EarlyBootProbePolicy.POST_LOCKED.equals(
                        EarlyBootProbePolicy.finalizeState(parsed, "boot-b", 400)),
                "job-first then receiver: an earlier locked marker finalizes POST_LOCKED");
        EarlyBootProbePolicy.Probe receiverFirst = EarlyBootProbePolicy.parseProbe(
                probeRecord("boot-b", EarlyBootProbePolicy.STATE_FIRED_NEW_BOOT,
                        EarlyBootProbePolicy.PRE_LOCKED, "500"));
        expect(EarlyBootProbePolicy.finalizeState(receiverFirst, "boot-b", 600) == null,
                "receiver-first: a verdict already computed is never recomputed");
        expect(EarlyBootProbePolicy.finalizeState(parsed, "boot-c", 600) == null,
                "a locked marker from another boot never finalizes this probe");
        expect(EarlyBootProbePolicy.finalizeState(parsed, "boot-b", -1) == null,
                "an invalid locked timestamp never finalizes");
        expect(EarlyBootProbePolicy.finalizeState(unknownClock, "boot-b", 600) == null,
                "an unreadable callback clock never finalizes to PRE_LOCKED");
        expect(EarlyBootProbePolicy.finalizeState(
                        EarlyBootProbePolicy.parseProbe(probeRecord("boot-a",
                                EarlyBootProbePolicy.STATE_FIRED_SAME_BOOT,
                                EarlyBootProbePolicy.LOCKED_PENDING, "500")),
                        "boot-a", 600) == null,
                "a same-boot callback is never finalized into an early-trigger pass");
        expect(EarlyBootProbePolicy.withLockedBootState(probe,
                        EarlyBootProbePolicy.PRE_LOCKED).contains(
                        "locked_boot_state=EARLY_JOB_PRE_LOCKED_BOOT"),
                "finalization rewrites exactly the locked_boot_state line");
        expect(EarlyBootProbePolicy.parseProbe(EarlyBootProbePolicy.withLockedBootState(
                        probe, EarlyBootProbePolicy.PRE_LOCKED)) != null,
                "a finalized record still parses strictly");

        // --- every field that could promote a gate is validated --------------
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("networkstack_state=NETWORKSTACK_READY",
                                "networkstack_state=READY")) == null,
                "an unrecognised networkstack_state refuses");
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("namespace_binding=PASS",
                                "namespace_binding=UNKNOWN")) == null,
                "namespace_binding has no third value; UNKNOWN refuses");
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("same_boot=0", "same_boot=maybe")) == null,
                "an unrecognised same_boot refuses");
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("stopped=0", "stopped=UNKNOWN")) == null,
                "stopped is a boolean; anything else refuses");
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("networkstack_proc=PASS",
                                "networkstack_proc=READY")) == null,
                "a readiness signal outside PASS/FAIL/UNKNOWN refuses");
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("schedule_receiver_12=PASS",
                                "schedule_receiver_12=")) == null,
                "an empty readiness signal refuses");
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("job_id=1145459269", "job_id=DFRE")) == null,
                "a non-numeric job_id refuses");
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("readiness_elapsed_ms=520",
                                "readiness_elapsed_ms=later")) == null,
                "a malformed readiness timestamp refuses");
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("marker_write_elapsed_ms=530",
                                "marker_write_elapsed_ms=-7")) == null,
                "a negative monotonic reading is not a timestamp and refuses");
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("callback_wallclock_ms=1700000000000",
                                "callback_wallclock_ms=UNKNOWN")) != null,
                "an explicitly UNKNOWN clock field still parses");
        expect(EarlyBootProbePolicy.parseProbe(
                        probe.replace("networkstack_proc=PASS",
                                "networkstack_proc=UNKNOWN")) != null,
                "an UNKNOWN readiness signal parses; absence is not a refusal");

        // --- the first locked timestamp of a boot is immutable ---------------
        String first = EarlyBootProbePolicy.formatLockedBoot("boot-b", 19300);
        expect(EarlyBootProbePolicy.mergeLockedBoot(null, "boot-b", 19300) != null,
                "the first locked marker of a boot is written");
        expect(EarlyBootProbePolicy.mergeLockedBoot(first, "boot-b", 41000) == null,
                "a second LOCKED_BOOT in the same boot never replaces the earlier one");
        expect(first.equals(EarlyBootProbePolicy.mergeLockedBoot(
                        EarlyBootProbePolicy.formatLockedBoot("boot-b", 41000),
                        "boot-b", 19300)),
                "an earlier timestamp for the same boot does replace a later one");
        expect(EarlyBootProbePolicy.mergeLockedBoot(first, "boot-c", 8000) != null,
                "a new boot replaces the previous boot's marker");
        expect(EarlyBootProbePolicy.mergeLockedBoot(first, "boot-b", -1) == null,
                "an unreadable clock never overwrites a valid marker");
        expect(EarlyBootProbePolicy.mergeLockedBoot(null, "boot-b", -1) == null,
                "an unreadable clock never creates a marker");
        expect(EarlyBootProbePolicy.mergeLockedBoot("garbage", "boot-b", 500) != null,
                "an unparsable marker is replaced, not trusted");

        // --- strict locked-marker parsing ------------------------------------
        expect(EarlyBootProbePolicy.parseLockedBoot(first) != null,
                "a well-formed locked marker parses");
        expect(EarlyBootProbePolicy.parseLockedBoot(first + "extra=1\n") == null,
                "an unknown locked-marker key refuses");
        expect(EarlyBootProbePolicy.parseLockedBoot("boot_id=boot-b\n") == null,
                "a locked marker missing its timestamp refuses");
        expect(EarlyBootProbePolicy.parseLockedBoot(
                        EarlyBootProbePolicy.formatLockedBoot("boot-b", -1)) == null,
                "a locked marker holding a failed clock reading refuses");

        System.out.println("EarlyBootProbePolicyTest: " + pass + "/" + (pass + fail)
                + " passed");
        if (fail != 0) System.exit(1);
    }
}
