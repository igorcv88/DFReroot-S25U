package com.polygraphene.df.companion;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * The attestation's decision layer: the root shell's keyed output in, a set of
 * separate signals out. Pure, so every negative case is reachable on a host.
 *
 * <h2>What "attested" has to mean here</h2>
 *
 * DFReroot's {@code RootEnvironment} will only grant the reuse route on a
 * positive attestation of the LOADED module, because a module name is shared by
 * both pairs and proves nothing (AGENTS.md §3.12). Two facts, taken together,
 * are such an attestation:
 *
 * <ol>
 *   <li><b>The bytes that ran are the pinned RMG daemon.</b> The digest is
 *       taken before the invocation and again after it, and both must equal the
 *       pin. See the window note below.</li>
 *   <li><b>The loaded module answered an ioctl only the RMG build
 *       implements.</b> {@code ksud profile status} runs
 *       {@code ensure_uapi_version_matched()} and {@code ioctl::contract(0)} —
 *       {@code 0xc0104b1e}, revision 1, {@code profile_size} 784, operation 0,
 *       which performs no write — and fails outright on an unpaired kernel.
 *       Upstream KernelSU has no such ioctl.</li>
 * </ol>
 *
 * Neither alone is enough. (1) without (2) describes a file on disk, not what
 * the kernel is running; (2) without (1) is a claim relayed by a binary of
 * unknown provenance.
 *
 * <h2>The residual window, stated rather than hidden</h2>
 *
 * AGENTS.md §3.5.1 is explicit that a digest on a mutable path binds a name and
 * not bytes, and that the fix is {@code execveat(fd, AT_EMPTY_PATH)} on the
 * hashed descriptor. This companion does not do that yet, and the reasons the
 * weaker form is accepted here are specific, not general:
 *
 * <ul>
 *   <li>the hash, the invocation and the second hash happen inside <b>one</b>
 *       root shell, sequentially, microseconds apart — not across app-level
 *       logic and boots, which is the case §3.5.1 was written about;</li>
 *   <li>writing {@code /data/adb/ksud} requires root already, so an attacker
 *       able to exploit the window has what the window would win them;</li>
 *   <li>the post-invocation hash means a replacement that persists is caught,
 *       and a mismatch is a refusal.</li>
 * </ul>
 *
 * It is still a weaker binding than the chain's own transport uses, and
 * {@code docs/COMPANION.md} records it as owed work rather than as settled.
 */
public final class AttestationReport {

    private AttestationReport() {}

    /** No claim is supported by this evidence. */
    public static final int ATTEST_NONE = 0;
    /**
     * A root operation we asked for demonstrably happened: uid 0, our nonce
     * echoed back, and a read only root can perform. It says a functioning
     * KernelSU granted this app root; it says nothing about which module.
     */
    public static final int ATTEST_ROOT_OPERATIONAL = 1;
    /** The two facts above both hold: the loaded module is the RMG pair. */
    public static final int ATTEST_RMG_CONTRACT = 2;

    private static final Set<String> KEYS = Set.of(
            "DFRC_UID", "DFRC_SELINUX", "DFRC_NONCE", "DFRC_KSUD_SHA256_PRE",
            "DFRC_KSUD_SIZE", "DFRC_STATUS", "DFRC_STATUS_RC",
            "DFRC_KSUD_SHA256_POST", "DFRC_MODULES", "DFRC_END");

    public static final class Verdict {
        public final int attestation;
        /** uid 0, our nonce, and a root-only read all came back. */
        public final boolean rootProven;
        /** The daemon's bytes equalled the pin before AND after the call. */
        public final boolean ksudPinned;
        /** The loaded module answered the RMG-only contract ioctl. */
        public final boolean contractRoundTrip;
        /** {@code /sys/fs/selinux/enforce} was 1 at the time of the call. */
        public final boolean selinuxEnforcing;
        /** A KernelSU-like module was named in {@code /proc/modules}. */
        public final boolean moduleNamed;
        public final String reason;

        private Verdict(int attestation, boolean rootProven, boolean ksudPinned,
                boolean contractRoundTrip, boolean selinuxEnforcing,
                boolean moduleNamed, String reason) {
            this.attestation = attestation;
            this.rootProven = rootProven;
            this.ksudPinned = ksudPinned;
            this.contractRoundTrip = contractRoundTrip;
            this.selinuxEnforcing = selinuxEnforcing;
            this.moduleNamed = moduleNamed;
            this.reason = reason;
        }

        /** Every signal separately, never one collapsed verdict (AGENTS.md §3.7). */
        public String signals() {
            return "ATTESTATION=" + name(attestation)
                    + " ROOT_OPERATION=" + pass(rootProven)
                    + " KSUD_PINNED=" + pass(ksudPinned)
                    + " CONTRACT_V1_ROUNDTRIP=" + pass(contractRoundTrip)
                    + " SELINUX_ENFORCING=" + pass(selinuxEnforcing)
                    + " MODULE_NAMED=" + pass(moduleNamed);
        }

        private static String pass(boolean b) {
            return b ? "PASS" : "FAIL";
        }
    }

    public static String name(int attestation) {
        switch (attestation) {
            case ATTEST_ROOT_OPERATIONAL: return "ROOT_OPERATIONAL";
            case ATTEST_RMG_CONTRACT: return "RMG_CONTRACT";
            default: return "NONE";
        }
    }

    private static Verdict none(String reason) {
        return new Verdict(ATTEST_NONE, false, false, false, false, false, reason);
    }

    private static boolean digest(String s) {
        if (s == null || s.length() != 64) return false;
        for (int i = 0; i < 64; i++) {
            char c = s.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                    || (c >= 'A' && c <= 'F');
            if (!hex) return false;
        }
        return true;
    }

    /**
     * @param output       the root shell's keyed output, verbatim
     * @param expectedNonce the nonce this call sent; a report that does not
     *                      echo it may be any previous run's output
     */
    public static Verdict evaluate(String output, String expectedNonce) {
        if (output == null || output.trim().isEmpty()) {
            return none("the attestation produced no output");
        }
        if (expectedNonce == null || expectedNonce.trim().isEmpty()) {
            // Without a nonce nothing binds the output to THIS call.
            return none("no nonce was supplied, so no output could be bound to this call");
        }
        Map<String, String> v = new HashMap<>();
        for (String raw : output.split("\n", -1)) {
            String line = raw.trim();
            if (line.isEmpty()) continue;
            int eq = line.indexOf('=');
            if (eq <= 0) continue; // shell noise; the required keys decide
            String key = line.substring(0, eq);
            if (!KEYS.contains(key)) continue;
            String value = line.substring(eq + 1);
            if (v.putIfAbsent(key, value) != null) {
                return none("duplicate attestation key " + key
                        + "; two reports may have been concatenated");
            }
        }
        if (!"1".equals(v.get("DFRC_END"))) {
            return none("the attestation output is truncated (no end marker);"
                    + " a partial report must not be read as a partial pass");
        }
        if (!expectedNonce.equals(v.get("DFRC_NONCE"))) {
            return none("the attestation did not echo this call's nonce");
        }

        boolean uidZero = "0".equals(v.get("DFRC_UID"));
        String pre = v.get("DFRC_KSUD_SHA256_PRE");
        String post = v.get("DFRC_KSUD_SHA256_POST");
        /*
         * /data/adb is 0700 root:root, so a digest of a file beneath it could
         * only have been produced by a process that traversed it. That is the
         * root-only read, and it is why the digest doubles as proof of
         * privilege rather than only as identity.
         */
        boolean rootOnlyRead = digest(pre) && digest(post);
        boolean rootProven = uidZero && rootOnlyRead;

        long size = -1L;
        try {
            size = Long.parseLong(v.getOrDefault("DFRC_KSUD_SIZE", "-1").trim());
        } catch (NumberFormatException ignored) {
            size = -1L;
        }
        boolean ksudPinned = rootOnlyRead
                && pre.equalsIgnoreCase(post)
                && pre.equalsIgnoreCase(RmgIdentity.RMG_KSUD_SHA256)
                && size == RmgIdentity.RMG_KSUD_SIZE;

        String status = v.get("DFRC_STATUS");
        boolean contractRoundTrip = "0".equals(v.get("DFRC_STATUS_RC"))
                && status != null
                && status.startsWith(RmgIdentity.STATUS_PREFIX)
                && status.contains("uid=")
                && status.contains("root=");

        boolean selinuxEnforcing = "Enforcing".equals(v.get("DFRC_SELINUX"));
        boolean moduleNamed = RmgIdentity.KSU_MODULE_NAME.equals(v.get("DFRC_MODULES"));

        if (!rootProven) {
            return new Verdict(ATTEST_NONE, false, ksudPinned, contractRoundTrip,
                    selinuxEnforcing, moduleNamed,
                    "the operation did not prove root: uid=" + v.get("DFRC_UID")
                            + ", root-only read " + (rootOnlyRead ? "ok" : "absent"));
        }
        if (ksudPinned && contractRoundTrip) {
            return new Verdict(ATTEST_RMG_CONTRACT, true, true, true,
                    selinuxEnforcing, moduleNamed,
                    "the pinned RMG daemon ran and the loaded module answered the"
                            + " managerless contract ioctl; the kernel side is the RMG pair");
        }
        return new Verdict(ATTEST_ROOT_OPERATIONAL, true, ksudPinned, contractRoundTrip,
                selinuxEnforcing, moduleNamed,
                "a root operation succeeded, but the loaded module was not attested"
                        + " (ksud pinned=" + ksudPinned + ", contract round-trip="
                        + contractRoundTrip + ")");
    }
}
