package com.polygraphene.df.companion

import java.security.SecureRandom

/**
 * The fixed attestation script and the nonce that binds its output to one call.
 *
 * Every command here is a read. `ksud profile status` is the one that reaches
 * the kernel, and it reaches it with the managerless contract probe, operation
 * 0, which the RMGLabs contract defines as performing no write. Nothing in this
 * script grants, revokes, persists, loads, stages or restarts anything, and
 * `tools/profile_binding_audit.py` fails if a token that could appear in such a
 * command appears in this file.
 */
object Attestation {

    private val random = SecureRandom()

    /** 16 random bytes as lowercase hex. Hex by construction, so it cannot be
     *  anything a shell would interpret. */
    fun newNonce(): String {
        val bytes = ByteArray(16)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * The digest is taken before AND after the daemon runs.
     *
     * One root shell, sequential, microseconds apart - see
     * [AttestationReport] for why that weaker binding is accepted here and
     * what is still owed.
     */
    fun script(nonce: String): String {
        val ksud = RmgIdentity.KSUD_PATH
        return buildString {
            appendLine("echo \"DFRC_UID=\$(id -u)\"")
            appendLine("echo \"DFRC_SELINUX=\$(getenforce 2>/dev/null)\"")
            appendLine("echo \"DFRC_NONCE=$nonce\"")
            appendLine(
                "echo \"DFRC_KSUD_SHA256_PRE=\$(sha256sum '$ksud' 2>/dev/null |" +
                    " cut -d' ' -f1)\""
            )
            appendLine("echo \"DFRC_KSUD_SIZE=\$(stat -c %s '$ksud' 2>/dev/null)\"")
            appendLine(
                "S=\$('$ksud' profile status ${CompanionContract.PACKAGE}" +
                    " 2>/dev/null | head -1); RC=\$?"
            )
            appendLine("echo \"DFRC_STATUS=\$S\"")
            appendLine("echo \"DFRC_STATUS_RC=\$RC\"")
            appendLine(
                "echo \"DFRC_KSUD_SHA256_POST=\$(sha256sum '$ksud' 2>/dev/null |" +
                    " cut -d' ' -f1)\""
            )
            appendLine(
                "if grep -qw ${RmgIdentity.KSU_MODULE_NAME} /proc/modules 2>/dev/null;" +
                    " then echo \"DFRC_MODULES=${RmgIdentity.KSU_MODULE_NAME}\";" +
                    " else echo \"DFRC_MODULES=absent\"; fi"
            )
            appendLine("echo \"DFRC_END=1\"")
        }
    }
}
