package com.polygraphene.df.reroot

import android.content.Context
import java.io.File
import java.security.MessageDigest

object KsudStage {
    const val TAG = "SysPersist"

    /**
     * Where the daemon is staged for the privileged handoff.
     *
     * This is not an arbitrary choice on either side any more: the RMG ZZIC ksud
     * is built with the `dfreroot` staging contract and calls
     * `stage_daemon_from("/data/system/dfreroot-ksud")` — this exact path,
     * compiled in. It is `system:system` and not world-writable, which is why
     * this app may reference it at all: AGENTS.md §3.6 forbids naming a
     * world-writable staging directory anywhere in code that ships here, and the
     * audit enforces that by mechanism rather than by spelling - comments
     * included, which is why this one describes the path instead of writing it.
     *
     * Both paths live on /data, so the daemon's own `rename(2)` onto
     * /data/adb/ksud does not cross a filesystem.
     */
    const val DEST = "/data/system/dfreroot-ksud"

    /**
     * The exact ksud these bytes must be. Mirrors `.ksud_sha256` / `.ksud_size`
     * in target_profile.c and tools/zzic_profile.json;
     * tools/profile_binding_audit.py fails on drift between the three copies and
     * on a bundled asset whose digest is not this one.
     */
    private const val KSUD_SHA256 =
        "14fb9eaf14cb6dc0a32aace6024e89124bba1ea8b4b37979136b7c2017dec97a"
    private const val KSUD_SIZE = 6670272L

    /**
     * The pinned digest, for code that must bind a decision to these exact bytes
     * without re-hashing them - the Auto Root qualification, which is void the
     * moment the daemon changes. Exposed as a function rather than copied, so
     * there is still exactly one literal in this app and the binding audit still
     * has one place to compare against target_profile.c and zzic_profile.json.
     */
    fun pinnedKsudSha256(): String = KSUD_SHA256

    fun stageFromAssets(context: Context): String {
        val raw = try {
            context.assets.open("ksud").use { it.readBytes() }
        } catch (t: Throwable) {
            return "[x] assets/ksud unreadable: $t (rebuild with ./build.sh?)\n"
        }
        return stageBytes(raw)
    }

    fun stageBytes(raw: ByteArray): String {
        val s = StringBuilder()
        s.appendLine("[*] ksud asset ${raw.size} bytes")

        /*
         * Identity BEFORE the write, and again after. A daemon that is about to
         * be handed uid 0 is the last thing that should be staged on trust: "we
         * shipped a ksud" is not evidence that we shipped THIS one, and the asset
         * is an opaque 6.6 MB binary nobody eyeballs.
         *
         * Size is checked separately from the digest so a truncated read is
         * reported as truncation rather than as a mismatch that looks like the
         * wrong binary.
         */
        if (raw.size.toLong() != KSUD_SIZE) {
            s.appendLine("[x] KSUD_SIZE=FAIL asset is ${raw.size} bytes, pinned $KSUD_SIZE")
            s.appendLine("[x] refusing to stage: a short read is not the pinned daemon")
            return s.toString()
        }
        val actual = sha256(raw)
        s.appendLine("[*] ksud sha256 $actual")
        if (actual != KSUD_SHA256) {
            s.appendLine("[x] KSUD_IDENTITY=FAIL expected $KSUD_SHA256")
            s.appendLine("[x] refusing to stage: these are not the verified ZZIC ksud bytes")
            return s.toString()
        }
        s.appendLine("[+] KSUD_IDENTITY=PASS (matches the pinned ZZIC daemon)")

        try {
            File(DEST).writeBytes(raw)
            android.system.Os.chmod(DEST, 448) // 0700
        } catch (t: Throwable) {
            s.appendLine("[!] $DEST not writable: ${t.javaClass.simpleName}: ${t.message}")
            return s.toString()
        }

        /*
         * Re-read what actually landed. A short write, a full filesystem or
         * anything that rewrote the file between the two moments must surface
         * here, not on the device as a daemon that fails for no visible reason.
         */
        val back = try {
            File(DEST).readBytes()
        } catch (t: Throwable) {
            s.appendLine("[x] staged file unreadable: ${t.javaClass.simpleName}")
            return s.toString()
        }
        val backDigest = sha256(back)
        if (back.size != raw.size || backDigest != KSUD_SHA256) {
            s.appendLine("[x] KSUD_STAGED_VERIFY=FAIL ${back.size} bytes, sha256 $backDigest")
            s.appendLine("[x] the staged file is not what was written; refusing to proceed")
            return s.toString()
        }
        s.appendLine("[+] KSUD_STAGED_VERIFY=PASS")
        s.appendLine("[+] staged $DEST (${raw.size} bytes)")
        return s.toString()
    }

    private fun sha256(b: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-256").digest(b)
        val sb = StringBuilder(64)
        for (x in d) sb.append("%02x".format(x))
        return sb.toString()
    }
}
