package com.polygraphene.df.reroot

import android.content.Context
import android.os.Build
import java.io.File
import java.security.MessageDigest

object KsudStage {
    const val TAG = "SysPersist"
    const val DEST = "/data/system/dfreroot-ksud"

    private data class KsudSpec(
        val profileId: String,
        val fingerprint: String,
        val assetName: String,
        val sha256: String,
        val size: Long,
    )

    private val ZZIC = KsudSpec(
        profileId = "S25U_ZZIC",
        fingerprint =
            "samsung/pa3qxxx/pa3q:17/CP2A.260605.016/" +
                "S938BXXUCZZIC_OXMCZZIC:user/release-keys",
        assetName = "ksud",
        sha256 =
            "d0cb516da0047b1b918f84adf8ce7a389c6285de9282cd6301514a40849af7fc",
        size = 6674552L,
    )

    private val DZIF = KsudSpec(
        profileId = "S25U_DZIF",
        fingerprint =
            "samsung/pa3qxxx/pa3q:17/CP2A.260605.016/" +
                "S938BXXUCDZIF_OXMCDZIF:user/release-keys",
        assetName = "ksud-dzif",
        sha256 =
            "f680f959472e994110eb1281d6aa47ed3cd934ae5775f5e9e378a2e946ae69e3",
        size = 6665720L,
    )

    private fun currentSpec(): KsudSpec? = when (Build.FINGERPRINT) {
        ZZIC.fingerprint -> ZZIC
        DZIF.fingerprint -> DZIF
        else -> null
    }

    fun pinnedKsudSha256(): String = currentSpec()?.sha256 ?: ""

    fun stageFromAssets(context: Context): String {
        val spec = currentSpec()
            ?: return "[x] KSUD_PROFILE=FAIL unsupported fingerprint=${Build.FINGERPRINT}\n"

        val raw = try {
            context.assets.open(spec.assetName).use { it.readBytes() }
        } catch (t: Throwable) {
            return "[x] assets/${spec.assetName} unreadable: $t\n"
        }
        return stageBytes(raw, spec)
    }

    fun stageBytes(raw: ByteArray): String {
        val spec = currentSpec()
            ?: return "[x] KSUD_PROFILE=FAIL unsupported fingerprint=${Build.FINGERPRINT}\n"
        return stageBytes(raw, spec)
    }

    private fun stageBytes(raw: ByteArray, spec: KsudSpec): String {
        val s = StringBuilder()
        s.appendLine("[*] ksud profile ${spec.profileId} asset=${spec.assetName}")
        s.appendLine("[*] ksud asset ${raw.size} bytes")

        if (raw.size.toLong() != spec.size) {
            s.appendLine("[x] KSUD_SIZE=FAIL asset is ${raw.size} bytes, pinned ${spec.size}")
            return s.toString()
        }

        val actual = sha256(raw)
        s.appendLine("[*] ksud sha256 $actual")
        if (actual != spec.sha256) {
            s.appendLine("[x] KSUD_IDENTITY=FAIL expected ${spec.sha256}")
            return s.toString()
        }
        s.appendLine("[+] KSUD_IDENTITY=PASS (matches pinned ${spec.profileId} daemon)")

        try {
            File(DEST).writeBytes(raw)
            android.system.Os.chmod(DEST, 448)
        } catch (t: Throwable) {
            s.appendLine("[!] $DEST not writable: ${t.javaClass.simpleName}: ${t.message}")
            return s.toString()
        }

        val back = try {
            File(DEST).readBytes()
        } catch (t: Throwable) {
            s.appendLine("[x] staged file unreadable: ${t.javaClass.simpleName}")
            return s.toString()
        }

        val backDigest = sha256(back)
        if (back.size != raw.size || backDigest != spec.sha256) {
            s.appendLine("[x] KSUD_STAGED_VERIFY=FAIL ${back.size} bytes, sha256 $backDigest")
            return s.toString()
        }

        s.appendLine("[+] KSUD_STAGED_VERIFY=PASS")
        s.appendLine("[+] staged $DEST (${raw.size} bytes)")
        return s.toString()
    }

    private fun sha256(b: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(b)
            .joinToString("") { "%02x".format(it) }
}
