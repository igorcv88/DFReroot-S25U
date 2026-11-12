package com.polygraphene.df.companion

import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.util.Log
import java.security.MessageDigest

/**
 * The exported surface. Three checks before anything runs, then one of two
 * enumerated transactions.
 *
 * The checks are deliberately redundant, in increasing strength: the manifest's
 * signature-level permission (the framework, before our code runs), the Binder
 * interface token, and [CallerAuthorization] (uid, package membership,
 * certificate digest, contract version). A gate is only as strong as its
 * weakest entry point, and there is exactly one entry point here.
 *
 * `onTransact` runs on a binder thread, so the bounded `su` invocation does not
 * block this app's main thread. It does occupy a binder thread for up to
 * [CompanionContract.ATTEST_TIMEOUT_MS], which is why the client must call from
 * a background thread of its own - DFReroot runs inside `system_server` and
 * must never wait on this from its main thread.
 */
class CompanionService : Service() {

    companion object {
        private const val TAG = "DFRCompanion"
    }

    private val binder = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != CompanionContract.TX_DESCRIBE && code != CompanionContract.TX_ATTEST) {
                // Not ours: let Binder answer (dump, interface queries, ...).
                return super.onTransact(code, data, reply, flags)
            }
            try {
                data.enforceInterface(CompanionContract.DESCRIPTOR)
            } catch (t: Throwable) {
                Log.e(TAG, "[DFRC][CALL] DESCRIPTOR_REFUSED ${t.javaClass.simpleName}")
                answer(reply, CompanionContract.RC_CALLER_REFUSED, "",
                    "the transaction did not carry this interface's token")
                return true
            }
            val requestedVersion = data.readInt()
            val verdict = authorize(requestedVersion)
            if (!verdict.allowed) {
                Log.e(TAG, "[DFRC][CALL] ${CompanionContract.rcName(verdict.rc)}" +
                    " ${verdict.reason}")
                answer(reply, verdict.rc, "", verdict.reason)
                return true
            }
            when (code) {
                CompanionContract.TX_DESCRIBE -> {
                    answer(reply, CompanionContract.RC_OK,
                        "CONTRACT_VERSION=${CompanionContract.CONTRACT_VERSION}" +
                            " TX=DESCRIBE,ATTEST COMMAND_CHANNEL=NONE",
                        verdict.reason)
                }
                CompanionContract.TX_ATTEST -> attest(reply)
            }
            return true
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    private fun authorize(requestedVersion: Int): CallerAuthorization.Verdict {
        val uid = Binder.getCallingUid()
        val packages = try {
            packageManager.getPackagesForUid(uid)
        } catch (t: Throwable) {
            Log.e(TAG, "[DFRC][CALL] PACKAGES_FOR_UID failed: ${t.javaClass.simpleName}")
            null
        }
        return CallerAuthorization.evaluate(
            uid,
            packages,
            signingDigest(CompanionContract.CLIENT_PACKAGE),
            signingDigest(packageName),
            requestedVersion,
        )
    }

    /**
     * SHA-256 of a package's first signing certificate, or null.
     *
     * Null on any failure, and [CallerAuthorization] treats a missing digest as
     * a refusal: an absent comparison is not a passed one.
     */
    private fun signingDigest(pkg: String): String? = try {
        val info = packageManager.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
        val signers = info.signingInfo?.apkContentsSigners
        if (signers == null || signers.isEmpty()) {
            null
        } else {
            MessageDigest.getInstance("SHA-256").digest(signers[0].toByteArray())
                .joinToString("") { "%02x".format(it) }
        }
    } catch (t: Throwable) {
        Log.e(TAG, "[DFRC][CALL] SIGNING_DIGEST $pkg failed: ${t.javaClass.simpleName}")
        null
    }

    private fun attest(reply: Parcel?) {
        val nonce = Attestation.newNonce()
        val outcome = SuChannel.runAsRoot(
            Attestation.script(nonce), CompanionContract.ATTEST_TIMEOUT_MS
        )
        if (outcome.timedOut) {
            answer(reply, CompanionContract.RC_TIMEOUT, "",
                "the root invocation did not return within " +
                    "${CompanionContract.ATTEST_TIMEOUT_MS}ms")
            return
        }
        if (outcome.execFailed) {
            answer(reply, CompanionContract.RC_UNAVAILABLE, "",
                "su could not be executed: ${outcome.stderr.trim()}")
            return
        }
        /*
         * A non-zero exit from `su` itself is the manager refusing this app, and
         * it is kept apart from an attestation that ran and proved nothing: the
         * first is "no grant", the second is "granted, evidence insufficient",
         * and the owner's next step differs (AGENTS.md 3.7).
         */
        val verdict = AttestationReport.evaluate(outcome.stdout, nonce)
        if (outcome.exit != 0 && !verdict.rootProven) {
            answer(reply, CompanionContract.RC_NO_ROOT, verdict.signals(),
                "su exited ${outcome.exit} and no root operation was proven;" +
                    " this app may not hold the KernelSU grant")
            return
        }
        val rc = if (verdict.attestation == AttestationReport.ATTEST_NONE) {
            CompanionContract.RC_ATTESTATION_INCONCLUSIVE
        } else {
            CompanionContract.RC_OK
        }
        Log.i(TAG, "[DFRC][ATTEST] ${verdict.signals()}")
        answer(reply, rc, verdict.signals(), verdict.reason)
    }

    private fun answer(reply: Parcel?, rc: Int, signals: String, reason: String?) {
        reply?.writeNoException()
        reply?.writeInt(CompanionContract.CONTRACT_VERSION)
        reply?.writeInt(rc)
        reply?.writeString(signals)
        reply?.writeString(reason ?: "")
    }
}
