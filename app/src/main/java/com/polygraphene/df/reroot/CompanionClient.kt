package com.polygraphene.df.reroot

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.IBinder
import android.os.Looper
import android.os.Parcel
import android.util.Log
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.TimeUnit

/**
 * Asks the companion for an attestation. Reads only; acquires no privilege.
 *
 * ## Mutual authentication, not just ours
 *
 * The companion checks our uid, package membership and certificate before it
 * does anything. This side does the same in reverse: the intent is pinned to
 * the companion's package AND its installed signing certificate is compared
 * with ours before the bind. A package name is not an identity - anything could
 * be installed under a name - and the whole point of this call is to decide
 * whether to believe a claim about who owns the kernel.
 *
 * ## Every wait here has a deadline, and one of them is not cancellable
 *
 * The bind waits [CompanionProtocol.BIND_TIMEOUT_MS]; each transaction waits
 * its own deadline through [BoundedCall]. The second one is the subtle case: a
 * synchronous binder transaction cannot be cancelled, so a timeout bounds the
 * CALLER and leaves one daemon thread parked in the driver. [BoundedCall]'s
 * header states that trade-off; it is deliberate, and it is why nothing here
 * retries in a loop.
 *
 * ## Why the main thread is a refusal and not a warning
 *
 * Every component of this app runs inside `system_server`
 * (`android:process="system"`). This call waits on a service bind and then on a
 * root shell behind it, up to [CompanionProtocol.ATTEST_TIMEOUT_MS]. Blocking
 * that looper is not a slow UI; it is a watchdog-visible stall of the system
 * process. So the main thread is checked and refused with
 * [CompanionProtocol.RC_CLIENT_MAIN_THREAD] rather than trusted to callers.
 */
object CompanionClient {

    private const val TAG = "DFReroot"

    class Outcome(
        val rc: Int,
        val verdict: CompanionProtocol.Verdict,
        val detail: String,
        val log: String,
    ) {
        /** The provider answered AND this side re-derived the RMG attestation. */
        val attestedRmg: Boolean
            get() = rc == CompanionProtocol.RC_OK && verdict.rmgContract
    }

    private fun outcome(rc: Int, log: StringBuilder, detail: String): Outcome {
        log.appendLine("[DFR][COMPANION] RESULT rc=$rc $detail")
        return Outcome(rc, CompanionProtocol.parseSignals(null), detail, log.toString())
    }

    /**
     * One bounded attestation round-trip. Blocking: the caller owns the thread.
     */
    fun attest(context: Context): Outcome {
        val log = StringBuilder()
        if (Looper.myLooper() == Looper.getMainLooper()) {
            return outcome(CompanionProtocol.RC_CLIENT_MAIN_THREAD, log,
                "refused on the main thread: this would stall system_server")
        }

        val ours = signingDigest(context, context.packageName)
        val theirs = signingDigest(context, CompanionProtocol.PACKAGE)
        if (theirs == null) {
            return outcome(CompanionProtocol.RC_CLIENT_NO_PROVIDER, log,
                "${CompanionProtocol.PACKAGE} is not installed")
        }
        if (ours == null || !ours.equals(theirs, ignoreCase = true)) {
            /*
             * A provider signed by another key is refused before the bind.
             * Its own caller check would refuse us anyway, but finding that
             * out by being refused is worse evidence than refusing here: this
             * way the log names the cause instead of the symptom.
             */
            return outcome(CompanionProtocol.RC_CLIENT_FOREIGN_PROVIDER, log,
                "the installed companion is signed by a different certificate")
        }
        log.appendLine("[DFR][COMPANION] PROVIDER_IDENTITY=PASS signature matches this build")

        val latch = CountDownLatch(1)
        /*
         * An AtomicReference, not a captured var: the callbacks run on the main
         * looper while this thread waits on the latch, so the handoff crosses
         * threads. `@Volatile` is not available on a local, and a plain capture
         * would be a data race on the one value this call depends on.
         */
        val bound = AtomicReference<IBinder?>(null)
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                bound.set(service)
                latch.countDown()
            }

            override fun onServiceDisconnected(name: ComponentName) {
                bound.set(null)
            }

            override fun onNullBinding(name: ComponentName) {
                // The service returned null from onBind. Count down so the
                // wait ends in a refusal rather than in the timeout.
                latch.countDown()
            }
        }
        val intent = Intent(CompanionProtocol.ACTION).setPackage(CompanionProtocol.PACKAGE)
        val requested = try {
            context.bindService(intent, connection, Context.BIND_AUTO_CREATE)
        } catch (t: Throwable) {
            log.appendLine("[DFR][COMPANION] BIND_THREW ${t.javaClass.simpleName}")
            false
        }
        if (!requested) {
            return outcome(CompanionProtocol.RC_CLIENT_NO_PROVIDER, log,
                "the companion service could not be bound")
        }
        try {
            if (!latch.await(CompanionProtocol.BIND_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                return outcome(CompanionProtocol.RC_TIMEOUT, log,
                    "the companion did not bind within ${CompanionProtocol.BIND_TIMEOUT_MS}ms")
            }
            val binder = bound.get()
                ?: return outcome(CompanionProtocol.RC_CLIENT_NO_PROVIDER, log,
                    "the companion returned a null binding")

            /*
             * DESCRIBE first, and its purpose is the version handshake: it takes
             * no root and reads nothing, so a version skew costs a cheap
             * refusal instead of a 30-second root attempt that ends the same
             * way (AGENTS.md 3.7 - two different facts, two different answers).
             */
            val describe = boundedTransact(
                binder, CompanionProtocol.TX_DESCRIBE,
                CompanionProtocol.DESCRIBE_TIMEOUT_MS, log
            ) ?: return outcome(CompanionProtocol.RC_TIMEOUT, log,
                "DESCRIBE produced no readable reply within" +
                    " ${CompanionProtocol.DESCRIBE_TIMEOUT_MS}ms")
            if (describe.version != CompanionProtocol.CONTRACT_VERSION) {
                return outcome(CompanionProtocol.RC_VERSION_MISMATCH, log,
                    "the companion speaks contract v${describe.version}," +
                        " this build speaks v${CompanionProtocol.CONTRACT_VERSION}")
            }
            if (describe.rc != CompanionProtocol.RC_OK) {
                return outcome(describe.rc, log, "DESCRIBE refused: ${describe.reason}")
            }
            log.appendLine("[DFR][COMPANION] DESCRIBE=PASS ${describe.signals}")

            val attest = boundedTransact(
                binder, CompanionProtocol.TX_ATTEST,
                CompanionProtocol.ATTEST_TIMEOUT_MS, log
            ) ?: return outcome(CompanionProtocol.RC_TIMEOUT, log,
                "ATTEST produced no readable reply within" +
                    " ${CompanionProtocol.ATTEST_TIMEOUT_MS}ms")
            if (attest.version != CompanionProtocol.CONTRACT_VERSION) {
                return outcome(CompanionProtocol.RC_VERSION_MISMATCH, log,
                    "the companion changed contract version mid-call")
            }
            val verdict = CompanionProtocol.parseSignals(attest.signals)
            log.appendLine("[DFR][COMPANION] ATTEST rc=${attest.rc} ${attest.signals}")
            log.appendLine("[DFR][COMPANION] REASON ${verdict.reason}")
            if (attest.rc != CompanionProtocol.RC_OK) {
                return Outcome(attest.rc, verdict, attest.reason, log.toString())
            }
            return Outcome(CompanionProtocol.RC_OK, verdict, attest.reason, log.toString())
        } finally {
            try {
                context.unbindService(connection)
            } catch (t: Throwable) {
                Log.i(TAG, "[DFR][COMPANION] unbind threw ${t.javaClass.simpleName}")
            }
        }
    }

    private class Reply(
        val version: Int,
        val rc: Int,
        val signals: String,
        val reason: String,
    )

    /**
     * One transaction, with a deadline the caller is guaranteed to observe.
     *
     * `binder.transact(..., 0)` is synchronous and has NO timeout: it returns
     * when the remote replies, and never if the remote's handler wedges. The
     * companion bounds its own `su` child at 20 s, and bounding a child is not
     * bounding the call - the same handler also resolves packages, hashes
     * certificates and occupies a binder thread, none of which that deadline
     * covers.
     *
     * So the transaction runs inside [BoundedCall]. Read its header for what
     * that does and does not buy: the caller returns at the deadline every
     * time, and the abandoned work is NOT cancelled, because a synchronous
     * binder transaction cannot be. The cost of a timeout is one parked daemon
     * thread; the cost of not having this was a caller stalled indefinitely
     * inside system_server. Found in the owner's review of PR C, which named
     * the proof: a declared ATTEST_TIMEOUT_MS that nothing read.
     */
    private fun boundedTransact(
        binder: IBinder,
        code: Int,
        timeoutMs: Long,
        log: StringBuilder,
    ): Reply? {
        val outcome = BoundedCall.run("dfr-companion-tx-$code", timeoutMs) {
            transact(binder, code, log)
        }
        if (outcome.timedOut) {
            log.appendLine(
                "[DFR][COMPANION] TRANSACT_TIMEOUT code=$code after ${timeoutMs}ms;" +
                    " the remote handler did not reply (its thread stays parked)"
            )
            return null
        }
        if (outcome.failure != null) {
            log.appendLine(
                "[DFR][COMPANION] TRANSACT_THREW code=$code" +
                    " ${outcome.failure.javaClass.simpleName}"
            )
            return null
        }
        return outcome.value
    }

    private fun transact(binder: IBinder, code: Int, log: StringBuilder): Reply? {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        return try {
            data.writeInterfaceToken(CompanionProtocol.DESCRIPTOR)
            data.writeInt(CompanionProtocol.CONTRACT_VERSION)
            binder.transact(code, data, reply, 0)
            reply.readException()
            Reply(reply.readInt(), reply.readInt(), reply.readString() ?: "",
                reply.readString() ?: "")
        } catch (t: Throwable) {
            log.appendLine("[DFR][COMPANION] TRANSACT_FAILED code=$code ${t.javaClass.simpleName}")
            null
        } finally {
            reply.recycle()
            data.recycle()
        }
    }

    /** SHA-256 of a package's first signing certificate, or null on any failure. */
    private fun signingDigest(context: Context, pkg: String): String? = try {
        val info = context.packageManager
            .getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
        val signers = info.signingInfo?.apkContentsSigners
        if (signers.isNullOrEmpty()) {
            null
        } else {
            MessageDigest.getInstance("SHA-256").digest(signers[0].toByteArray())
                .joinToString("") { "%02x".format(it) }
        }
    } catch (t: Throwable) {
        null
    }
}
