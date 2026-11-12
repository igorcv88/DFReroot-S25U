package com.polygraphene.df.companion

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.TextView

/**
 * A diagnostics screen, not a control panel.
 *
 * It runs the same attestation the Binder transaction runs, so the owner can
 * see what the provider would report before DFReroot asks for it - and so a
 * refusal can be read here rather than inferred from the other app's log. The
 * grant itself is NOT requested from here: it is `ksud profile grant` from a
 * root shell, which is the owner's deliberate act, and a button that asked for
 * root authority on its own behalf would be a different kind of app.
 */
class MainActivity : Activity() {

    private lateinit var log: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        log = findViewById(R.id.log)
        findViewById<Button>(R.id.btnAttest).setOnClickListener { attest() }
    }

    private fun attest() {
        log.text = "running..."
        Thread {
            val nonce = Attestation.newNonce()
            val outcome = SuChannel.runAsRoot(
                Attestation.script(nonce), CompanionContract.ATTEST_TIMEOUT_MS
            )
            val verdict = AttestationReport.evaluate(outcome.stdout, nonce)
            val text = buildString {
                appendLine("exec_failed=${outcome.execFailed} timed_out=${outcome.timedOut}" +
                    " exit=${outcome.exit}")
                appendLine(verdict.signals())
                appendLine(verdict.reason)
                if (outcome.stderr.isNotBlank()) {
                    appendLine("--- stderr ---")
                    appendLine(outcome.stderr.trim())
                }
                appendLine("--- raw ---")
                append(outcome.stdout.trim())
            }
            runOnUiThread { log.text = text }
        }.start()
    }
}
