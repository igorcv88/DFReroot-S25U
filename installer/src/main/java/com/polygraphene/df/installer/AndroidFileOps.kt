package com.polygraphene.df.installer

import android.system.ErrnoException
import android.system.Os
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/**
 * The one place DFInstaller touches the filesystem. Everything that decides
 * *what* to do lives in [SafeWrite], which is pure Java and host-tested; this
 * class only carries those decisions out.
 *
 * Failures are translated to [IOException] rather than swallowed: SafeWrite
 * distinguishes "the direct overwrite was denied, use rename(2)" from "the
 * backup could not be written", and it can only do that if the difference
 * reaches it.
 */
class AndroidFileOps(
    /** Structural validation of a candidate packages.xml image. */
    private val parser: (ByteArray) -> Boolean
) : SafeWrite.FileOps {

    override fun exists(path: String): Boolean = File(path).exists()

    override fun stat(path: String): SafeWrite.Meta {
        try {
            val st = Os.stat(path)
            return SafeWrite.Meta(
                st.st_uid,
                st.st_gid,
                // Permission + setuid/setgid/sticky bits; the file-type bits in
                // st_mode are not settable by chmod(2) and must not be compared.
                st.st_mode and 0xFFF,
                st.st_size,
                readContext(path)
            )
        } catch (e: ErrnoException) {
            throw IOException("stat($path): $e", e)
        }
    }

    override fun read(path: String): ByteArray = try {
        File(path).readBytes()
    } catch (e: Exception) {
        throw IOException("read($path): $e", e)
    }

    override fun writeAndSync(path: String, data: ByteArray) {
        try {
            FileOutputStream(path).use { out ->
                out.write(data)
                out.flush()
                // Without this the bytes can still be in page cache when the
                // rename lands, which is exactly the window a backup must not
                // have: a crash there is how a zero-byte backup appears.
                out.fd.sync()
            }
        } catch (e: Exception) {
            throw IOException("write($path): $e", e)
        }
    }

    override fun chmod(path: String, mode: Int) {
        try {
            Os.chmod(path, mode)
        } catch (e: ErrnoException) {
            throw IOException("chmod($path, 0${Integer.toOctalString(mode)}): $e", e)
        }
    }

    override fun chown(path: String, uid: Int, gid: Int) {
        try {
            Os.chown(path, uid, gid)
        } catch (e: ErrnoException) {
            throw IOException("chown($path, $uid:$gid): $e", e)
        }
    }

    override fun rename(from: String, to: String) {
        try {
            Os.rename(from, to)
        } catch (e: ErrnoException) {
            throw IOException("rename($from, $to): $e", e)
        }
    }

    override fun deleteQuietly(path: String) {
        try { File(path).delete() } catch (_: Exception) { }
    }

    override fun restorecon(path: String): Boolean = exec("/system/bin/restorecon", path)

    override fun setContext(path: String, context: String): Boolean {
        // android.os.SELinux is @hide but present; app_process-as-root reaches it.
        try {
            val m = Class.forName("android.os.SELinux")
                .getMethod("setFileContext", String::class.java, String::class.java)
            val r = m.invoke(null, path, context)
            if (r == true) return true
        } catch (_: Throwable) {
            // fall through to the binary
        }
        return exec("/system/bin/chcon", context, path)
    }

    override fun parses(image: ByteArray): Boolean = try {
        parser(image)
    } catch (_: Throwable) {
        false
    }

    /**
     * SELinux label of `path`, or null when it cannot be read. Null means
     * "unknown", never "no label": SafeWrite treats the two differently.
     */
    private fun readContext(path: String): String? {
        try {
            val m = Class.forName("android.os.SELinux")
                .getMethod("getFileContext", String::class.java)
            val r = m.invoke(null, path) as? String
            if (!r.isNullOrBlank()) return r.trim().trim('\u0000')
        } catch (_: Throwable) {
            // fall through to ls -Z
        }
        return try {
            val p = Runtime.getRuntime().exec(arrayOf("/system/bin/ls", "-Z", path))
            val out = p.inputStream.bufferedReader().readText().trim()
            p.waitFor()
            val ctx = out.substringBefore(' ').trim()
            if (ctx.startsWith("u:object_r:")) ctx else null
        } catch (_: Exception) {
            null
        }
    }

    private fun exec(vararg argv: String): Boolean = try {
        Runtime.getRuntime().exec(argv).waitFor() == 0
    } catch (_: Exception) {
        false
    }
}
