package com.polygraphene.df.installer

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import org.w3c.dom.Document
import org.w3c.dom.Element

/**
 * packages.xml injector core (no Android Context needed).
 *
 * Mirrors TLPE EvilFactory.injectSystemSignatures(): put our own cert key
 * into each target <shared-user> pastSigs with flags="2".
 * Foreign pastSigs entries (e.g. another tool's key for the same
 * shared-user) are kept in the same single pastSigs block: PMS honors
 * only the first pastSigs block and drops the rest on its next rewrite,
 * so merging is required for coexistence.
 * Our key is written twice: the most-recent past cert is not counted as
 * a rotation candidate, hence x2.
 *
 * Format handling:
 *  - READ: ABX (Android 13+ on-device format, magic `ABX\0`) via [Abx],
 *    plain-text XML via JAXP fallback. No reflection except the single
 *    framework entry-point call inside [Abx] (app_process-as-root only).
 *  - WRITE: plain-text XML (what PMS itself wrote for a decade;
 *    resolvePullParser auto-detects it on next boot and rewrites ABX on the
 *    next writeSettings). Attribute values are preserved verbatim from the
 *    string layer; [Abx.guardDecimalAttrs] aborts instead of corrupting if an
 *    INT_HEX-typed value ever shows up.
 *  - cert `key=` is ALWAYS lowercase hex (PMS reads it with
 *    getAttributeBytesHex == hexStringToBytes). Base64 is rejected, so our
 *    key is normalized with [Abx.toHex] at every entry point.
 *
 * Backends sharing [buildPatchedXml]:
 *  - [injectDirect]: [InjectMain] running pre-install as root via app_process
 *    (direct java.io.File access). PRIMARY path.
 */
object PackagesXml {
    const val PACKAGES_XML = "/data/system/packages.xml"
    /** One definition, owned by [SafeWrite] (which creates and validates it). */
    @JvmField val BACKUP_SUFFIX: String = SafeWrite.BACKUP_SUFFIX
    const val FLAG_SHARED_USER_ID = "2"

    /** Parse either ABX or text into DOM. Returns doc; throws with reason. */
    fun parseToDom(raw: ByteArray): Document {
        if (Abx.isAbx(raw)) return Abx.parseToDom(raw)
        val dbf = DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = false
            isCoalescing = true
        }
        return dbf.newDocumentBuilder().parse(ByteArrayInputStream(raw)).also {
            it.documentElement.normalize()
        }
    }

    /** Structural sanity checks before any mutation. Throws on failure. */
    fun structuralChecks(doc: Document, targets: List<String>, log: StringBuilder) {
        val root = doc.documentElement?.tagName
            ?: throw RuntimeException("no root element")
        if (root != "packages") throw RuntimeException("unexpected root <$root>")
        val pkgs = doc.getElementsByTagName("package")
        log.appendLine("[*] <package> count=${pkgs.length}")
        if (pkgs.length < 20) throw RuntimeException("suspiciously few packages; refusing")
        val names = doc.getElementsByTagName("shared-user")
        val suNames = (0 until names.length).map {
            (names.item(it) as Element).getAttribute("name")
        }
        log.appendLine("[*] shared-users present: $suNames")
        for (t in targets) {
            if (t !in suNames) {
                throw RuntimeException(
                    "shared-user $t absent (not creating it: userId assignment " +
                        "must come from PMS itself)"
                )
            }
        }
    }

    /**
     * Global cert table in PMS encounter order (mirrors
     * PackageSignatures.readCertsListXml EXACTLY): single document-order
     * walk over every <cert>; inline `key=` null-pads to its index then
     * APPENDS (even if that overshoots a duplicate index); index-only
     * refs and index-less certs record nothing (PMS drops the latter with
     * a settings-problem warning).
     *
     * Why this matters: PMS writes with ONE global dedup table shared by
     * packages and shared-users (packages first). When our key bytes equal
     * an already-written cert (e.g. df_installer itself, same signing key),
     * PMS re-serializes our pastSigs as INDEX-ONLY refs on its next
     * writeSettings. A checker matching only inline `key=` then goes blind
     * while PMS itself still honors the rotation. Always resolve through
     * [effectiveKey], never by raw attribute.
     *
     * NOTE: `<cert index=N>` lives in this table's namespace; keyset
     * `<public-key identifier=M>` is a DIFFERENT namespace (KeySetManager
     * key IDs). A missing identifier proves nothing about an index.
     * Returns hex keys (lowercase) or null padding slots.
     */
    fun resolveKeyTable(doc: Document): MutableList<String?> {
        val table = mutableListOf<String?>()
        val all = doc.getElementsByTagName("cert")
        for (i in 0 until all.length) {
            val c = all.item(i) as? Element ?: continue
            val idx = c.getAttribute("index").toIntOrNull() ?: continue
            val key = c.getAttribute("key")
            if (key.isNotEmpty()) {
                if (!Abx.isHex(key)) continue // PMS would reject; don't trust
                while (table.size < idx) table.add(null)
                table.add(key.lowercase())
            }
        }
        return table
    }

    /**
     * Effective hex key of one <cert> element (inline `key=`, else the
     * encounter-order table at its index). Null when unresolvable
     * (dangling index, non-hex inline key) — PMS drops such certs too.
     */
    fun effectiveKey(cert: Element, table: List<String?>): String? {
        val inline = cert.getAttribute("key")
        if (inline.isNotEmpty()) {
            return if (Abx.isHex(inline)) inline.lowercase() else null
        }
        val idx = cert.getAttribute("index").toIntOrNull() ?: return null
        return if (idx >= 0 && idx < table.size) table[idx] else null
    }

    /**
     * Returns (keyHex, index) of our own <cert> from our <package> node, or
     * null. Resolves inline-key and index-only (table-resolved) refs alike —
     * the latter happens whenever another package with the same key bytes
     * was serialized earlier (same-signing-key apps dedup to one slot).
     */
    fun findInstalledKey(doc: Document, ownPkg: String): Pair<String, String>? {
        val table = resolveKeyTable(doc)
        val pkgs = doc.getElementsByTagName("package")
        for (i in 0 until pkgs.length) {
            val el = pkgs.item(i) as? Element ?: continue
            if (el.getAttribute("name") != ownPkg) continue
            val sigs = child(el, "sigs") ?: return null
            val cert = child(sigs, "cert") ?: return null
            val resolved = effectiveKey(cert, table) ?: return null
            return resolved to cert.getAttribute("index").ifEmpty { "0" }
        }
        return null
    }

    /**
     * Pure transform on an already-parsed DOM: returns patched TEXT XML bytes.
     * [ourKeyHex] must be lowercase hex (enforced).
     */
    fun buildPatchedXml(
        doc: Document,
        ourKeyHex: String,
        targets: List<String>,
        log: StringBuilder
    ): ByteArray {
        val key = ourKeyHex.lowercase()
        require(Abx.isHex(key) && key.length > 100) { "our cert key is not plausible hex" }
        Abx.guardDecimalAttrs(doc)

        // Safety: refuse when our key is already present (uninstall first).
        // Checked before touching anything so a partial multi-target write
        // can never happen.
        for (t in targets) {
            if (isInjected(doc, t, key)) {
                throw RuntimeException(
                    "already injected into $t (uninstall first to re-inject)"
                )
            }
        }

        // fresh index: after every existing index AND the encounter table
        // (PMS appends inline-key certs at max(size, index); stay past both).
        var maxIdx = -1
        var reuse: String? = null
        val allCerts = doc.getElementsByTagName("cert")
        for (i in 0 until allCerts.length) {
            val c = allCerts.item(i) as? Element ?: continue
            if (c.getAttribute("key").lowercase() == key && c.hasAttribute("index")) {
                reuse = c.getAttribute("index")
                break
            }
            c.getAttribute("index").toIntOrNull()?.let { maxIdx = maxOf(maxIdx, it) }
        }
        // NOTE: index-only refs share the same global table; take the max of
        // both so a padded table can never collide with our new entry.
        val table = resolveKeyTable(doc)
        val freshIndex = reuse ?: (maxOf(maxIdx + 1, table.size)).toString()
        if (reuse != null) log.appendLine("[+] reusing existing index $reuse for our key")
        else log.appendLine("[+] fresh cert index=$freshIndex")

        var changed = 0
        val users = doc.getElementsByTagName("shared-user")
        for (t in targets) {
            var node: Element? = null
            for (i in 0 until users.length) {
                val el = users.item(i) as? Element ?: continue
                if (el.getAttribute("name") == t) { node = el; break }
            }
            if (node == null) {
                log.appendLine("[!] shared-user $t not found, skipping")
                continue
            }
            log.appendLine("[+] injecting into $t userId=${node.getAttribute("userId")}")
            var sigs = child(node, "sigs")
            if (sigs == null) {
                sigs = doc.createElement("sigs")
                sigs.setAttribute("count", "1")
                node.appendChild(sigs)
            }
            val past = doc.createElement("pastSigs")
            var kept = 0
            for (old in children(sigs, "pastSigs")) {
                for (c in children(old, "cert")) {
                    past.appendChild(c)
                    kept++
                }
                sigs.removeChild(old)
            }
            if (kept > 0) log.appendLine("[+] keeping $kept foreign cert(s) in $t")
            repeat(2) {
                val c = doc.createElement("cert")
                c.setAttribute("index", freshIndex)
                c.setAttribute("key", key)
                c.setAttribute("flags", FLAG_SHARED_USER_ID)
                past.appendChild(c)
            }
            past.setAttribute("count", (kept + 2).toString())
            sigs.appendChild(past)
            changed++
        }
        if (changed == 0) throw RuntimeException("nothing changed (no target shared-user found)")

        val out = ByteArrayOutputStream()
        TransformerFactory.newInstance().newTransformer()
            .transform(DOMSource(doc), StreamResult(out))
        return out.toByteArray()
    }

    /**
     * True when [target] shared-user holds our key in any pastSigs cert.
     * Resolves through the encounter-order table, so PMS-normalized
     * (index-only) pastSigs are recognized too.
     */
    fun isInjected(doc: Document, target: String, ourKeyHex: String): Boolean {
        val key = ourKeyHex.lowercase()
        val table = resolveKeyTable(doc)
        val users = doc.getElementsByTagName("shared-user")
        for (i in 0 until users.length) {
            val el = users.item(i) as? Element ?: continue
            if (el.getAttribute("name") != target) continue
            val sigs = child(el, "sigs") ?: return false
            for (past in children(sigs, "pastSigs")) {
                if (children(past, "cert").any { effectiveKey(it, table) == key })
                    return true
            }
            return false
        }
        return false
    }

    /**
     * Removes only pastSigs certs carrying our key (foreign entries are
     * left alone). Returns true when anything was removed.
     */
    fun removeOurKeys(
        doc: Document,
        targets: List<String>,
        ourKeyHex: String,
        log: StringBuilder
    ): Boolean {
        val key = ourKeyHex.lowercase()
        var removed = false
        // Table must see the whole document (PMS-normalized index-only
        // refs point at inline keys elsewhere, e.g. our own package).
        // Built once: removals below only delete our own certs, which
        // never serve as another ref's resolution target here.
        val table = resolveKeyTable(doc)
        val users = doc.getElementsByTagName("shared-user")
        for (t in targets) {
            var node: Element? = null
            for (i in 0 until users.length) {
                val el = users.item(i) as? Element ?: continue
                if (el.getAttribute("name") == t) { node = el; break }
            }
            if (node == null) {
                log.appendLine("[!] shared-user $t not found, skipping")
                continue
            }
            val sigs = child(node, "sigs") ?: continue
            for (past in children(sigs, "pastSigs").toList()) {
                val certs = children(past, "cert")
                val ours = certs.filter { effectiveKey(it, table) == key }
                if (ours.isEmpty()) continue
                if (ours.size == certs.size) {
                    sigs.removeChild(past)
                    log.appendLine("[+] removed our pastSigs from $t")
                } else {
                    ours.forEach { past.removeChild(it) }
                    past.setAttribute("count", children(past, "cert").size.toString())
                    log.appendLine("[+] removed ${ours.size} our cert(s) from $t pastSigs")
                }
                removed = true
            }
        }
        return removed
    }

    /** Re-parse written bytes and confirm our pastSigs landed intact. */
    fun verifyPatched(patched: ByteArray, targets: List<String>, ourKeyHex: String): String {
        val key = ourKeyHex.lowercase()
        val doc = parseToDom(patched)
        val table = resolveKeyTable(doc)
        val log = StringBuilder()
        val users = doc.getElementsByTagName("shared-user")
        for (t in targets) {
            var ok = false
            var foreign = 0
            for (i in 0 until users.length) {
                val el = users.item(i) as? Element ?: continue
                if (el.getAttribute("name") != t) continue
                val past = child(child(el, "sigs") ?: continue, "pastSigs") ?: continue
                val certs = children(past, "cert")
                val ours = certs.count {
                    effectiveKey(it, table) == key &&
                        it.getAttribute("flags") == FLAG_SHARED_USER_ID
                }
                foreign = certs.size - ours
                ok = ours >= 2 && past.getAttribute("count") == certs.size.toString()
            }
            log.appendLine("[verify] $t pastSigs intact: $ok (foreign certs kept: $foreign)")
            if (!ok) throw RuntimeException("verify FAILED for $t")
        }
        return log.toString()
    }

    /** Direct backend (app_process as root, pre-install). */
    fun injectDirect(
        xmlPath: String,
        ourKeyHex: String,
        targets: List<String>,
        log: StringBuilder,
        dryRun: Boolean = false
    ): Int {
        val raw = java.io.File(xmlPath).readBytes()
        log.appendLine("[*] read ${raw.size} bytes from $xmlPath")
        val doc = parseToDom(raw)
        structuralChecks(doc, targets, log)
        val patched = buildPatchedXml(doc, ourKeyHex, targets, log)
        log.append(verifyPatched(patched, targets, ourKeyHex.lowercase()))
        if (dryRun) {
            log.appendLine("[*] dry-run: NOT writing")
            return patched.size
        }
        writeBack(xmlPath, patched, log)
        return patched.size
    }

    /** Uninstall backend (app_process as root): removes only our key. */
    fun uninstallDirect(
        xmlPath: String,
        ourKeyHex: String,
        targets: List<String>,
        log: StringBuilder
    ): Int {
        val key = ourKeyHex.lowercase()
        require(Abx.isHex(key) && key.length > 100) { "our cert key is not plausible hex" }
        val raw = java.io.File(xmlPath).readBytes()
        log.appendLine("[*] read ${raw.size} bytes from $xmlPath")
        val doc = parseToDom(raw)
        structuralChecks(doc, targets, log)
        Abx.guardDecimalAttrs(doc)
        if (!removeOurKeys(doc, targets, key, log)) {
            log.appendLine("[*] our key not present: already clean, nothing to write")
            return raw.size
        }
        val out = ByteArrayOutputStream()
        TransformerFactory.newInstance().newTransformer()
            .transform(DOMSource(doc), StreamResult(out))
        val patched = out.toByteArray()
        log.append(verifyAbsent(patched, targets, key))
        writeBack(xmlPath, patched, log)
        return patched.size
    }

    /** Re-parse written bytes and confirm our key is gone from targets. */
    fun verifyAbsent(patched: ByteArray, targets: List<String>, ourKeyHex: String): String {
        val doc = parseToDom(patched)
        val log = StringBuilder()
        for (t in targets) {
            val gone = !isInjected(doc, t, ourKeyHex)
            log.appendLine("[verify] $t our key removed: $gone")
            if (!gone) throw RuntimeException("verify FAILED for $t (key still present)")
        }
        return log.toString()
    }

    /** Serialize a DOM back to text XML bytes (used by the round-trip check). */
    private fun domToText(doc: Document): ByteArray {
        val out = ByteArrayOutputStream()
        TransformerFactory.newInstance().newTransformer()
            .transform(DOMSource(doc), StreamResult(out))
        return out.toByteArray()
    }

    /**
     * Gate H - read-only installer/packages.xml compatibility diagnostic for
     * Android 17 Samsung. Zero writes. Emits `[DFR][INSTALLER]` gate lines:
     *   PACKAGES_FORMAT, PACKAGES_PARSE, ANDROID_UID_SYSTEM_FOUND,
     *   CERT_TABLE_PARSE, ROUND_TRIP_VALID, METADATA_CAPTURED
     * plus owner/group/mode/SELinux label and per-target pastSigs shape, so the
     * Samsung Android 17 structure can be confirmed understood by the parser.
     */
    fun diagnose(raw: ByteArray, xmlPath: String, targets: List<String>, log: StringBuilder) {
        log.appendLine("[DFR][INSTALLER] ENTER gate H")
        val format = if (Abx.isAbx(raw)) "ABX" else "TEXT"
        log.appendLine("[DFR][INSTALLER] PACKAGES_FORMAT=$format")

        // file metadata (owner/group/mode/SELinux)
        var metaOk = false
        try {
            val st = android.system.Os.stat(xmlPath)
            log.appendLine("[DFR][INSTALLER] owner_uid=${st.st_uid} group_gid=${st.st_gid} " +
                "mode=0%o".format(st.st_mode and 0x1FF))
            val ctx = try {
                val p = Runtime.getRuntime().exec(arrayOf("/system/bin/ls", "-Z", xmlPath))
                p.inputStream.bufferedReader().readText().trim().substringBefore(' ')
            } catch (e: Exception) { "UNKNOWN($e)" }
            log.appendLine("[DFR][INSTALLER] selinux_label=$ctx")
            metaOk = true
        } catch (e: Exception) {
            log.appendLine("[DFR][INSTALLER] metadata FAIL: $e")
        }
        log.appendLine("[DFR][INSTALLER] METADATA_CAPTURED=${if (metaOk) "PASS" else "FAIL"}")

        val doc = try {
            parseToDom(raw).also { log.appendLine("[DFR][INSTALLER] PACKAGES_PARSE=PASS (parser=${if (format == "ABX") "Abx.resolvePullParser" else "JAXP"})") }
        } catch (e: Exception) {
            log.appendLine("[DFR][INSTALLER] PACKAGES_PARSE=FAIL: $e")
            return
        }

        val sharedUsers = doc.getElementsByTagName("shared-user")
        val names = (0 until sharedUsers.length).map { (sharedUsers.item(it) as Element).getAttribute("name") }
        log.appendLine("[DFR][INSTALLER] shared_users=$names")
        val hasSystem = names.contains("android.uid.system")
        log.appendLine("[DFR][INSTALLER] ANDROID_UID_SYSTEM_FOUND=${if (hasSystem) "PASS" else "FAIL"}")

        val table = try {
            resolveKeyTable(doc).also {
                log.appendLine("[DFR][INSTALLER] CERT_TABLE_PARSE=PASS (size=${it.size})")
            }
        } catch (e: Exception) {
            log.appendLine("[DFR][INSTALLER] CERT_TABLE_PARSE=FAIL: $e")
            mutableListOf<String?>()
        }

        for (t in targets) {
            val su = (0 until sharedUsers.length)
                .map { sharedUsers.item(it) as Element }
                .firstOrNull { it.getAttribute("name") == t } ?: continue
            val sigs = child(su, "sigs")
            val pastCount = if (sigs != null) children(sigs, "pastSigs").sumOf { children(it, "cert").size } else 0
            log.appendLine("[DFR][INSTALLER] target=$t pastSigs_certs=$pastCount")
        }

        // serialization round-trip: DOM -> text -> DOM, compare structure.
        var rtOk = false
        try {
            val text = domToText(doc)
            val doc2 = parseToDom(text)
            val p1 = doc.getElementsByTagName("package").length
            val p2 = doc2.getElementsByTagName("package").length
            val c1 = doc.getElementsByTagName("cert").length
            val c2 = doc2.getElementsByTagName("cert").length
            val s1 = doc.getElementsByTagName("shared-user").length
            val s2 = doc2.getElementsByTagName("shared-user").length
            rtOk = (p1 == p2 && c1 == c2 && s1 == s2)
            log.appendLine("[DFR][INSTALLER] round_trip packages=$p1/$p2 certs=$c1/$c2 shared_users=$s1/$s2")
        } catch (e: Exception) {
            log.appendLine("[DFR][INSTALLER] round_trip FAIL: $e")
        }
        log.appendLine("[DFR][INSTALLER] ROUND_TRIP_VALID=${if (rtOk) "PASS" else "FAIL"}")
        /*
         * Backup state, read-only. The v2.0.2-zzic run left a ZERO-BYTE
         * .bak-df-installer behind, which the old code would have reported as
         * "backup already exists, keeping" - so the diagnostic now says what is
         * actually in it, before anyone relies on it to roll back.
         */
        val backup = try {
            SafeWrite.describeBackup(androidOps(), xmlPath)
        } catch (e: Throwable) {
            "BACKUP_PRESENT=UNKNOWN ($e)"
        }
        log.appendLine("[DFR][INSTALLER] $backup")
        val backupOk = !backup.contains("BACKUP_VALID=FAIL")
        log.appendLine("[DFR][INSTALLER] ${if (hasSystem && rtOk && backupOk) "PASS" else "UNKNOWN"} gate H")
    }

    /**
     * Transactional replacement of packages.xml, shared by the inject and
     * uninstall backends.
     *
     * The logic lives in [SafeWrite] (pure Java, host-tested against an
     * in-memory filesystem); this method only supplies the Android filesystem
     * and the parser [SafeWrite] validates backups with.
     *
     * Two v2.0.2-zzic field defects are fixed there and must not come back
     * here: the final file's uid/gid/mode/label now come from a stat of the
     * ORIGINAL taken before any write - never from the freshly created backup,
     * which is root:root 0644 - and a backup that exists but is empty or
     * truncated is a hard failure instead of a reassuring log line.
     */
    private fun writeBack(xmlPath: String, patched: ByteArray, log: StringBuilder) {
        SafeWrite.writeBack(androidOps(), xmlPath, patched, log)
    }

    /** Filesystem surface for [SafeWrite], with our own packages.xml validator. */
    private fun androidOps(): SafeWrite.FileOps = AndroidFileOps { image ->
        // "Parses" means more than well-formed XML: a rollback image has to be
        // a packages.xml, so require the document element and at least one
        // <package> or <shared-user> in it.
        val doc = parseToDom(image)
        val root = doc.documentElement
        root != null && root.tagName == "packages" &&
            (doc.getElementsByTagName("package").length > 0 ||
                doc.getElementsByTagName("shared-user").length > 0)
    }

    private fun child(el: Element, tag: String): Element? {
        val nl = el.childNodes
        for (i in 0 until nl.length) {
            val n = nl.item(i)
            if (n is Element && n.tagName == tag) return n
        }
        return null
    }

    private fun children(el: Element, tag: String): List<Element> {
        val out = mutableListOf<Element>()
        val nl = el.childNodes
        for (i in 0 until nl.length) {
            val n = nl.item(i)
            if (n is Element && n.tagName == tag) out.add(n)
        }
        return out
    }
}
