# Post-flash transport review — 2026-10-18

Baseline: `3b70be723ed13874b19726a0485028f7ee99fb7d`.

PR #83 merged at a9ed5f7; #84 merged at 3b70be7. PR #85 is still open at
daee27d and explicitly does not implement a transport fix. Its review finding
about flattened boot-health outcomes has a correction on that branch, not in
this main. Do not claim it has landed by reading its documentation.

## Current transport boundary

RootTransport.prepare stages and hashes the pinned daemon, then calls
System.loadLibrary("dfrsu"). The DFR application runs in system_server.
StageHop already documents why libexp must instead load in network_stack.
Thus library packaging/discoverability and successful executable mapping are
different gates. A readable file or a changed SELinux label proves neither.

The native transport's host tests start after library loading and fake the
privileged KernelSU calls. Their PASS does not reproduce the Samsung linker
policy and cannot prove that the application reaches nativeRunRootShell.
Without the post-flash policy/AVCs and a physical library-load test, no safe
transport correction is claimed. No permissive policy, app-data relabeling,
system UID grant, native-helper execution from /data, or execution override
was added in this change.

Manual root and POST_ROOT_COMPLETE can still be tested separately from Apply
Modules: the latter depends on this transport. Do not replay the exploit to
recover a post-root library refusal, and do not treat the root refusal of an
unrecognized OWO fingerprint as a bootstrap defect.

## Host changes and evidence

The descriptor regression used /proc/$$/fd. In the validation environment $$
named a PID absent from that procfs, so the positive controls failed. Inspecting
/proc/self/fd in the executed process fixes the observation. The descriptor
quarantine, grant gate, driver-fd exception and descriptor-range mutation tests
still kill all four mutations. Device execution and SELinux behavior are
unchanged.

A synthetic fingerprint changing only OXM to OWO, while preserving the DZIF
AP/kernel fields, is refused by the native target classifier. This is a
negative fixture, not a prediction of the real OWO fingerprint. The owner subsequently supplied the exact OWO/ZTO fingerprint and vbmeta
digest b9e6d6cf…014c7. Its AP/kernel release/build timestamp match historical
metadata, but binary compatibility and the new AVB chain are still pending.
The runtime profile remains the historical OXM profile; no execution gate
was widened.

The Payloads ko-loaded reader writes ko_sha256 but previously ignored it when
reading. The proposed strict parser requires this daemon's embedded module
digest and rejects duplicate/unknown fields. No new daemon hash is pinned in
this DFR change, and the Early Root authorization list is untouched.

## Physical sequence and recovery

1. Collect checkpoint A before root: real fingerprint, CSC, kernel, vendor,
   vbmeta, boot ID, Play Protect, separate integrity verdicts and Key Attestation.
2. Review a new exact profile and artifact pair against that capture. Until
   then, OWO execution remains refused. An APK build alone is not permission.
3. Run one approved manual root attempt, then verify same-boot post-root status
   and live SELinux Enforcing. Record the daemon and loaded module identities.
4. Apply modules only after the library mapping and root transport are physically
   proven. A refusal leaves this stage unvalidated; it does not justify another
   exploit attempt.
5. Use a full reboot to clear kernel/mount state after a partial module mount.
   A framework/soft restart retains the kernel boot ID and is not a reset of
   the exploit budget. Do not arm Early Root until its exact pair is authorized.

No fastboot unlock, patched boot flash or AVB/verity disabling is part of this
procedure. Automatic device recovery is not implemented by these host changes.

## Incremental build dependency

CMake omitted the DZIF DirtyFrag module from exp.c OBJECT_DEPENDS although exp.c
embeds it through .incbin. An incremental build could therefore retain the old
embedded bytes after only that module changed. The dependency is now present;
the host contract test inventories every embedded module and requires its
explicit dependency. The non-publishing signed APK build verifies the full
package/asset/signing chain; it does not authorize OWO execution.

## Signed APK review result

Run 39163451470 passed at source 72e3cd26e7926992c2602beae10c5b1e64b0e0e8.
Both APKs have the existing signer e5d68192109e8c65f4d433cb4beda0a47c40e7b73c9e48832673b24a6b0b9257.
DFInstaller's embedded DFR APK was also independently compared byte for byte.

- df_reroot.apk SHA-256: 7d0ae1d3028acb05bd9b5cd4f7749f17500d0796752882f738fefc8c4ba75e58
- df_installer.apk SHA-256: c0991be9dc4e8ab319b9b019ad91be1e13ac05c9b83883f444a11cbc112c9d66

This review package retains the historical 89eb37bd… daemon. The corrected
0381b429… daemon is a separate, fully built/audited CI artifact from Payloads
run 39162758466, not an implicit APK repin. Both the OWO binary compatibility
review and the explicit selection/integration of its pair remain pending.
The native transport mapping defect remains unresolved. These dev APKs are
validation outputs, not an installation instruction or release-ready builds.
