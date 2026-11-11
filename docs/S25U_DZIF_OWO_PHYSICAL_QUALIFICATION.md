# S25U DZIF/OWO physical qualification plan

**Nothing in this document has been performed.** It is the acceptance plan for a
later, separately authorised phase — not a runbook to start now, and not
evidence of anything.

Scope: the owner's SM-S938B, `S938BXXUCDZIF` on the OWO multi-CSC, with
ephemeral KernelSU root and **no Manager APK**, keeping Google Wallet working
and Play Integrity at BASIC + DEVICE + STRONG.

Companion to `docs/PHYSICAL_TESTING.md` (the general procedure) and
`docs/S25U_DZIF_OWO_COMPATIBILITY.md` (the evidence record, which is
authoritative about what is *proven*).

## Why this is split into four gates

The chain changes two independent things, and a single pass/fail verdict cannot
say which one broke what:

1. **persisting a certificate** in `android.uid.system`'s `pastSigs` — a
   durable edit to `/data/system/packages.xml` that survives reboots and is the
   step that can bootloop the device or disturb certification;
2. **running DirtyFrag** — ephemeral page-cache writes plus an LKM load, all of
   which a reboot undoes.

A prior incident reported an integrity investigation after `pastSigs` was
removed, with no causal conclusion. So Wallet and Integrity are re-checked
**between** those two steps. If they regress after the certificate and before
DirtyFrag has ever run, the cause is the `packages.xml` edit; if they regress
only afterwards, it is the kernel/daemon. Collapsing the two would make that
question permanently unanswerable.

## Preconditions

Every one of these must hold before anything is written.

| # | Precondition | How it is satisfied |
|---|---|---|
| 1 | PRs #88, #89 and `RMGLabs-Payloads` #28 reviewed and merged | owner's decision |
| 2 | A DFR managerless Secure Late-Load pair **built and audited** | `RMGLabs-Payloads` #28 makes it buildable; it does not build it |
| 3 | That pair's digest and size pinned into `S25U_DZIF_OWO`, with the asset bundled and byte-checked | a follow-up PR, not this one |
| 4 | Both APKs signed with the **same** key, and the release certificate the same one already trusted on the device | `release.yml` compares the two digests |
| 5 | `df_reroot.apk` embedded in DFInstaller byte-identical to the published APK | `tools/ci_build_audit.sh` |
| 6 | A verified `packages.xml` backup, stock firmware for this exact build, and a **tested** restore path | owner |
| 7 | `AUTO_ROOT=OFF`, Early Integrated Root disarmed, Apply Modules not attempted | `docs/AUTO_ROOT.md`, `docs/EARLY_ROOT.md` |
| 8 | `su -c id` confirmed to work **from DFInstaller's own uid** | PR #88 makes the answer legible; it does not answer it |

Precondition 3 is the one that currently blocks everything: the profile's daemon
is deliberately unpinned, so the chain refuses before the first write.

## Baseline (read-only, before any change)

Record, and keep, with the `boot_id` on every line:

- `ro.build.fingerprint`, `ro.boot.vbmeta.digest`, `ro.boot.verifiedbootstate`,
  `ro.boot.flash.locked`, `ro.boot.veritymode`, `getenforce`
- SHA-256 and size of `/data/adb/ksud` (expected `95b2cc36…`, 5797976 B)
- the **loaded** KernelSU module's identity — `lsmod` plus its build-id if it
  can be read at all. The 2026-11-11 capture reported
  `loaded_kernelsu_build_note_hex=UNREADABLE`, so this is an open item: the
  Wallet/Integrity state the owner reports is attributable to the *daemon*
  digest, not yet to a specific module build
- KernelSU root grants currently held (Termux, Swift Backup), via
  `ksud profile list-grants` — read-only
- installed DFReroot / DFInstaller versions, and whether `pastSigs` already
  carries the certificate (`InjectMain --check`)
- Wallet: a **functional** transaction test, not just app launch
- Play Integrity: BASIC / DEVICE / STRONG, naming the app and version used
- Play Protect certification status

**STRONG is not the same thing as Wallet working**, and a pass before the
injection does not predict acceptance after it. Record both.

Do not export the keybox, attestation keys, account credentials or any private
data into this record.

## Gate 1 — PMS and the certificate

Persisting the certificate is the only durable change in the whole plan.

1. `InjectMain --dump`, then `--check`, then `--dry-run`. Compare the dry-run's
   intended result against the dump.
2. Inject. `SafeWrite` preserves `uid/gid/mode/SELinux context` and takes a
   transactional backup; confirm the backup exists, is non-empty and parses.
3. Re-read `packages.xml` and confirm the certificate is present **once**, and
   that no other package's entry changed.
4. Soft reboot so PMS re-reads the file.
5. Confirm DFReroot installed as `android.uid.system` with exactly the expected
   certificate, and that **no root manager was installed**.

**Stop if:** the backup is missing, empty or unparsable; two certificates or an
unexpected `pastSigs` history appear; any other package's entry moved; the
device does not boot. On a boot failure, restore `packages.xml` from the backup
— do not reboot again to "try it once more" with a partially modified database.

## Gate 2 — Wallet and Integrity, before DirtyFrag has ever run

Re-run the full baseline set: Wallet functional test, BASIC/DEVICE/STRONG, Play
Protect certification.

This is the gate that isolates the `pastSigs` risk. **Do not proceed to Gate 3
until it is clean**, and do not run DirtyFrag "just to see" — that would destroy
the attribution this split exists to provide.

**Stop if:** Wallet fails a real transaction, STRONG is lost, or certification
changes. The recovery is `InjectMain --uninstall` and a reboot, then re-measure
to confirm the regression follows the certificate.

## Gate 3 — one manual DirtyFrag run

One attempt. No Auto Root, no Early Root, no retry in the same boot.

Acceptance, all in the **same boot**:

- `POST_ROOT_COMPLETE=PASS` in `/data/system/dfreroot-post-root`, with the
  current `boot_id`
- KernelSU version 32601 and UAPI 2 as the profile pins them
- `POST_ROOT_KSU_CONTROL=PASS` and `POST_ROOT_KSU_CONTROL_AFTER_RESTORE=PASS`
- `SELINUX_RESTORE=PASS`, and `/sys/fs/selinux/enforce` reads `1`
- `transport_fix=kdp-cred-1`, and `DFR_KO_LOADED=PASS` bound to the SHA-256 of
  the module this daemon actually embeds
- a root command that works under the managerless authorisation

`dfm3` and `stage2` are **not** success. A marker from another boot, or one that
names a different fix, is not success either.

**Stop if:** any gate refuses (that is the tool working — do not weaken it); a
panic or rollback occurs; the marker is absent or stale; SELinux is left
permissive. After any attempt that ends in an uncertain state: **full reboot**,
then investigate. Never a second trigger in the same boot.

## Gate 4 — managerless behaviour, then Wallet and Integrity again

1. Confirm root grants can be listed and changed **only** within the scope
   already authorised, with no Manager APK installed.
2. Confirm the RMG pair at `/data/adb/ksud` was not silently replaced — compare
   its digest against the baseline.
3. Confirm LSPosed / Zygisk Next and the owner's existing modules are unchanged.
4. Re-measure Wallet (functional) and BASIC/DEVICE/STRONG.

**Stop if:** any grant appears that was not requested; the RMG daemon was
overwritten; Wallet or STRONG regress.

## Out of scope, deliberately

- **Apply Modules / soft-reboot transport.** `System.loadLibrary("dfrsu")` in
  `system_server` has a known failure and needs real AVC and linker evidence;
  `docs/POSTFLASH_TRANSPORT_REVIEW.md` holds the detail. Qualify separately,
  after the manual chain is proven. Not with permissive SELinux or a generic
  relabel.
- **Early Integrated Root.** Physical proof still pending, and a prior run
  panicked in KernelSU's manager scanner. Stays disarmed.
- **Auto Root.** Off until Gates 1–4 all pass.
- **A ZTO-exclusive gate.** The property names are known
  (`ro.boot.sales_code`, `ro.csc.sales_code`, `ro.boot.carrierid`) but the
  profile is OWO-compatibility by decision; see the compatibility record.

## What a green CI run does not prove

It proves host logic, compilation and packaging. It proves nothing about
`system_server`, the Samsung linker, kernel stability under the LKM, Wallet
acceptance, or the durability of the `packages.xml` edit. Preserving Wallet and
STRONG is a **stop condition**, not a property static analysis can demonstrate.
