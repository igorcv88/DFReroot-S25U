# DFReroot S25U / ZZIC — handoff

**Where to pick up.** This file is the moving part: current state, what is
blocked, what closes it. It is the only one of the three that is expected to go
stale, so trust it least and re-derive from the audits when in doubt.

- **`AGENTS.md`** (symlinked as `CLAUDE.md`) — the standing rules. Read it
  first, before changing anything. It holds nothing version-specific.
- **`docs/S25U_ZZIC_COMPATIBILITY.md`** — the authoritative gate matrix and
  evidence record. If this file and that one disagree about what is *proven*,
  that one wins.

**State is POST-G1-BUILD / PRE-SECOND-PHYSICAL-TEST.** It reflects the first
hardware execution of the chain (`v2.0.2-zzic`) plus the exact ZZIC helper and
ksud integration that follow it. The next signed build is `2.0.4-zzic`
(versionCode 7): G1 is closed offline, while G2/G4 and the downstream chain still
need one same-boot hardware run.

Three things this file used to say are no longer true and must not be
reintroduced: the `scheduleReceiver` overload shape is **not** unknown,
`crash_dump64`'s hash **has** been captured, and Gate H is **not** untested.

## Target

```
Samsung Galaxy S25 Ultra, SM-S938B, codename pa3q
Android 17 / SDK 37, One UI 9 Beta 3, firmware S938BXXUCZZIC
kernel 6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k, aarch64, 4096-byte pages
```

The userspace Android release (17) and the Android common kernel family
(android15) are independent values; the kernel release string parsing to
`android15` is **kernel-family** module selection, not identity.

## What the code does

Upstream DFReroot chain, unchanged for every device that is not this exact
firmware: temp root → DFInstaller injects the signing key into
`/data/system/packages.xml` → soft reboot → DFReroot installs as
`android.uid.system` → it hops `system_server` → `com.android.networkstack.process`
(which can `dlopen` and holds `CAP_NET_ADMIN`) → Dirty Frag page-cache writes to
`crash_dump64`, the vendor file, `libc.so`, `libc++.so` → LKM sets SELinux
permissive → `ksud`.

Added for this target: a fail-closed profile (`app/src/main/jni/target_profile.{h,c}`,
`DFR_PROFILE_ZZIC`) plus gates in `app/src/main/jni/exp.c`, boundary-tagged
`[DFR][*]` diagnostics, and offline audit tools under `tools/`.

## The rules

They moved to **`AGENTS.md`** so they stop being restated (and drifting) once
per handoff. Do not edit them here; edit them there. In short, and not as a
substitute for reading it:

1. Fail-closed. Missing evidence is a refusal, never a pass.
2. Identity comparison is exact and case-sensitive; a partial match is a hard
   `MISMATCH`.
3. Every page-cache stage runs both gates — a gate enforced in one of three
   entry points is not enforced.
4. Proof may change form when an artefact is unreadable; it may not be skipped.
5. Artefact hashes are scoped to the stage that writes them. Never widen a mask.
6. A boolean is not evidence: `ko_zzic_verified` is bound to the bundled bytes.
7. No execution override, under any name.
8. DFInstaller's metadata source of truth is the original file, stat'd before
   any write; backups are transactional and a bad one is fatal.
9. The C profile and `tools/zzic_profile.json` must agree, and the JSON must
   agree with itself.

## Current state

The old Gate-G refusal is gone for the exact ZZIC target. The bundled
`dirtyfrag-android15-6.6-S938BXXUCZZIC.ko` is selected only after exact target
classification, is re-hashed before the first write, and is bound in the profile
to SHA-256
`b941d3234ad57235083f5778ff33c52cd4691aaf620d98be43fbaedc74ae3017`.
Its strict audit is `MODVERSION_COVERAGE = COMPLETE (5/5)` and
`MODULE_VS_ZZIC_KERNEL = COMPATIBLE`; this closes G1 offline.

Everything before that boundary remains proven from the first physical run:
Gate A, Gate B (kernel / `crash_dump64` / vendor provenance), Gate C
(`scheduleReceiver/12`), Gate D (`network_stack` + `libexp.so`) and Gate H.
Gate F is also PASS offline.

What is *not* promoted by G1: G2 runtime symbol discovery, G4 write safety, the
downstream libc/libc++ stages, the stage2/ksud handoff, and full Gate I. Exact
ZZIC BTF supports G3's layout assumption (`enforcing` at offset 0), but runtime
confirmation remains pending. Automatic restoration of SELinux to `Enforcing`
after KernelSU readiness is still open and must not be assumed.

The next run is therefore a real hardware experiment rather than a fail-closed
evidence-only refusal. If it passes the module policy it may reach `patch #1`
and, if the helper executes, may set SELinux permissive.

## Pending work, in order

### 0. Collect everything the device can supply, in one read-only pass

```sh
# in Termux, or: adb shell sh /data/local/tmp/zzic_collect.sh
sh tools/zzic_collect.sh > zzic-identity.txt 2>&1
```

Writes nothing; no root needed except for the `/proc/kallsyms` section. It prints
every field `dfr_classify_target()` compares, the `crash_dump64` hash, `boot_id`
and the network_stack process state, and says which of the remaining blockers a
device capture cannot close.

**Check the identity block first.** All twelve fields are compared exactly and
case-sensitively; one difference classifies the real device `MISMATCH` and refuses
the whole chain. `kernel_version` is a build timestamp
(`#1 SMP PREEMPT Wed Sep 16 14:21:43 UTC 2026`) and is the field most likely to
have moved. If the device disagrees with the profile, **the profile is wrong** —
correct it from the observed values, never the reverse.

`tools/profile_binding_audit.py` fails CI if the collector stops printing a field
the runtime gate compares.

### 1. ~~`crash_dump64` SHA-256~~ — CLOSED

Captured from the device and pinned in `app/src/main/jni/target_profile.c` and
`tools/zzic_profile.json` (both the top-level field and the `targets[]` entry;
CI now fails if those two disagree with each other, not just if C and JSON do):

```
9249d66445837c52322c2c86ee62efa64e49a7c1b72084c1ce98f72c12a1151f
```

`crash_dump64` IS readable from the domain the chain runs in, so it stays a
direct runtime SHA-256 check. The vendor ELF is not — see invariant 3b.

### 2. ~~A Gate-G validated kernel module~~ — G1 CLOSED

The exact helper is now bundled separately from the generic android15/6.6 image:

```text
app/src/main/jni/dirtyfrag-android15-6.6-S938BXXUCZZIC.ko
sha256  b941d3234ad57235083f5778ff33c52cd4691aaf620d98be43fbaedc74ae3017
size    6592 bytes
vermagic 6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k SMP preempt mod_unload modversions aarch64
MODVERSION_COVERAGE = COMPLETE (5/5)
MODULE_VS_ZZIC_KERNEL = COMPATIBLE
```

The five required entries are `module_layout`, `__stack_chk_fail`, `_printk`,
`memset` and `sprint_symbol`. Their CRCs come from the provenance-bound
stock-module witness in `evidence/zzic/gate-g/`. The build workflow repairs the
DDK's intentionally disabled modpost export matching before building; do not
replace that with a hand-built four-entry table, because `module_layout` is
checked by the kernel even though it is not an undefined import.

The ZZIC image is deliberately absent from `ko_images[]`. A generic
android15/6.6 device still gets the untouched generic module; only
`DFR_TARGET_S25U_ZZIC` may select the exact image. The binding audit guards that
separation and verifies the bundled bytes and CRC table.

Remaining Gate-G boundaries:

- G2 — runtime discovery of `kallsyms_lookup_name` and `selinux_state`:
  **RUNTIME UNVERIFIED**.
- G3 — layout: exact BTF supports `enforcing` at offset 0; runtime confirmation
  pending.
- G4 — the write itself: **UNVERIFIED**.

A real helper load is not a clean G1 probe because its init path performs G4.
The next signed run intentionally collects that hardware evidence; treat it as a
single-run experiment, not as a retry loop.

### 3. ~~`scheduleReceiver` overload shape~~ — CLOSED

Android 17 / One UI 9 exposes the same 12-parameter overload `StageHop` already
invokes, observed physically:

```
[DFR][AMS] scheduleReceiver/12 params=[Intent, ActivityInfo, CompatibilityInfo,
    int, String, Bundle, boolean, boolean, int, int, int, String]
```

`getProcessRecordLocked` is **absent** on this build; the `mProcessNames`
fallback is what resolves the ProcessRecord, and `mOnewayThread` is the correct
thread field. None of that is a blocker, and the log now says so explicitly
(`PROCESS_LOOKUP_PRIMARY=UNAVAILABLE`, `PROCESS_LOOKUP_FALLBACK=mProcessNames`,
`PROCESS_LOOKUP=PASS`) instead of leaving a bare `UNKNOWN`.

The rule that produced this outcome still stands for the next firmware: **do not
guess a fallback overload.** Invoking an unknown shape with fabricated arguments
runs inside `system_server`. Wire a new shape only from an observed
`[DFR][AMS] scheduleReceiver/<n> params=[...]` line.

### 4. Remaining runtime captures

```sh
adb logcat -c && adb logcat -s DFReroot DirtyFrag | tee zzic-run.log
grep '\[DFR\]' zzic-run.log
adb shell cat /proc/sys/kernel/random/boot_id
```

| Needed | Boundary that emits it | State |
|---|---|---|
| AMS / ProcessRecord / IApplicationThread shapes (Gate C) | `[DFR][AMS] *` | captured |
| network_stack identity (Gate D) | `[DFR][PROCESS] REMOTE_COMPONENT_REACHED` | captured |
| `libexp.so` actually loaded | `[DFR][PROCESS] LIBEXP_LOADED` | captured |
| packages.xml semantics (Gate H) | `InjectMain --diag-zzic` → `[DFR][INSTALLER] *` | captured |
| vendor provenance chain | `[DFR][USERSPACE] VENDOR_PROV *` | new in 2.0.3, needs one run |
| SELinux / seccomp viability for XFRM and native load | `[DFR][PROCESS]` capability + seccomp fields, plus denials in `dmesg`/`logcat` | partial |

Still needing device evidence downstream of G1: the `vendor_modprobe` SELinux
domain and its exec transition, the seccomp verdict on the native syscalls,
mount-namespace behaviour, the staged-ksud rename from `/data/system`, any
Samsung DEFEX-style restriction, KernelSU readiness, and restoration of SELinux
to `Enforcing`.

### 5. ~~Dead pins: the four `network_stack_*` fields~~ — CLOSED

All four are now compared at run time and tied to the pins statically.
`network_stack_process`, `network_stack_uid` and `network_stack_context` were
already compared in `Diagnostics.kt`/`StageHop.kt` — but against Kotlin constants,
not against the profiles, so the pins themselves were dead and a third copy of
each value could drift unnoticed. `network_stack_cap_eff` was compared nowhere at
all; it now emits `NETWORK_STACK_CAP_EFF=PASS/FAIL/SKIP/UNKNOWN`, with an
unreadable `CapEff` reported `UNKNOWN` rather than counted as agreement.

`tools/profile_binding_audit.py` ties each Kotlin constant to both profiles and
fails on drift, on a removed constant, and on a removed emit — the static-guard
pattern AGENTS.md §5 prescribes for Kotlin that needs an Android runtime. Each of
those was verified by sabotage.

Two more signals were fixed in the same pass:

- `NATIVE_LIBRARY_DISCOVERABLE` is gone. It could never read PASS on any device:
  the APK ships `lib/arm64-v8a/libexp.so` Stored with
  `android:extractNativeLibs="false"`, so nothing is written to
  `nativeLibraryDir`. It was observed `UNKNOWN` next to `LIBEXP_LOADED=PASS` in
  the same process. Replaced by `NATIVE_PAYLOAD_PACKAGED` (the APK zip entry,
  which can actually pass) and `NATIVE_PAYLOAD_EXTRACTED` (the fact, with `NO`
  stated as expected). `LIBEXP_LOADED` remains the only proof `dlopen` succeeded.
  The audit fails if the old signal comes back.
- `MainActivity.append()` now mirrors every line to logcat before touching the
  UI. Until now `runAll done res=`, the remote-boundary block and the CONTROLLER
  binder receipt existed only on screen, which made every "wait for X in logcat"
  instruction in these docs impossible to follow.

#### Original note

`network_stack_process`, `network_stack_uid` (1073), `network_stack_context` and
`network_stack_cap_eff` (`0x800003c00`) are declared in `target_profile.h`, pinned
in `target_profile.c` and in `tools/zzic_profile.json`, and **not one of the four
is read anywhere**. The device reported `CapEff=0000000800003c00`, matching the
pin — but a value nobody compares is not a check, it is a profile advertising a
boundary it never enforces. That is the same defect the code itself calls out for
`android_release`.

This is not a one-line cleanup either way:

- **To enforce them**, the runtime has to *observe* the real process's uid,
  SELinux context and `CapEff` at the Gate D boundary and feed them to a
  `dfr_network_stack_eval()` alongside the pinned values, with a negative case per
  field — the shape `dfr_vendor_provenance_eval()` already uses.
- **To remove them**, all four go out of both profiles and out of the header.

Either is a change to the chain's runtime, so it is recorded here rather than
bundled into unrelated work. Do not pin a fifth field of this kind in the
meantime.

## Build, release and verification

The commands, the toolchain versions and the release conventions are in
`AGENTS.md` §5 and §6. Two things worth repeating because getting them wrong is
expensive:

- **Both APKs must be signed with the same key.** DFInstaller writes DFReroot's
  certificate into `packages.xml`; a mismatch makes the injected key useless.
  The release workflow compares the certificate digests and fails if they differ.
- **Runner minutes are billed to the owner.** `ci.yml` is manual-dispatch only
  and is disabled at the repository level; `release.yml` runs the same offline
  gate set before it spends a signed build, so there is no second run to
  schedule. Run the checks below locally instead, and dispatch a workflow only
  when a release is actually wanted (`AGENTS.md` §6.1).
- **Every change goes through a PR** unless the owner says otherwise
  (`AGENTS.md` §6.2), and releases are published as stable/latest, with the
  compatibility state carried by the generated notes (`AGENTS.md` §6.3).

Expected counts, so a drop is noticeable:

```sh
sh tools/tests/run_tests.sh              # 72/72, the exp.c syntax pass,
                                         # then 38/38 (ko_audit modversion rules)
sh tools/tests/run_installer_tests.sh    # 49/49 (SafeWrite)
sh tools/tests/test_resolve_release_tag.sh   # 8/8
python3 tools/verify_zzic_avb.py          # AVB provenance, reproducible
```

The one command that is specific to this handoff rather than to the repo:

```sh
sh tools/zzic_collect.sh > zzic-identity.txt 2>&1   # on-device, read-only
```

It writes nothing, needs root only for its `/proc/kallsyms` section, and prints
every field the identity gate compares plus the whole vendor-provenance chain.

## Things that must not be quietly "fixed"

See `AGENTS.md` §7 ("Things that look like defects and are not") and §3.6
("No execution override, under any name"). The short list, for orientation:
the `org.lsposed.lspromise.DirtyFrag` JNI package name is load-bearing;
`libexp.so` is arm64-only by design; `REFERENCE_DIRTYFRAG_FIX_ABSENT` is an
independent fact and not proof of anything; and a run that refuses at a gate and
writes nothing is the tool working.

Gate promotion still needs independent evidence for every boundary, recorded in
`docs/S25U_ZZIC_COMPATIBILITY.md`. Today: A, B, C, D, E, F, H and G1 are PASS
(G1 offline; A/B/C/D/H include physical evidence). G2 and G4 are unverified, G3
is supported offline but awaits runtime confirmation, and Gate I is pending the
next same-boot physical run.
