# DFReroot S25U / ZZIC — handoff

**State is POST-PHYSICAL-TEST.** It reflects the first hardware execution of
the chain — `v2.0.2-zzic` (versionCode 5) on SM-S938B / `S938BXXUCZZIC` — and
the fixes that run produced, which ship as `2.0.3-zzic` (versionCode 6). Read it
with `docs/S25U_ZZIC_COMPATIBILITY.md`, which is the authoritative gate matrix
and evidence record; this file is only the "where to pick up" summary.

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

## Invariants the gates rest on — do not break these

1. **Identity comparison is case-sensitive and exact.** `ro.product.manufacturer`
   is lowercase `samsung` on this firmware. A capitalised value makes the real
   device classify `MISMATCH` and refuses the entire chain. Two host tests guard
   this; `tools/profile_binding_audit.py` guards it again in CI.

1b. **A gate is only as strong as its weakest entry point.** `patch_ko()`,
   `patch_libc()` and `patch_cxx()` are each independently reachable (JNI natives
   plus `StageReceiver` transactions 1–3), so both the identity gate
   (`gate_target`) and the Gate-G module policy (`gate_module_policy`) run in all
   three. Enforcing either in only one stage is the same as not enforcing it.
   `tools/profile_binding_audit.py` fails CI if a stage drops the policy call.

2. **Artefact hashes are scoped to the stage that writes them.** The chain
   rewrites the vendor file, `libc` and `libc++` in the page cache, so a stage
   that re-hashes an artefact an earlier stage already patched compares against
   the pristine pinned digest and aborts the chain on its own writes.
   `patch_ko()` owns `DFR_ART_CRASHDUMP | DFR_ART_VENDOR` (it writes both),
   `patch_libc()` owns `DFR_ART_LIBC`, `patch_cxx()` owns `DFR_ART_LIBCXX`.
   Artefacts a stage does not own log `SKIP`. **Never widen a stage's mask to
   "check everything"** — that is self-blocking. Each artefact is still validated
   exactly once, while pristine, immediately before it is written, and a
   mismatch is still a hard refusal.

3. **A required artefact with no pinned hash is a FAIL, not an UNKNOWN.** "We
   never captured the hash" is not evidence of a match.

3b. **An unreadable artefact is not an excuse to skip the proof — only to change
   its form.** `/vendor/lib64/libstagefrighthw.so` cannot be `open`ed from
   `system_server` or `network_stack` on this firmware (`EACCES`), which is why
   `patch_ko()` writes it through the `crash_dump64` helper instead. The gate
   therefore proves the AVB chain the pinned digest was captured under (vbmeta
   digest, `verifiedbootstate=green`, `device_state=locked`, `flash.locked=1`,
   `veritymode=enforcing`, `/vendor` erofs read-only) and refuses on any
   divergence. `EACCES` never becomes a PASS by itself, and a file that IS
   readable but hashes differently is always a hard refusal.

3c. **DFInstaller's metadata source of truth is the ORIGINAL file, stat'd before
   any write.** Never the backup, never a hardcoded `0600`. The device's
   `packages.xml` is `1000:1000 0660 u:object_r:system_data_file:s0`, and a
   freshly created file in a root-run `app_process` is `root:root 0644` — that
   mismatch is exactly the v2.0.2 defect. A backup is created transactionally
   and verified by size and digest; an existing backup that is empty, truncated
   or unparsable is a hard failure, not a log line.

4. **No validation happens after a write.** All identity checks, module
   selection and the Gate-G policy run before the first page-cache write, so a
   refusal never leaves a corrupted file behind.

5. **`ko_zzic_verified=1` is bound to the bytes.** The invariant is
   `ko_zzic_verified == 1 IMPLIES ko_sha256 pinned AND SHA-256(selected module
   bytes) == ko_sha256`, enforced in `patch_ko()` and in
   `tools/profile_binding_audit.py`. All three fields (`ko_zzic_verified`,
   `ko_filename`, `ko_sha256`) are set together or none are.

6. **Signals are never collapsed.** `NETWORKSTACK_PROCESS_FOUND` (a
   network_stack-uid process was observed) and `REMOTE_COMPONENT_REACHED` (our
   code actually executed inside it) are separate values, as are
   `NATIVE_LIBRARY_DISCOVERABLE` and `LIBEXP_LOADED`. No single `/dev/df*` marker
   means end-to-end compatibility.

7. **Evidence is per-boot.** `boot_id` is logged at every boundary; states from
   different boots must never be combined into one successful chain.

8. **The C profile and `tools/zzic_profile.json` must agree.** The CI drift check
   fails if they diverge — any pinned value goes in both.

## Current state

The chain was demonstrated on hardware up to Gate G. It now **refuses by design**
at exactly one boundary:

```
[DFR][MODULE] GENERIC_ANDROID15_6_6_MODULE=UNVERIFIED
[DFR][MODULE] ZZIC_MODULE_POLICY=REFUSE_UNVERIFIED
```

Everything before it is proven: Gate A (exact identity), Gate B (kernel,
`crash_dump64`, vendor provenance), Gate C (`scheduleReceiver/12` on Android 17),
Gate D (`network_stack` boundary, `libexp.so` loaded) and Gate H (packages.xml
injection surviving a soft reboot). A `2.0.3-zzic` run is expected to end
`runAll done res=3` with **no** `patch #1` and no page-cache write; that is the
test passing.

Off-device: 72/72 host gate checks, 49/49 installer write-path checks, and the
offline audits pass. Both APKs build and are signed with one key.

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

### 2. A Gate-G validated kernel module — unblocks the module load

The bundled `dirtyfrag-android15-6.6.ko` shares the ZZIC kernel's GKI base
(`6.6.127`) and page tag (`4k`) but ships an **empty `__versions` table** while
the kernel has `CONFIG_MODVERSIONS=y`, so no symbol-CRC agreement can be
established offline. Verdict is `UNVERIFIED`; an ABI-mismatched module can fault
the kernel.

`Module.symvers` is a kernel **build** artefact and is not present on a running
Android filesystem, so searching the device for it is not a valid route. One of
these is needed:

- the `Module.symvers` from the exact ZZIC kernel build;
- a module rebuilt from the matching source, config and toolchain;
- another verifiable source of that kernel's symbol CRCs.

The resulting module must carry a `__versions` table consistent with
`CONFIG_MODVERSIONS=y`. Matching the GKI base (`6.6.127`) and the 4k page tag is
**not** sufficient and must never be treated as if it were. A captured
`/proc/kallsyms` supplies existence evidence for the two runtime-resolved
symbols.

```sh
python3 tools/ko_audit.py app/src/main/jni/dirtyfrag-android15-6.6.ko \
    --symvers Module.symvers --kallsyms kallsyms.txt
```

`MODULE_VS_ZZIC_KERNEL = COMPATIBLE` is the only result that justifies setting
the three `ko_*` profile fields. The module imports only `sprint_symbol`,
`_printk`, `memset`, `__stack_chk_fail`; it resolves `kallsyms_lookup_name` and
`selinux_state` at runtime rather than importing them, so those two need
existence evidence, not export evidence.

Until a positively validated module is cryptographically bound to the ZZIC
profile, Gate G remains fail-closed at **every** page-cache stage
(`patch_ko`, `patch_libc`, `patch_cxx`), not just the module write. There is no
runtime marker or operator override that converts `UNVERIFIED` into permission to
proceed, and CI rejects the reintroduction of one under any name.

Read the consequence plainly: the chain cannot be exercised end to end on this
firmware today, deliberately or otherwise. Restoring an at-own-risk opt-in is a
policy decision for the repository owner; it is not something to reinstate quietly
because a run is inconvenient.

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

Still entirely unknown and needing device evidence, all of it downstream of
Gate G and therefore unreachable until Gate G is closed: the `vendor_modprobe`
SELinux domain and its exec transition, the seccomp filter's verdict on the
syscalls the native flow needs, mount-namespace behaviour, and any Samsung
DEFEX-style restriction.

## Build and release

```sh
# local, uses the create-keystore.sh defaults
ANDROID_HOME=<sdk> ANDROID_NDK_HOME=<ndk> ./build.sh

# with explicit signing material
KEYSTORE_FILE=<path> KEYSTORE_PASSWORD=... KEY_ALIAS=... KEY_PASSWORD=... ./build.sh
```

Toolchain that is known to work: JDK 21, Gradle 9.7.1 (wrapper), AGP 8.7.3,
Kotlin 2.0.21, SDK platform 36, build-tools 36.0.0, NDK 27.0.12077973,
CMake 3.22.1.

DFReroot and DFInstaller **must** be signed with the same key: DFInstaller writes
DFReroot's certificate into `packages.xml`, so a mismatch makes the injected key
useless. The release workflow verifies this and fails if the two certificate
digests differ.

`.github/workflows/release.yml` — push a `v*` tag or dispatch manually. Publishes
to GitHub Releases only, no workflow artifacts. Secrets: `KEYSTORE_BASE64`,
`KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`.

`.github/workflows/ci.yml` — offline gates on every branch/PR, plus a full build
signed with a throwaway key.

## Verification commands

```sh
sh tools/zzic_collect.sh                 # on-device, read-only evidence pass
sh tools/tests/run_tests.sh              # 72/72 expected, + exp.c syntax pass
sh tools/tests/run_installer_tests.sh    # 49/49 expected (SafeWrite)
python3 tools/profile_binding_audit.py   # §39 invariant + C/JSON drift
python3 tools/ko_audit.py <ko>           # Gate G; exits 1 on INCOMPATIBLE
python3 tools/apk_audit.py df_reroot.apk  # Gate E
python3 tools/elf_audit.py --root ./pulled   # Gate F
python3 tools/installer_audit.py <packages.xml>  # Gate H; exits 1 on a failed gate
./tools/ci_build_audit.sh                # post-build packaging audit
./tools/repro_report.sh                  # toolchain + artefact hashes
```

All audit tools exit non-zero on a failed gate; `UNVERIFIED` and `N/A` are
successful on purpose (evidence absent, or not a candidate — neither is a defect).

## Things that must not be quietly "fixed"

- The JNI package name `org.lsposed.lspromise.DirtyFrag` is load-bearing:
  `exp.c` registers `Java_org_lsposed_lspromise_DirtyFrag_*` and `JNI_OnLoad`
  looks it up. Renaming either side breaks linkage.
- `libexp.so` is arm64-only by design; a load failure on x86_64 is expected and
  non-fatal, so the Java hop stays testable on an emulator.
- `REFERENCE_DIRTYFRAG_FIX_ABSENT=CONFIRMED` is an independent static fact. It is
  not proof of exploitability and must not be used to promote any gate.
- No gate may be promoted to `SUPPORTED` without independent evidence for every
  boundary. Today: Gates A, B (kernel/crash_dump64/vendor provenance), C, D, E
  and H are `PASS` — A/B/C/D/H from the physical run; Gate G is `UNVERIFIED`;
  Gates F and I remain `BLOCKED`.
- `ZZIC_VENDOR_PROVENANCE` must not be "simplified" back into a direct
  `gate_hash()` of the vendor ELF. That read returns `EACCES` in every domain
  the chain runs in, so the simplification makes the ZZIC path unrunnable —
  `tools/profile_binding_audit.py` fails CI if the old call shape reappears.
- DFInstaller's write path must keep going through `SafeWrite`. Inlining it
  again is how the metadata source of truth drifts back onto the backup file.
