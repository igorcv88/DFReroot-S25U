# DFReroot S25U / ZZIC — handoff

State as of the merge of PR #4. Read this with
`docs/S25U_ZZIC_COMPATIBILITY.md`, which is the authoritative gate matrix and
evidence record; this file is only the "where to pick up" summary.

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

The ZZIC path **refuses by design**, at:

```
[DFR][USERSPACE] ZZIC_CRASHDUMP_IDENTITY FAIL required hash is not pinned
```

That is correct behaviour, not a bug. Everything static is done and verified:
the project builds, both APKs are produced and signed with one key, 28/28 host
gate tests pass, and the offline audits pass. What remains is evidence only.

## Pending work, in order

### 1. `crash_dump64` SHA-256 — unblocks Gate B

```sh
adb shell sha256sum /apex/com.android.runtime/bin/crash_dump64
```

Set the value in **both** files (the CI drift check enforces agreement):

- `app/src/main/jni/target_profile.c` → `.crashdump_sha256 = "<hex>"`
- `tools/zzic_profile.json` → `"crashdump_sha256": "<hex>"`

For the full §26 record, also pull the file and run
`python3 tools/elf_audit.py --root ./pulled` (size, build-id, program/section
headers, `DT_NEEDED`, APEX provenance).

### 2. A Gate-G validated kernel module — unblocks the module load

The bundled `dirtyfrag-android15-6.6.ko` shares the ZZIC kernel's GKI base
(`6.6.127`) and page tag (`4k`) but ships an **empty `__versions` table** while
the kernel has `CONFIG_MODVERSIONS=y`, so no symbol-CRC agreement can be
established offline. Verdict is `UNVERIFIED`; an ABI-mismatched module can fault
the kernel.

Needed from the device/kernel: `Module.symvers` and a captured `/proc/kallsyms`.

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
profile, Gate G remains fail-closed. There is no runtime marker or operator
override that converts `UNVERIFIED` into permission to proceed.

### 3. `scheduleReceiver` overload shape — the one runtime unknown

`StageHop.hopToNetworkStack()` invokes the **12-parameter** `scheduleReceiver`
overload. If Android 17 changed that shape the hop fails and logs every overload
it found. **Do not guess a fallback**: invoking an unknown overload with
fabricated arguments runs inside `system_server`. Wire the real shape only from
an observed log line:

```
[DFR][AMS] scheduleReceiver/<n> params=[...]
```

### 4. Remaining runtime captures

```sh
adb logcat -c && adb logcat -s DFReroot DirtyFrag | tee zzic-run.log
grep '\[DFR\]' zzic-run.log
adb shell cat /proc/sys/kernel/random/boot_id
```

| Needed | Boundary that emits it |
|---|---|
| AMS / ProcessRecord / IApplicationThread shapes (Gate C) | `[DFR][AMS] *` |
| network_stack identity (Gate D) | `[DFR][PROCESS] REMOTE_COMPONENT_REACHED` |
| `libexp.so` actually loaded | `[DFR][PROCESS] LIBEXP_LOADED` |
| SELinux / seccomp viability for XFRM and native load | `[DFR][PROCESS]` capability + seccomp fields, plus denials in `dmesg`/`logcat` |
| packages.xml semantics (Gate H) | `InjectMain --diag-zzic` → `[DFR][INSTALLER] *` |

Still entirely unknown and needing device evidence: the `vendor_modprobe`
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
sh tools/tests/run_tests.sh              # 28/28 expected
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
  boundary. Today: Gate A and Gate E `PASS`, Gate G `UNVERIFIED`, everything else
  `BLOCKED`.
