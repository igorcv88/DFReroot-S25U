# DFReroot — Galaxy S25 Ultra SM-S938B / One UI 9 Beta 3 / ZZIC compatibility

Fail-closed compatibility profile and diagnostics for the exact firmware
`S938BXXUCZZIC`. This document records what was implemented, what was verified
in the build environment, and — explicitly — what remains `BLOCKED` on physical
hardware. **No gate is auto-promoted to global compatibility.** The `SUPPORTED`
state is intentionally *not* granted: only Gates A and E are `PASS` in this
environment; every gate that needs the ZZIC device or its pulled artefacts is
left `BLOCKED`/`UNKNOWN` with the exact command that closes it.

## Baseline

| Item | Value |
|---|---|
| Upstream | `polygraphene/DFReroot` |
| Working fork | `igorcv88/DFReroot-S25U` |
| Reference version | `v2.0.1` |
| Base commit | `9f1d6cd592d898b42d2e0c2d25ee1577e2aabe77` |
| Branch | `claude/dfreroot-s25u-zzic-support-dgw8fi` |
| Architecture preserved | build system, packages, module table, exploit flow unchanged |

## Target identity (pinned profile)

Source of truth: `app/src/main/jni/target_profile.c` (`DFR_PROFILE_ZZIC`) and
`tools/zzic_profile.json` (Python tools). Values:

```
manufacturer      = Samsung
model             = SM-S938B
device            = pa3q
sdk               = 37
android_release   = 17
display           = CP2A.260605.016.S938BXXUCZZIC
fingerprint       = samsung/pa3qxxx/pa3q:17/CP2A.260605.016/S938BXXUCZZIC_OXMCZZIC:user/release-keys
kernel_release    = 6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k
kernel_version    = #1 SMP PREEMPT Wed Sep 16 14:21:43 UTC 2026
page_size         = 4096
abi               = arm64-v8a
kernel_arch       = aarch64
```

## Kernel identity / Image / BTF (from hardware captures, pinned into the profile)

| Field | Value |
|---|---|
| Kernel Image SHA-256 | `470d40df59320e01b1449f8dbe962e0d44d735c817b99293dc6da286175ffcf3` (39,115,264 bytes) |
| ZZI4 Image SHA-256 (prior) | `7811e9413a3928079219347a435eadbfe0241f74ac28c459ad71b5195fdb8aef` (same size) |
| ZZIC×ZZI4 delta | 1,294,850 bytes (~3.3103445%), 136,593 distinct ranges |
| BTF SHA-256 | `e13df32a16b5536c43897542b4dbc2c7082f2aefb91249bc94a06bfc5870950c` (offset `0x18aca6c`, 6,425,607 bytes) |
| Kallsyms live | ~395,241 entries; 115,127 core symbols reconstructed, 0 mismatches |
| Kernel config confirmed | `CONFIG_MODULES/MODVERSIONS/MODULE_SIG/DEBUG_INFO_BTF = y` (runtime grep); XFRM/ESP v4+v6 = y |

`skb_shared_info`: flags=0, nr_frags=2, frag_list=8. `sk_buff`: data_len=0x74,
end=0xcc, head=0xd0. `struct selinux_state`: 128 bytes, 9 fields, `enforcing`
bit@0, `initialized` bit@8.

### Reference Dirty Frag fix — independent state

`esp_input` (`0x101803c`, 868 B), `esp6_input` (`0x10acffc`, 868 B),
`__ip_append_data` (`0xf9963c`, 3812 B), `__ip6_append_data` (`0x105a538`,
3908 B) are byte-for-byte identical between ZZI4 and ZZIC; the reference
shared-frag fix is absent in all four.

```
REFERENCE_DIRTYFRAG_FIX_ABSENT = CONFIRMED
```

This is recorded as an **independent** state. It is *not* treated as proof of
end-to-end exploitability (Gate I stays `BLOCKED`).

## Userspace identity (pinned)

| Path | SHA-256 | Notes |
|---|---|---|
| `/vendor/lib64/libstagefrighthw.so` | `308b254a82c51695015182fc3b78b5d0cbb6e36cd6cf8f2f282452f8a47f8049` | 51,632 B, `u:object_r:vendor_file:s0` |
| `/system/lib64/libc.so` (resolved) | `88fba68b3d1fded4bfd25197f6de24f5b8794d3253de860ee261a4272be9e861` | symlink → `/apex/com.android.runtime/lib64/bionic/libc.so` |
| `/system/lib64/libc++.so` | `cb118e98c74d3454858921123b9b51ba13df9cad7dfa141dd892c453661a4d78` | 1,152,760 B, `u:object_r:system_lib_file:s0` |

## NetworkStack observations (hardware)

`com.android.networkstack.process`, uid/gid 1073, `u:r:network_stack:s0`,
`CapEff=0x800003c00` (CAP_NET_ADMIN present; bits 10–13, 35), `Seccomp=2`,
1 filter, `NoNewPrivs=0`. Process observed running. A `cmd package` call during
one collection returned `Failed transaction (2147483646)`; recorded separately
from process existence because the process was directly observed.

## Files added / changed

**Added**
- `app/src/main/jni/target_profile.{h,c}` — target/profile abstraction, fail-closed classification, generic selection + uname parse (host-testable).
- `app/src/main/jni/sha256.{h,c}` — dependency-free SHA-256 for Gate B runtime hashing.
- `app/src/main/java/com/polygraphene/df/reroot/Diagnostics.kt` — Gate C/D `[DFR][AMS]`/`[DFR][PROCESS]` instrumentation.
- `tools/elf64.py` — shared ELF64 reader.
- `tools/ko_audit.py` (Gate G), `tools/elf_audit.py` (Gate F), `tools/apk_audit.py` (Gate E), `tools/installer_audit.py` (Gate H).
- `tools/zzic_profile.json`, `tools/tests/test_target_profile.c`, `tools/tests/run_tests.sh`, `tools/ci_build_audit.sh`, `tools/repro_report.sh`.
- `docs/S25U_ZZIC_COMPATIBILITY.md` (this file).

**Changed**
- `app/src/main/jni/exp.c` — Gate A/B fail-closed chokepoint at `patch_ko()` entry; `read_device_versions`/`select_ko_image` now delegate to `target_profile` (behaviour unchanged).
- `app/src/main/jni/CMakeLists.txt` — compile `target_profile.c` + `sha256.c`.
- `app/src/main/java/.../StageHop.kt`, `StageReceiver.kt` — wire Gate C/D dumps.
- `installer/src/main/java/.../PackagesXml.kt`, `InjectMain.kt` — `--diag-zzic` Gate H read-only diagnostic.

## Selection architecture (fail-closed)

```
exact known target
  → exact firmware profile (DFR_PROFILE_ZZIC)
    → validate firmware/kernel/userspace identity (Gate B, runtime)
      → select profile-specific artifacts where defined
        → otherwise upstream generic behaviour (unrelated devices)
```

`dfr_classify_target()` returns:
- `S25U_ZZIC` only when **every** identity field matches exactly.
- `MISMATCH` when the ZZIC **model/codename anchor** (`SM-S938B`/`pa3q`) is
  present but any field deviates → **refused** before any patch.
- `UPSTREAM_GENERIC` for unrelated devices → upstream path unchanged.

The ZZIC profile currently references the **generic** `android15-6.6` module
(kept separate from the profile). No ZZIC-specific `.ko` is bundled; if one is
produced it gets its own profile reference. The uname string parses to
`android15/6.6` — that is **kernel-family** selection, not identity.

## Unit tests (target detection) + regression tests

`tools/tests/run_tests.sh` (host `cc`, no Android). **22/22 pass.**

Target detection: exact ZZIC → `S25U_ZZIC`; and all required negatives → not
ZZIC: `SM-S938B+ZZI4` (MISMATCH), `SM-S938U`, `SM-S938N`, `pa3q+other display`
(MISMATCH), `ZZIC display+different kernel` (MISMATCH), `same kernel+different
fingerprint` (MISMATCH), unrelated Samsung 6.6 (UPSTREAM_GENERIC).

Regression: every upstream table combination (`android12/5.10 … android17/6.18`)
selects its own module unchanged; fallback and unknown-kernel behaviour preserved;
the ZZIC uname parse resolves to the `android15-6.6` family entry.

## Module ABI analysis (Gate G) — verified in this environment

`python3 tools/ko_audit.py app/src/main/jni/dirtyfrag-android15-6.6.ko`

```
sha256      : 6658df7da8b2e90a9d15dd551cbdc7a2405d707fdd13ee8892a1d7c635d884c0  (5656 B, git blob f35f374…)
machine     : AArch64 (OK)          module: dirtyfrag   license: GPL   depends: <none>
vermagic    : 6.6.127-4k-g46a034eca005-dirty SMP preempt mod_unload modversions aarch64
signed      : False
imports (4) : __stack_chk_fail, _printk, memset, sprint_symbol
__versions  : 0 entries   (section present, size 0 — no per-symbol CRC table)
relocations : .rela.text 8, .rela.init.text 25, .rela.init.data 1, .rela.gnu.linkonce.this_module 1
GENERIC_ANDROID15_6_6_MODULE = UNVERIFIED
```

Key findings, reported as **four independent properties** (never collapsed):
- The module imports **only** `sprint_symbol`, `_printk`, `memset`,
  `__stack_chk_fail`. It does **not** directly import `kallsyms_lookup_name`
  or `selinux_state` (it resolves addresses via `sprint_symbol`), despite the
  README’s prose — `SYMBOL_IMPORTED_BY_MODULE=False` for both.
- `SYMBOL_EXISTS_IN_KERNEL` / `SYMBOL_EXPORTED` are `UNKNOWN` from the `.ko`
  alone (the hardware capture confirms `sprint_symbol` has an export marker and
  that `kallsyms_lookup_name`/`selinux_state` exist as symbols; feed
  `--kallsyms`/`--symvers` to promote these).
- The generic module’s vermagic base is `6.6.127-4k` while the ZZIC kernel is
  `6.6.127-…-abogkiS938BXXUCZZIC-4k`. Same GKI base `6.6.127`, same `4k` page
  tag → vermagic is *necessary-compatible* but not sufficient.
- `CONFIG_MODVERSIONS=y` makes loadability turn on symbol-CRC agreement, but the
  module ships an **empty `__versions` table**, so no CRC can be checked offline.
  Verdict is therefore `UNVERIFIED` — resolve with the ZZIC `Module.symvers`:
  `tools/ko_audit.py … --symvers Module.symvers --kallsyms kallsyms.txt`.

## Native packaging (Gate E) — built and verified in this environment

Full `./build.sh` ran here (Android SDK/NDK installed on the fly; see
Reproducibility). `python3 tools/apk_audit.py df_reroot.apk`:

```
df_reroot.apk    sha256 6f60996288a00298eeba292e677ea9b31853062ce3cf46c6a313a9f1af5bced8  (8,231,450 B)
native libs      lib/arm64-v8a/libexp.so
assets           assets/dexopt/baseline.prof, assets/dexopt/baseline.profm, assets/ksud
libexp.so        sha256 88c05e9a18d905e01f5428629462caf95f618d372780d4ba490981a7d4e133bd  (96,400 B)
  elf            ELFCLASS64 / little-endian / ET_DYN   machine AArch64 (OK)
  build id       8ce5a20de58dde342fe2bb826cc6dc53a996649b
  DT_NEEDED      liblog.so, libm.so, libdl.so, libc.so
  JNI symbols    JNI_OnLoad, patchMod, patchLibc, patchCxx, createOrphanProcess, runAll  → all OK
status           PASS
df_installer.apk sha256 47f8aeace3d3b13719073efe01e054cdad0ea73910985a49bc870e06eef86fcf  (9,679,362 B)
  bundles assets/df_reroot.apk = True; ships no native lib of its own (by design — app_process, not JNI)
```

`libexp.so` contains the new gate code (45 `[DFR]` strings incl.
`TARGET_PROFILE=S25U_ZZIC|UPSTREAM_GENERIC|MISMATCH`).

## Java / AMS diagnostics (Gate C) and Process identity (Gate D)

Implemented in `Diagnostics.kt`, wired into `StageHop` (system_server) and
`StageReceiver` (network_stack). Emits deterministic, boundary-tagged lines:
AMS concrete class; `getProcessRecordLocked` overloads + parameter types;
`ProcessRecord` concrete class; `*thread*` fields and methods; concrete
application-thread type; `scheduleReceiver` overloads + parameter count/types
(Gate C). Gate D: pid/uid/gid, process name, SELinux context, ABI, classloader,
`nativeLibraryDir`, and the separate signals `NETWORKSTACK_PROCESS_FOUND`,
`REMOTE_COMPONENT_REACHED`, `NATIVE_LIBRARY_DISCOVERABLE` (never collapsed).
Execution requires the device (logcat capture) → **BLOCKED** here.

## Userspace ELF audit (Gate F) and Installer (Gate H)

`tools/elf_audit.py` audits crash_dump64 / libstagefrighthw.so / libc.so /
libc++.so pulled from the device: real path, SHA-256, ELF class/machine/build-id,
program & section headers, dynamic symbols, `LIBC_SYMBOL___libc_init` and
`LIBCXX_UPSTREAM_SYMBOL` lookups, and identity vs the pinned hashes. Verified to
run against host ELFs; **awaits pulled ZZIC artefacts** → `BLOCKED`.

`tools/installer_audit.py` + `InjectMain --diag-zzic` produce `PACKAGES_FORMAT`,
`PACKAGES_PARSE`, `ANDROID_UID_SYSTEM_FOUND`, `CERT_TABLE_PARSE`,
`ROUND_TRIP_VALID`, `METADATA_CAPTURED`. The offline tool was verified on a
synthetic text `packages.xml` (round-trip valid, cert table resolved). ABX and
real device metadata need the device → **BLOCKED**.

## Reproducibility

`tools/repro_report.sh` (rerun any time). This build:

| Field | Value |
|---|---|
| host os | Linux 6.18.44 x86_64 |
| git commit | `9f1d6cd…` (base) + this branch’s working tree |
| java | OpenJDK 21.0.10 |
| gradle (wrapper) | 9.7.1 |
| AGP / Kotlin | 8.7.3 / 2.0.21 |
| SDK platform | android-36 |
| build-tools | 36.0.0 |
| NDK | 27.0.12077973 (r27) |
| CMake | 3.22.1 |
| df_reroot.apk | `6f609962…` (8,231,450 B) |
| df_installer.apk | `47f8aeac…` (9,679,362 B) |
| libexp.so | `88c05e9a…` (96,400 B), build-id `8ce5a20d…` |
| ksud asset | `7bba5a9b…` |
| profile | `S25U_ZZIC` (fail-closed) |

> Note: `create-keystore.sh` is interactive upstream; in CI the keystore was
> generated non-interactively with `keytool … -dname "CN=dfreroot"` (script
> left unchanged). APK byte-hashes depend on the local keystore/signing and are
> not expected to match across differently-keyed builds; `libexp.so` and the
> compiled-in `.ko`/asset hashes are the signing-independent identity.

## Gate matrix (never auto-promoted to global compatibility)

| Gate | Result | Evidence |
|---|---|---|
| A — Target identity | **PASS** | fail-closed classifier implemented; 22/22 host tests incl. exact ZZIC + all required negatives |
| B — Kernel/userspace identity | **BLOCKED** | validation code + pinned hashes implemented; runtime SHA-256/symlink/page-size checks need the ZZIC device |
| C — Java/system-server compat | **BLOCKED** | `[DFR][AMS]` deterministic dumps implemented; needs on-device logcat to compare Android 17 shapes |
| D — NetworkStack identity | **BLOCKED** (process facts already observed on HW) | `[DFR][PROCESS]` instrumentation implemented; runtime capture pending |
| E — Native packaging | **PASS** | real `./build.sh`; `libexp.so` AArch64, all JNI symbols, hashes recorded (apk_audit) |
| F — Userspace ELF audit | **BLOCKED** | tool implemented + host-verified; awaits pulled ZZIC ELFs |
| G — Module ABI compatibility | **UNKNOWN / UNVERIFIED** | ko_audit ran on the real generic `.ko`; empty `__versions`, verdict UNVERIFIED without ZZIC `Module.symvers` |
| H — Installer format compatibility | **BLOCKED** | `--diag-zzic` + offline tool implemented; offline round-trip verified on synthetic XML; needs device packages.xml |
| I — Full hardware compatibility | **BLOCKED** | requires end-to-end on-device run; `REFERENCE_DIRTYFRAG_FIX_ABSENT=CONFIRMED` is independent, not proof |

**Conclusion:** `SUPPORTED` is **not** granted. In this environment only Gate A
(logic + tests) and Gate E (real build) are `PASS`; Gate G is `UNVERIFIED`; all
remaining gates are `BLOCKED` pending the ZZIC device and its pulled artefacts.
Each blocked gate above names the exact command/artefact that closes it.

## How to close the blocked gates on hardware

```sh
# Gate B/C/D — run on device, capture logcat tagged DFReroot / [DFR]
#   (Run DirtyFrag from the app; gate_target() aborts fail-closed unless the
#    exact ZZIC identity + userspace hashes validate.)
adb logcat -s DFReroot | grep '\[DFR\]'

# Gate F — pull the four artefacts and audit against the pinned hashes
adb pull /vendor/lib64/libstagefrighthw.so /system/lib64/libc++.so ./pulled/
python3 tools/elf_audit.py --root ./pulled

# Gate G — resolve UNVERIFIED with the ZZIC kernel symbol table
python3 tools/ko_audit.py app/src/main/jni/dirtyfrag-android15-6.6.ko \
    --symvers Module.symvers --kallsyms kallsyms.txt

# Gate H — audit the device packages.xml (or the .bak-df-installer backup)
adb shell su -c 'CLASSPATH=/data/local/tmp/df_installer.apk app_process /system/bin \
    com.polygraphene.df.installer.InjectMain --diag-zzic'
```
