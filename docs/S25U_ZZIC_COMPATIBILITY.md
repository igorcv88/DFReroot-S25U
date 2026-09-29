# DFReroot — Galaxy S25 Ultra SM-S938B / One UI 9 Beta 3 / ZZIC compatibility

Fail-closed compatibility profile and diagnostics for the exact firmware
`S938BXXUCZZIC`. This document records what was implemented, what was verified
in the build environment, and — explicitly — what remains blocked.

> **This document is post-physical-test.** The state below reflects the first
> hardware execution of the chain, `v2.0.2-zzic` (versionCode 5) on
> SM-S938B / `S938BXXUCZZIC`. Gates A, B (kernel), C, D and H are no longer
> predictions; they were observed. Anything still written as a prediction is
> marked as such.

The rules this evidence is judged against — fail-closed, exact identity, proof
may change form but never be skipped — are in **`AGENTS.md`** at the repository
root, not restated here.

**No gate is auto-promoted to global compatibility.** `SUPPORTED` is still
intentionally *not* granted. Gate G1 (loader/import ABI) is now closed offline
with the exact bundled ZZIC module (`COMPLETE (5/5)` / `COMPATIBLE`), while
G2 remains runtime-unverified, G3 is supported by exact BTF but not yet confirmed
at runtime, and G4 (the write to `selinux_state.enforcing`) is still unverified.
Gate I therefore awaits the next physical run rather than being blocked by G1.

## Baseline

| Item | Value |
|---|---|
| Upstream | `polygraphene/DFReroot` |
| Working fork | `igorcv88/DFReroot-S25U` |
| Reference version | upstream `v2.0.1`; this fork's version is derived per release run from the tag it publishes (`tools/resolve_release_version.sh`, `versionCode = major*10000 + minor*100 + patch`) and is a literal in no file. `2.0.5-zzic` (versionCode 20005 under the derived scheme; the published build carried 8, the last hand-edited one) is the version physically validated |
| Base commit | `9f1d6cd592d898b42d2e0c2d25ee1577e2aabe77` |
| Branch | `claude/dfreroot-s25u-zzic-support-dgw8fi` |
| Architecture preserved | build system, packages, module table, exploit flow unchanged |

## Physical run — `v2.0.2-zzic`, first hardware execution

Everything in this section was **observed on the device**, not inferred. It is
the evidence the rest of this document now rests on.

### The chain that executed

```
DFInstaller (app_process as root)
  -> /data/system/packages.xml, our cert into android.uid.system pastSigs
    -> soft reboot (framework restart; boot_id unchanged)
      -> DFReroot installed as package:com.polygraphene.df.reroot uid:1000
         sharedUser=android.uid.system/1000
        -> runs as uid=1000(system) gid=1000 context=u:r:system_server:s0
          -> ActivityManagerService
            -> getProcessRecordLocked ABSENT -> mProcessNames fallback
              -> ProcessRecord{...:com.android.networkstack.process/1073}
                -> mOnewayThread (android.app.IApplicationThread)
                  -> scheduleReceiver/12
                    -> StageReceiver in network_stack
                      -> System.loadLibrary("exp")
                        -> CONTROLLER binder back to the UI
                          -> runAll -> Gate A PASS -> Gate B ...
```

`boot_id` was `0643a5e2-9a44-4bb9-b7a4-31a3b255e3ac` across the soft reboot,
confirming the framework restart did not change the boot.

### Gate A — exact identity: **physical PASS**

All twelve compared fields matched. Reported by the device:

```
manufacturer=samsung   model=SM-S938B   device=pa3q
sdk=37   android=17
display=CP2A.260605.016.S938BXXUCZZIC
fingerprint=samsung/pa3qxxx/pa3q:17/CP2A.260605.016/S938BXXUCZZIC_OXMCZZIC:user/release-keys
kernel_release=6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k
kernel_version=#1 SMP PREEMPT Wed Sep 16 14:21:43 UTC 2026
page_size=4096   abi=arm64-v8a   arch=aarch64
-> TARGET_PROFILE=S25U_ZZIC, PASS exact identity
```

### Gate B — kernel: **physical PASS**

```
ZZIC_KERNEL_IDENTITY=PASS
ZZIC_KERNEL_VERSION=PASS
ZZIC_KERNEL_ARCH=PASS (aarch64)
ZZIC_PAGE_SIZE=PASS (4096)
```

### Gate C — Android 17 AMS shapes: **physical PASS**

The concrete class is `com.android.server.am.ActivityManagerService`.
`getProcessRecordLocked` **does not exist on this build** — the enumeration
returned an empty overload list. The `mProcessNames` fallback resolved the
ProcessRecord, and `mOnewayThread` (`android.app.IApplicationThread`) was the
correct thread field; `mThread` is a
`com.android.server.am.ApplicationThreadDeferred`.

The `scheduleReceiver` overload on Android 17 / One UI 9 is **no longer
unknown**. Observed exactly:

```
scheduleReceiver/12 params=[
    android.content.Intent,
    android.content.pm.ActivityInfo,
    android.content.res.CompatibilityInfo,
    int,
    java.lang.String,
    android.os.Bundle,
    boolean,
    boolean,
    int,
    int,
    int,
    java.lang.String
]
```

which is the shape `StageHop` already invokes. `scheduleReceiver sent` and
`networkstack CONTROLLER binder received` both followed.

**Change made in `2.0.3-zzic`:** the absent primary lookup used to log a bare
`getProcessRecordLocked UNKNOWN (no overload found)` with no verdict afterwards,
which reads like a blocker when the fallback has already succeeded. The gate now
ends on an explicit conclusion:

```
[DFR][AMS] PROCESS_LOOKUP_PRIMARY=UNAVAILABLE (no getProcessRecordLocked on this build)
[DFR][AMS] PROCESS_LOOKUP_FALLBACK=mProcessNames
[DFR][AMS] PROCESS_LOOKUP_METHOD=ProcessList.mProcessNames.get/2
[DFR][AMS] PROCESS_LOOKUP=PASS
```

### Gate D — remote boundary: **physical PASS**

The CONTROLLER binder is created by `StageReceiver.stage2()` only *after*
`System.loadLibrary("exp")` succeeds, so receiving it is itself proof that
`libexp.so` was loaded inside `u:r:network_stack:s0`.

**Change made in `2.0.3-zzic`:** that proof was previously only in logcat, so
closing Gate D needed a second capture from a different process. `StageReceiver`
now carries its own `Diagnostics.processIdentity()` output and `LIBEXP_LOADED`
back in the `EVIL` broadcast (`DIAG` extra), and the UI prints them under a
`--- remote boundary (network_stack) ---` block. A stage that lands but cannot
arm now also reports in, instead of leaving the UI to time out silently.

### Gate H — installer / `packages.xml`: **physical PASS, with two defects found**

`packages.xml` on this device is:

```
uid=1000 gid=1000 mode=0660 u:object_r:system_data_file:s0 format=ABX
```

The `ABX -> TEXT -> ABX` cycle is accepted by this firmware's PackageManager:
DFInstaller wrote plain-text XML, PMS re-read it and reserialised to ABX on the
next `writeSettings`, and the injection survived:

```
[check] android.uid.system injected=true
[check] all_injected=true
```

Two real defects surfaced in the same run and are fixed in `2.0.3-zzic`
(see "Installer write path" below).

## Vendor ELF: why the direct hash was the wrong proof

The `v2.0.2-zzic` Gate B hashed `/vendor/lib64/libstagefrighthw.so` directly and
refused when it could not:

```
[DFR][USERSPACE] ZZIC_VENDOR_ELF FAIL cannot read
/vendor/lib64/libstagefrighthw.so (errno=13)
```

`errno=13` is `EACCES`. The measurements that explain it:

| Domain | `open`/hash of the vendor ELF |
|---|---|
| `u:r:ksu:s0` | OK — `308b254a82c51695015182fc3b78b5d0cbb6e36cd6cf8f2f282452f8a47f8049` |
| `u:r:system_server:s0` (uid 1000) | `Permission denied` |
| `u:r:network_stack:s0` (uid 1073) | `Permission denied` |

This is **not** a missing file, a missing mount, or KernelSU "Unmount modules".
The file is present and identical inside both namespaces
(`/proc/<system_server>/root/...` and `/proc/<network_stack>/root/...`:
`-rw-r--r-- root root u:object_r:vendor_file:s0`, 51632 bytes), the mount
namespaces differ (`mnt:[4026535926]` vs `mnt:[4026535863]`) but both resolve
it, and `/vendor` is mounted `/dev/block/dm-17 ... erofs ro,seclabel`. The
absence of an `avc: denied` line in `dmesg`/`logcat` is not evidence of
permission either — the policy may `dontaudit` it. The functional evidence is
`open()` returning `EACCES`.

The decisive point is that **the upstream exploit already knows this.**
`patch_file()` only calls `open(path, O_RDONLY)` when `use_helper == 0`, and
`patch_ko()` writes the vendor target with `use_helper = 1`, which goes through
`execl(kCrashDump, "crashdump64", offset, target_lib_path, NULL)` and never
opens the file from this process. The v2.0.2 gate demanded a read the
architecture is deliberately built to avoid.

### What replaced it

The requirement for proof does not go away; the *form* of the proof changes. The
pinned digest `308b25…` was captured on this exact firmware while dm-verity was
enforcing, verified boot was green, the bootloader was locked, and vbmeta
reported a specific digest. Under AVB those facts are what authenticate the bytes
on `/vendor`: the same vbmeta digest with verity enforcing on a green/locked
device means the `/vendor` tree is the one that digest covers. So the runtime
re-establishes that chain instead, and every element of it is compared:

```
ro.boot.verifiedbootstate    = green
ro.boot.vbmeta.device_state  = locked
ro.boot.flash.locked         = 1
ro.boot.veritymode           = enforcing
ro.boot.vbmeta.digest        = 23a0e0b0a5b421d5a75b62de40edb37489a4e6d441d54e58ee6f930c1a9a3f62
ro.boot.vbmeta.avb_version   = 1.2
ro.boot.vbmeta.hash_alg      = sha256
/vendor                      = erofs, mounted read-only
```

The runtime now logs, on the exact ZZIC target:

```
[DFR][USERSPACE] ZZIC_VENDOR_DIRECT_HASH=UNAVAILABLE_EACCES
[DFR][USERSPACE] ZZIC_VENDOR_PROVENANCE=PASS_AVB
```

The verdicts, all fail-closed, are in `dfr_vendor_provenance_eval()`
(`target_profile.c`, host-tested):

| Verdict | Meaning |
|---|---|
| `PASS_DIRECT` | the file *was* readable and its digest is the pinned one — the chain is still required and intact |
| `PASS_AVB` | the read was denied with `EACCES` and every AVB/mount element matched |
| `FAIL_DIRECT_MISMATCH` | readable and **not** the pinned bytes — no provenance excuses this |
| `FAIL_CHAIN` | any AVB or mount element absent or divergent, or an available size/label that diverges |
| `FAIL_UNREADABLE` | unreadable for any errno other than `EACCES` |
| `FAIL_NO_PIN` | the profile does not pin the full chain |

There is **no verdict that turns `EACCES` into a pass on its own.** `EACCES`
only changes *which* proof is required, never *whether* one is required.

Two anchors are observational rather than required: the file's `st_size` and its
SELinux label. A domain denied `open(2)` may also be denied `getattr`, so these
are compared **when available** (available-and-divergent is a hard `FAIL_CHAIN`)
and recorded as `SKIP` when not. They are never counted as agreement.

### The anchor is now reproducible, not merely observed

Until the AVB evidence landed, the pinned `vbmeta_digest` was a number somebody
had seen on a device once. That is the kind of evidence this repository does not
accept anywhere else, and it was recorded here as a limitation.

It no longer is. `evidence/zzic/avb/` holds the four vbmeta images from the
official ZZIC OTA, and `tools/verify_zzic_avb.py` re-derives the digest from
them:

```text
chain order       : dtbo -> optics -> prism
digest reproduced : 23a0e0b0a5b421d5a75b62de40edb37489a4e6d441d54e58ee6f930c1a9a3f62
digest pinned     : 23a0e0b0a5b421d5a75b62de40edb37489a4e6d441d54e58ee6f930c1a9a3f62
VBMETA_DIGEST_REPRODUCIBLE = PASS
```

`ro.boot.vbmeta.digest` is SHA-256 over the top-level vbmeta blob followed by
each chained vbmeta in descriptor order, so `vbmeta.img` alone reproduces
nothing — the three children are load-bearing, and a missing one is a refusal
rather than a shorter walk. The digest commits the auxiliary block, which
carries the signed hashtree descriptor for `vendor`; that descriptor's root
digest, salt and geometry are verified against the profile in the same run. The
tool parses AVB itself (`tools/avb.py`), so CI and any reviewer with `python3`
can redo the derivation with no AOSP checkout and no `avbtool`.

What remains observational, and is stated as such:

- The ELF bytes were read from the verified `/vendor` mount rather than
  extracted from a 3.5 GB `vendor.img`. Under `veritymode=enforcing` with a root
  digest matching a signed descriptor, those are equivalent — reconstructing the
  image would be redundant forensics, not a missing link.
- The **live** dm-verity table is corroboration, not a requirement. The DM ioctl
  succeeds from `u:r:ksu:s0` and fails from `u:r:untrusted_app_27:s0`, and has
  never been measured from `u:r:network_stack:s0`. Requiring it at runtime would
  rebuild the 2.0.2 trap — a gate the chain's own domain cannot satisfy. Drop a
  raw `dmsetup table vendor-verity` capture into `evidence/zzic/avb/` and the
  offline verifier compares it automatically; while it is absent the tool reports
  `LIVE_DM_VERITY_TABLE = SKIP (artefact absent)`, never implicit agreement.

The descriptor's geometry is pinned in `tools/zzic_profile.json` under
`vendor_avb` and **not** in `target_profile.c`: block counts are canonical, byte
offsets are derived and compared, and `data_blocks + tree_blocks ==
fec_offset_blocks` is asserted. These are offline-only values, because a pinned
field the runtime never compares is dead weight advertising a check nobody
performs.

## Installer write path — two field defects fixed

Both were produced by the `v2.0.2-zzic` run and are now covered by
`tools/tests/SafeWriteTest.java` (49 checks, in-memory filesystem, no device).

### 1. Metadata was inferred from the wrong file

The old `writeBack()` created the backup with `File.copyTo` and then read the
target uid/gid/mode out of **the backup it had just created**. A file created by
a root-run `app_process` is `root:root 0644`, so those were the values reapplied
to the final `packages.xml`. Before the inject the file was `1000:1000 0660`;
after the rename swap it was `0:0 0644`.

Fixed: the original is `stat`'d (plus its SELinux label and a SHA-256 of its
contents) **before anything is written**, and that stat is the only source of
truth for the backup, the staged replacement and the final file. After the
rename the metadata is re-read and compared; a divergence rolls the file back
and refuses, rather than asking for a framework restart on a mis-owned
`packages.xml`. `0600` is no longer hardcoded as a universal default.

### 2. The backup could exist and be empty

The run left `/data/system/packages.xml.bak-df-installer` at **0 bytes**, and the
old code's only check was `bak.exists()` followed by
`"backup already exists, keeping"`. That is worse than no backup: it looks like a
rollback path and restores nothing. (The pristine image — 1,205,358 bytes,
`559dde0e57f29cb7b68905ad7b25b27f8ea92901c14dcaef26d6b60d504a49a1` — was
recovered by hand.)

Fixed: backup creation is transactional — staged under a temporary name, read
back and compared by size **and** SHA-256, given the original's metadata,
`fsync`ed, then `rename(2)`d into place. An existing backup is still never
overwritten (it is the pristine pre-injection image), but it is now validated,
and one that is empty, truncated or unparsable is a hard failure with an
actionable message. `InjectMain --diag-zzic` reports `BACKUP_PRESENT` /
`BACKUP_VALID` read-only, so the state is visible before anyone relies on it.

## Target identity (pinned profile)

Source of truth: `app/src/main/jni/target_profile.c` (`DFR_PROFILE_ZZIC`) and
`tools/zzic_profile.json` (Python tools). Values:

```
manufacturer      = samsung
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

`manufacturer` is lowercase. `ro.product.manufacturer` reports `samsung` (the
same casing the fingerprint prefix uses) and the comparison is case-sensitive,
so pinning `Samsung` would classify the real device as `MISMATCH` and refuse the
whole chain. `tools/tests/test_target_profile.c` asserts both directions, and
`tools/profile_binding_audit.py` re-checks it in CI.

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

Exact identity compares **all** of: manufacturer, model, device, sdk,
android_release (`ro.build.version.release`), display, fingerprint, `uname -r`,
`uname -v` (kernel_version), `uname -m` (kernel_arch), page size and abi. A rebuilt kernel that keeps `uname -r` but changes `uname -v`
or `uname -m` is therefore a `MISMATCH`, not an "exact" target.

**Every** page-cache corruption entry point runs the gate, not just `patch_ko()`:
`patchMod`/`patch_ko`, `patchLibc`/`patch_libc` and `patchCxx`/`patch_cxx` each
re-validate before touching a file (the JNI methods are exposed independently by
`StageReceiver` transactions 1–3).

On the exact ZZIC target the generic module is Gate-G `UNVERIFIED`. The same
chokepoint applies at **every** one of those three stages, not only at
`patch_ko()`: `gate_module_policy()` refuses (`[DFR][MODULE] FAIL`) unless a
ZZIC-validated module is bundled and cryptographically bound to the profile.

The reason the policy is not confined to the stage that writes the module: on
ZZIC the earlier writes (`crash_dump64`, the vendor file, `libc`, `libc++`) exist
for one purpose — to make the kernel load that module. If the load can never be
permitted, corrupting those files is risk with no reachable outcome, and
`patchLibc`/`patchCxx` are independently invokable (`StageReceiver` transactions
2 and 3), so a policy enforced only in `patch_ko()` is not enforced at all.

The decision itself is `dfr_module_policy_eval()` in `target_profile.c` — pure
logic, no I/O — so the host tests exercise the same verdicts the device produces.
`exp.c` only logs the boundary and, in `patch_ko()` alone, binds the verdict to
`SHA-256(selected payload)`: that stage is the only holder of the module bytes, so
the byte binding stays where it can be proven instead of being assumed earlier.
`tools/profile_binding_audit.py` fails CI if any of the three stages stops calling
the policy, or if any DFReroot runtime source regains a `/data/local/tmp` marker.

## Unit tests (target detection) + regression tests

`tools/tests/run_tests.sh` (host `cc`, no Android). **72/72 pass**, and it also
syntax-checks `exp.c` against the stub NDK headers in `tools/tests/ndkstub/`, so
a typo in a gate costs a second on any host instead of a whole signed NDK build.

`tools/tests/run_installer_tests.sh` (host `javac`/`java`, no Android).
**49/49 pass** — the DFInstaller write path driven against an in-memory
filesystem, including the EPERM-then-rename branch that lost the file's metadata
on hardware, and every invalid-backup case.

Target detection: exact ZZIC → `S25U_ZZIC`; and all required negatives → not
ZZIC: `SM-S938B+ZZI4` (MISMATCH), `SM-S938U`, `SM-S938N`, `pa3q+other display`
(MISMATCH), `ZZIC display+different kernel` (MISMATCH), `same kernel+different
fingerprint` (MISMATCH), `same kernel_release+different kernel_version`
(MISMATCH), `different kernel_arch` (MISMATCH), unrelated Samsung 6.6
(UPSTREAM_GENERIC).

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
imports (4) : __stack_chk_fail, _printk, memset, sprint_symbol   (4 need a version entry, 0 weak)
__versions  : 0 entries   (section present, size 0 — no per-symbol CRC table)
MODVERSION_COVERAGE = EMPTY (__versions holds no entries; 4 import(s) need one)
relocations : .rela.text 8, .rela.init.text 25, .rela.init.data 1, .rela.gnu.linkonce.this_module 1
GENERIC_ANDROID15_6_6_MODULE = UNVERIFIED
```

With `--require-modversion-coverage` the same module is `INCOMPATIBLE`: the empty
table alone makes it unloadable on a `CONFIG_MODVERSIONS=y` kernel, independently
of any CRC. The plain invocation stays `UNVERIFIED` (exit 0) on purpose, so the
release audit is not blocked by evidence that is merely absent.

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
- `MODVERSION_COVERAGE=EMPTY` is reported as its own value, distinct from
  `INCOMPLETE` and from the CRC diff. "The table has no entry for this import"
  and "the entry disagrees with the kernel" are different facts; so are
  `SYMBOL_HAS_MODVERSION_ENTRY` and `MODVERSION_MATCH`. An imported symbol with
  no entry reports `MISSING (imported, no __versions entry)` — it used to report
  `N/A (not imported)`, a false label on exactly the hole that matters.

## Native packaging (Gate E) — built and verified in this environment

Full `./build.sh` ran here (Android SDK/NDK installed on the fly; see
Reproducibility). `python3 tools/apk_audit.py df_reroot.apk`:

```
df_reroot.apk    sha256 72063006e074bab482221cd5fc4fe3b8e1ddb0e7916d93e5afe430d455a5e74c  (8,233,082 B)
native libs      lib/arm64-v8a/libexp.so
assets           assets/dexopt/baseline.prof, assets/dexopt/baseline.profm, assets/ksud
libexp.so        sha256 5bfe5cd2b5954cccfb207a5fb05070e4e4b2cd7a720429a740d6e629dda5f776  (98,032 B)
  elf            ELFCLASS64 / little-endian / ET_DYN   machine AArch64 (OK)
  build id       5ce74e68e30bac3034c3c47f1b39c842764527d2
  DT_NEEDED      liblog.so, libm.so, libdl.so, libc.so
  JNI symbols    JNI_OnLoad, patchMod, patchLibc, patchCxx, createOrphanProcess, runAll  → all OK
status           PASS
df_installer.apk sha256 6f0cf97e37169bb0031631aa9b30d38d83334c2993282d2d9779c3a4e21978d8  (9,680,038 B)
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

Both gates are **physical PASS** as of the `v2.0.2-zzic` run; see "Physical run"
above for the observed Android 17 shapes. Two observability changes shipped in
`2.0.3-zzic`: Gate C ends on an explicit `PROCESS_LOOKUP=PASS|FAIL` instead of
leaving a bare `UNKNOWN` after a successful fallback, and Gate D's remote-side
evidence travels back to the UI in the `EVIL` broadcast rather than existing only
in logcat.

## Userspace ELF audit (Gate F) and Installer (Gate H)

`tools/elf_audit.py` audits crash_dump64 / libstagefrighthw.so / libc.so /
libc++.so pulled from the device: real path, SHA-256, ELF class/machine/build-id,
program & section headers, dynamic symbols, `LIBC_SYMBOL___libc_init` and
`LIBCXX_UPSTREAM_SYMBOL` lookups, and identity vs the pinned hashes. Verified to
run against host ELFs; **awaits pulled ZZIC artefacts** → `BLOCKED`. `--root`
rebases **absolute** symlink targets (e.g. `libc.so → /apex/.../libc.so`) under
the pulled root instead of the host filesystem, so libc resolves correctly from
a pulled tree.

`tools/installer_audit.py` + `InjectMain --diag-zzic` produce `PACKAGES_FORMAT`,
`PACKAGES_PARSE`, `ANDROID_UID_SYSTEM_FOUND`, `CERT_TABLE_PARSE`,
`ROUND_TRIP_VALID`, `METADATA_CAPTURED`. The offline tool was verified on a
synthetic text `packages.xml` (round-trip valid, cert table resolved), and the
on-device path is **physical PASS** as of `v2.0.2-zzic`: real ABX input, real
`1000:1000 0660 u:object_r:system_data_file:s0` metadata, and an
`ABX → TEXT → ABX` cycle the firmware's PMS accepted. `--diag-zzic` now also
reports `BACKUP_PRESENT` / `BACKUP_VALID`, read-only, after the run left a
zero-byte backup behind.

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
| df_reroot.apk | `72063006…` (8,233,082 B) |
| df_installer.apk | `6f0cf97e…` (9,680,038 B) |
| libexp.so | `5bfe5cd2…` (98,032 B), build-id `5ce74e68…` |
| ksud asset | `7bba5a9b…` |
| profile | `S25U_ZZIC` (fail-closed) |

> Note: `create-keystore.sh` is interactive upstream; in CI the keystore was
> generated non-interactively with `keytool … -dname "CN=dfreroot"` (script
> left unchanged). APK byte-hashes depend on the local keystore/signing and are
> not expected to match across differently-keyed builds; `libexp.so` and the
> compiled-in `.ko`/asset hashes are the signing-independent identity.

## Second review pass — defects found and fixed

A full re-read of the merged implementation found two defects that would each
have made the port non-functional on the real device, plus three gaps between
what the dossier demands and what the code enforced.

**P0 — the profile could never match the target.** `DFR_PROFILE_ZZIC.manufacturer`
was `"Samsung"`, but `ro.product.manufacturer` on this firmware is `"samsung"`
and `dfr_streq()` is case-sensitive. On the real SM-S938B the model/codename
anchor hits, so the single failed field made `dfr_classify_target()` return
`DFR_TARGET_MISMATCH` — the fail-closed path — and **every** entry point
(`patchMod`, `patchLibc`, `patchCxx`, `runAll`) refused before doing anything.
The device it was written for was the one device it rejected. The host test
suite did not catch it because the test vector carried the same wrong casing as
the profile, so the bug was asserted rather than detected. Both are fixed, and
the suite now asserts the profile's casing directly *and* that a capitalised
value is a `MISMATCH`.

**P0 — the artefact gate aborted the chain on the chain's own writes.** Gate B
hashed the vendor file, libc and libc++ on *every* gate run, and every entry
point runs the gate. But this chain rewrites exactly those three files in the
page cache: after `patch_ko()` patched the vendor file, `patch_libc()`'s gate
re-hashed it, saw content that no longer matched the pinned pristine digest, and
refused — so `runAll` could never get past its second stage on a validated ZZIC
device. Each stage now passes only the artefact **it** is about to write
(`DFR_ART_VENDOR` / `DFR_ART_LIBC` / `DFR_ART_LIBCXX`); the artefacts it does not
own are logged `SKIP` so no reader mistakes an unhashed artefact for a validated
one. Every pinned artefact is still validated exactly once, while pristine,
immediately before it is written, and a mismatch is still a hard refusal — the
check was scoped, not relaxed.

**Section 26 — `crash_dump64` is a required boundary.** It is the first file the
chain writes, and its hash was simply absent from the profile, so `gate_hash()`
reported `UNKNOWN` and let the write through. `crashdump_sha256` is now a profile
field, owned by `patch_ko()` (which writes both crash_dump64 and the vendor
file), and on the ZZIC target an unpinned **required** artefact is a `FAIL`, not
an `UNKNOWN`: "we never captured the hash" is not evidence of a match. It is
`NULL` today, so **the ZZIC path refuses until the hash is supplied** — that is
the intended state, and closing it needs one value from the device (see
"What is still needed" below).

**Ordering — a refusal no longer leaves a corrupted file behind.** `patch_ko()`
patched `crash_dump64` (patch #1) *before* selecting the module and applying the
Gate-G module policy, so a fail-closed module refusal happened after the first
page-cache write. Module selection and the policy decision are pure lookups and
now run before any write.

**Section 39 — `ko_zzic_verified` is no longer a bare boolean.** Nothing bound
the flag to the bytes it vouched for: flipping it to 1 would have loaded
whatever module was bundled. The profile gained `ko_filename` + `ko_sha256`, and
the invariant

```
ko_zzic_verified == 1  IMPLIES  ko_sha256 pinned
                       AND      SHA-256(selected module bytes) == ko_sha256
```

is enforced at run time in `patch_ko()` (`ZZIC_MODULE_BINDING=PASS`, refusal
otherwise) and in CI by `tools/profile_binding_audit.py`, which also refuses a
stale digest left pinned while the flag is 0, and checks that the C profile and
`tools/zzic_profile.json` have not drifted apart.

**Section 57 — `android_release` is now compared, not just stored.** It was
pinned in the profile and in the JSON, but absent from `ObservedTarget`, so it
was advertised as identity and never checked. It is read from
`ro.build.version.release`, logged as `TARGET_ANDROID_RELEASE`, and included in
the exact-match set; an unreadable value (0) is a `MISMATCH`, never an assumption.

**Section 22 — `REMOTE_COMPONENT_REACHED` now rests on an observation.** It was
`PASS` whenever the caller passed the string `"network_stack"`. It now requires
the observed uid **and** `/proc/self/cmdline` process name to agree with the
profile, and reports `FAIL` with the observed identity otherwise.

**`ko_audit.py` verdict label.** Auditing a module from another kernel family
(e.g. `dirtyfrag-android17-6.18.ko`) printed
`GENERIC_ANDROID15_6_6_MODULE = INCOMPATIBLE`, which reads as "evaluated and
rejected" when the module was simply never a ZZIC candidate. The key is now
`MODULE_VS_ZZIC_KERNEL` and reports `N/A` with the reason for other families.

## Release / CI automation

`.github/workflows/release.yml` (tag `v*` or manual dispatch) builds both signed
APKs and publishes them as **GitHub Release assets only** — no workflow
artifacts are uploaded. It runs the offline gates first, then signs, then
verifies. Repository secrets:

| Secret | Purpose |
|---|---|
| `KEYSTORE_BASE64` | `base64 -w0` of the keystore; decoded to `$RUNNER_TEMP`, never into the working tree |
| `KEYSTORE_PASSWORD` | keystore password |
| `KEY_ALIAS` | key alias |
| `KEY_PASSWORD` | key password |

Both `build.gradle.kts` files resolve signing from `KEYSTORE_FILE` /
`KEYSTORE_PASSWORD` / `KEY_ALIAS` / `KEY_PASSWORD`, falling back to the
`create-keystore.sh` development defaults so local `./build.sh` is unchanged.
**Both APKs must be signed with the same key** — DFInstaller injects DFReroot's
certificate into `packages.xml` — so the workflow compares the two certificate
digests and fails the release if they differ.

Release assets: `df_reroot_<version>.apk`, `df_installer_<version>.apk`,
`build-provenance.txt` (toolchain, commit, payload hashes) and `SHA256SUMS.txt`.

`.github/workflows/ci.yml` runs on every branch and PR: the host gate tests, the
binding invariant, Python/shell syntax, the Gate G module audit, a Gate H
round-trip on a synthetic `packages.xml`, and a full build + Gate E packaging
audit signed with a throwaway key (those APKs are build checks, not releases).

`build-splice.sh` now accepts `ANDROID_NDK`, `ANDROID_NDK_HOME` or
`ANDROID_NDK_ROOT`, falling back to the newest `$ANDROID_HOME/ndk/*`; it
previously required `ANDROID_NDK` specifically, which most CI setups do not set.

### CI gates that could not actually fail (Codex review of `5ad3397`)

Four findings, all verified by reproducing the failure first:

- **P1 — a release could attach one commit's artifacts to another commit's tag.**
  On a manual dispatch naming an existing tag, the checkout sits at the
  dispatched ref, which need not be the tag's target, and the old release was
  updated from `GITHUB_SHA` regardless. The tag's commit is now resolved before
  the build (annotated tags dereferenced) and a mismatch refuses. `--clobber`
  also only replaces same-named assets, so a version bump left the previous
  version's APKs in the release; stale `*.apk` assets not being re-uploaded are
  now removed.
- **P2 — Gate G could not fail.** `ko_audit.py` always returned 0, so a module
  with the wrong architecture, page tag or a symbol-CRC mismatch printed
  `INCOMPATIBLE` and the release proceeded. It now exits 1 on `INCOMPATIBLE`,
  with the reason. `UNVERIFIED` and `N/A` stay successful deliberately: the
  first means the deciding evidence is absent, the second that the module was
  never a ZZIC candidate — conflating either with a hard rejection would make
  the gate unusable while the ZZIC symbol table is missing.
- **P2 — Gate H could not fail.** `installer_audit.py` always returned 0,
  including on `PACKAGES_PARSE=FAIL`, a missing `android.uid.system` or
  `ROUND_TRIP_VALID=FAIL`. It now exits 1 when any gate field is not
  `PASS`/`SKIP` (an ABX input still legitimately `SKIP`s).
- **P2 — a shell syntax error stayed green.** `sh -n "$s" && echo ok` puts the
  check on the left of `&&`, where `set -e` does not terminate the step, and a
  loop reports only its last iteration's status. Reproduced: a broken first
  script gave `rc=0`. Now a bare command, which gives `rc=2`.

## Post-review hardening (Codex automated review of `9645c09`)

Four review findings were verified and fixed:
- **P1 — gate every corruption entry point.** `patchLibc`/`patchCxx` (StageReceiver
  transactions 2/3) called `patch_libc`/`patch_cxx` directly, bypassing the
  `patch_ko()` gate. Both now re-run the fail-closed gate at entry.
- **P1 — refuse the unverified module on ZZIC.** `patch_ko()` no longer proceeds
  to corrupt the vendor file with the Gate-G `UNVERIFIED` generic module on the
  ZZIC target. It refused unless `ko_zzic_verified` was set or an operator
  override marker was present; the marker was later removed outright (see
  *Strict Gate-G policy* below), so `ko_zzic_verified` bound to the module digest
  is now the only way through.
- **P2 — compare `kernel_version` + `kernel_arch`.** Both are now in
  `ObservedTarget` and the fail-closed identity check; a rebuilt kernel with a
  matching `uname -r` but different `uname -v`/`-m` is a `MISMATCH`.
- **P2 — `elf_audit.py --root` absolute-symlink rebasing.** Absolute link targets
  now resolve under the pulled root, so Gate F can be closed from a pulled tree.

## The ksud handoff — pinned to the exact RMG ZZIC daemon

The bundled `assets/ksud` was an opaque 6.6 MB binary, unpinned, and demonstrably
**not** the exact ZZIC build. It is now the RMGLabs-Payloads artefact built with
the `dfreroot` staging contract, byte-identical to it:

```text
app/src/main/assets/ksud
SHA-256  f9ba5d98d23606f278d86ea4c60101092da22043486a889f5794c7bf23bac97c
size     6,675,136
```

Verified from the bytes, not from the build log: it contains
`/data/system/dfreroot-ksud` and `/data/system/dfreroot-ksu-ready`, and **zero**
occurrences of either world-writable path the earlier `rmg` contract used. That is
what makes it usable here at all — AGENTS.md §3.6 forbids naming such a directory
anywhere in shipped code, and the audit enforces it by mechanism.

Three things changed together, because any one of them alone would be a hole:

1. **`stage1.S` no longer passes `--stage-from`.** The upstream DFReroot ksud
   accepted it; neither RMG build does — the path is compiled in via
   `stage_daemon_from()`. Measured on the binaries: the clap long-name
   `stage-from` appears once in the old asset and **zero** times in either RMG
   build. `clap` rejects an unknown long option, so passing it would have made
   `late-load` exit on a usage error before doing anything, and the failure would
   have looked like the hop failing.
2. **`ksud_sha256` / `ksud_size` are pinned** in `target_profile.c` and
   `tools/zzic_profile.json`, and `KsudStage` compares the asset bytes **before**
   writing and re-reads the staged file afterwards. Size is checked separately so
   a truncated read is named as truncation rather than as the wrong binary.
   Unpinned is allowed and means `KsudStage` refuses to stage: an unverified
   daemon about to receive uid 0 is exactly the failure shape this repository
   exists to prevent.
3. **The manager-app fallback is removed.** It read the daemon out of whatever
   KernelSU manager happened to be installed and staged those bytes — unpinned,
   third-party, into a uid-0 handoff. With the pin in place that path could only
   be refused, or be the one place the pin did not apply.

`tools/profile_binding_audit.py` guards all of it: digest/size drift between the
two profiles and the Kotlin copy, a bundled asset that does not match the pin, a
bundled ksud that lacks the `dfreroot` path or still carries the forbidden one,
`--stage-from` reappearing in `stage1.S`, the identity signals disappearing from
`KsudStage`, and the fallback coming back. Each was verified by sabotage.

### What this does not establish

`stage_daemon_from()` renames the staged file out of `/data/system` in ksud's
pre-KernelSU bootstrap context — uid 0, but SELinux and DEFEX fully in force, so
`remove_name` on `system_data_file` is **not** proven from there. If it is
refused it must surface as a named refusal, never as a fallback to a
world-writable path. That is the one untested step in the new contract.

Restoring SELinux to `Enforcing` after readiness is published also remains open,
and must be verified rather than assumed.

## Second physical run — `v2.0.4-zzic`, full root path

The exact ZZIC helper and DFR-specific ksud were then exercised on hardware.
Every result below belongs to the same boot:

```text
boot_id=0643a5e2-9a44-4bb9-b7a4-31a3b255e3ac
```

The run repeated the already-proven A/B/C/D boundaries, then passed the newly
opened exact-module boundary:

```text
TARGET_PROFILE=S25U_ZZIC
PASS exact identity
ZZIC_KERNEL_IDENTITY=PASS
ZZIC_KERNEL_VERSION=PASS
ZZIC_KERNEL_ARCH=PASS
ZZIC_PAGE_SIZE=PASS
ZZIC_CRASHDUMP_IDENTITY PASS
ZZIC_VENDOR_PROVENANCE=PASS_AVB
PROCESS_LOOKUP=PASS
REMOTE_COMPONENT_REACHED=PASS
NETWORK_STACK_CAP_EFF=PASS
LIBEXP_LOADED=PASS

ZZIC_MODULE_POLICY=ALLOW
ZZIC_MODULE_SELECTED=PASS
ko_filename=dirtyfrag-android15-6.6-S938BXXUCZZIC.ko
ko_sha256_actual=b941d3234ad57235083f5778ff33c52cd4691aaf620d98be43fbaedc74ae3017
ZZIC_MODULE_BINDING=PASS
```

All six page-cache stages completed. The stage-specific runtime checks observed
`ZZIC_LIBC_IDENTITY PASS` before the libc write and
`ZZIC_LIBCXX_IDENTITY PASS` before the libc++ write.

The native trigger reached:

```text
mark: 0 0 0 0
mark: 1 1 1 0
runAll done res=0
Done. Check KSU Manager.
```

The current four marker values are `df, dfm2, dfm3, dfm4`; `dfm1` is not
probed by that log line.

Post-run evidence from a KernelSU root shell:

```text
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
getenforce=Permissive
/sys/fs/selinux/enforce=0

/dev/df   present
/dev/dfm2 present
/dev/dfm3 present
/dev/dfm1 absent
/dev/dfm4 absent
```

The kernel log showed active KernelSU control/root handling (`sys_execve su
found`, Samsung KDP task-scoped credential install, and ksu fd installation).

Still in that same boot, manual restoration was executed:

```sh
su -c '/system/bin/setenforce 1'
```

and independently verified:

```text
getenforce=Enforcing
/sys/fs/selinux/enforce=1
uid=0(root) ... context=u:r:ksu:s0
```

KernelSU remained operational after the transition back to Enforcing. Therefore
the hardware has now demonstrated the complete root mechanism and the viability
of the final SELinux restoration. What remains is making that restoration and
its verification part of the automatic completion protocol.

### What the missing dfm1 means

`stage1.S` currently attempts to create `/dev/dfm1` before
`finit_module()`, while SELinux is still enforcing, and the `create_mark`
macro ignores the `openat()` result. A denied marker creation is therefore
silent. Later markers are attempted after the helper has set SELinux permissive,
which explains why `dfm2` and `dfm3` can exist while `dfm1` does not.

That is a telemetry defect, not evidence that stage2 was skipped: `dfm2` and
`dfm3` are reached later in the same stage2 path, and KernelSU was physically
functional.

The next implementation should move the positive `dfm1` milestone to after the
expected helper return and check the marker syscall result.

## Gate matrix (never auto-promoted to global compatibility)

"Physical PASS" below means observed on SM-S938B / `S938BXXUCZZIC`, not
inferred from a nearby firmware.

| Gate | Result | Evidence |
|---|---|---|
| A — Target identity | **physical PASS** | all twelve fields matched; `TARGET_PROFILE=S25U_ZZIC`, exact identity PASS |
| B — Kernel identity | **physical PASS** | kernel release/version/arch/page-size all PASS |
| B — `crash_dump64` identity | **physical PASS / pinned** | direct runtime hash matched `9249d664…` |
| B — vendor ELF provenance | **physical PASS_AVB** | exact green/locked/enforcing AVB chain and pinned vbmeta digest matched |
| B — `libc` / `libc++` identity | **physical PASS** | both stage-scoped runtime identity gates passed immediately before their writes in v2.0.4 |
| C — Java/system-server compat | **physical PASS** | Android 17 `scheduleReceiver/12`, `mProcessNames` fallback and `mOnewayThread` all observed working |
| D — NetworkStack identity | **physical PASS** | remote component reached as uid 1073 / `u:r:network_stack:s0`, pinned CapEff matched, `LIBEXP_LOADED=PASS` |
| E — Native packaging | **PASS** | signed release packaging audit |
| F — Userspace ELF audit | **PASS** | exact four target ELFs / symbols / hashes audited |
| G1 — Module loader/import ABI | **physical PASS** | exact helper was hash-bound and the same-boot downstream helper effect occurred; offline acceptance remains `COMPLETE (5/5)` / `COMPATIBLE` |
| G2 — Runtime symbol discovery | **physical PASS** | helper reached the success path that requires the sprint_symbol anchor, kallsyms lookup and `selinux_state` resolution |
| G3 — `selinux_state` layout | **physical PASS** | exact BTF predicted offset 0 and the hardware write produced the expected global enforcing state change |
| G4 — Write safety | **physical PASS** | system remained operational after `enforcing=0`, KernelSU late-load completed and root worked |
| H — Installer / packages.xml | **physical PASS** | injected key survived framework restart; write-path fixes regression-tested |
| I — Automatic safe end state | **physical PASS** | `v2.0.5-zzic`, boot `62e8538c…`: the closeout ran unaided to a same-boot `POST_ROOT_COMPLETE`, and the operator independently read `Enforcing` / sysfs `1`, `su` in `u:r:ksu:s0`, and the pinned daemon installed at `/data/adb/ksud`. See the fourth physical run below |
| AUTO_ROOT_FULL_BOOT — unattended run after a full boot | **PARTIALLY ACCEPTED (still ships disabled)** | `2.0.6-zzic`, boot `2e447aaf…`: the service completed an unattended attempt after a full reboot. Its own per-boot journal — written by `DfrAutoRootService` and by nothing else — read `phase=COMPLETE` / `native_started=1` / `attempts=1` against the same `boot_id` as a valid post-root record, with `Enforcing` / sysfs `1` and `su` in `u:r:ksu:s0`. The gate also covers three boundaries one successful boot cannot speak for, and they are now in different states: a framework restart must trigger nothing (**done**, seventh physical run, with the caveat recorded there), the next full boot must make exactly one attempt (**done**, `2.0.8-zzic`, boot `7d1cea20…`, with the refusal of the boot's second broadcast in the log), and opting out must suppress the next boot (**still untested** — and note that a version bump stops Auto Root through `buildMatches` before `opt_in` is consulted, so "nothing ran after an update" is not evidence for it). Step 7 is therefore why this is not a promotion to PASS (AGENTS.md section 8). It ships OFF: a verified manual completion on the exact build plus an explicit opt-in remain required. See the fifth and seventh physical runs below |

**Conclusion:** the exact ZZIC root chain is now physically demonstrated. The
remaining blocker to calling the automated flow complete is the post-root
closeout: KernelSU control-channel proof, automatic `setenforce 1`, read-back
of `/sys/fs/selinux/enforce == 1`, post-restore KernelSU re-check, and a
same-boot `POST_ROOT_COMPLETE` state.

The implementation plan for that work is now in `docs/HANDOFF.md`.

### Post-root source implementation checkpoint (not physical evidence)

The fail-closed closeout has been implemented in source. RMGLabs-Payloads
workflow run `36180951294` built the DFR profile successfully and published the
exact daemon in commit `a14a331`; those bytes are now bundled and pinned in the
DFReroot branch. This does **not** promote Gate I: the new APK has not been
signed or executed on the phone.

The implementation makes four decisions that future reviews must preserve:

- the DFR ksud's `get_info()` is uncached, because the post-restore proof must
  issue a second real KernelSU ioctl rather than reuse `INFO_CACHE`;
- the exact authority sequence is KSU 32601 / UAPI 2 / late-load proof,
  enforcing restore and sysfs read-back, then a second live KSU proof;
- `/data/system/dfreroot-post-root` is an atomic, same-boot telemetry record for
  the system-UID UI, while `/data/system/dfreroot-ksu-ready` remains only a
  serialization marker;
- stage2 accepts only the helper's intentional `finit_module() == -E2BIG`, moves
  `dfm1` after that result, and never treats isolated `dfm3` as final success.

Host target/profile and contract-shape tests pass. The generated daemon is
`6,675,136` bytes with SHA-256
`f9ba5d98d23606f278d86ea4c60101092da22043486a889f5794c7bf23bac97c`,
and all three DFR pins carry that identity. Gate I remains **PENDING PHYSICAL
ACCEPTANCE** until the offline/build gates pass and the final same-boot
Enforcing state is observed on ZZIC.

### Auto Root source implementation checkpoint (not physical evidence)

The unattended boot path is implemented and **disabled**: `DfrBootReceiver` (boot
broadcasts only), a non-exported `DfrAutoRootService`, the pure `AutoRootPolicy`
(61 host cases) and `DfrRootCoordinator`, which is now the single execution path
for both the button and the boot service.

This promotes nothing. What it adds to the evidence record is negative:

- Auto Root refuses unless a MANUAL run on this exact versionCode, ksud digest
  and `Build.FINGERPRINT` ended in verified same-boot `POST_ROOT_COMPLETE` with
  live `/sys/fs/selinux/enforce == 1`, and the owner then opted in explicitly;
- `BOOT_COMPLETED` is not treated as evidence of a kernel boot: a framework
  restart re-broadcasts it with the same `boot_id`, so neither the boot that
  qualified Auto Root nor the boot it was switched on in can run it, an attempt
  must arrive within 10 minutes of kernel boot, and the per-boot journal is
  durable (`fsync` of the record and of its directory) rather than merely atomic.
  The enforced property is "at most once per boot_id, inside the boot window,
  never in the qualifying or arming boot" — deliberately stated that way rather
  than as "only after a full boot", which the code does not establish;
- whether the platform keeps the boot-time service alive to completion on this
  build is **unproven**. A truncated run fails closed, but the reliability of the
  attempt itself is an acceptance item, and a foreground service is the identified
  remedy if it truncates;
- the `/dev/df` and `dfm*` probe is `stat(2)` plus errno, so a failed lookup
  refuses instead of reading as a clean device;
- `STARTED` is journalled before transaction 5, so no failure after the native
  run can be followed by a second automatic attempt in that boot;
- the retry budget is bounded in the journal, with no alarm or job anywhere on
  the path (the binding audit fails if one appears);
- no gate is weakened, no override exists, and the automatic PASS is the same
  conjunction as the manual one.

`AUTO_ROOT_FULL_BOOT` is **partially accepted** as of the fifth physical run below,
executed after Gate I passed manually, in that order. The run proves the positive
path; steps 5-7 of `docs/AUTO_ROOT.md` — the boundaries a single successful boot
cannot speak for — remain untested, and the gate is not promoted to PASS until they
are.

### Third physical run — `v2.0.5-zzic`, displaced by a pre-existing KernelSU

The first hardware run of the automatic closeout. It did **not** promote Gate I,
and the reason is not a defect in this repository.

```text
boot_id=28beeff3-ffe6-4862-9bd1-128ad8183900
```

Everything up to the handoff passed, in one boot:

```text
TARGET_PROFILE=S25U_ZZIC            PASS exact identity
ZZIC_KERNEL_*                       PASS (identity, version, aarch64, 4096)
KSUD_IDENTITY=PASS                  KSUD_STAGED_VERIFY=PASS (6,670,272 bytes)
PROCESS_LOOKUP=PASS                 REMOTE_COMPONENT_REACHED=PASS
NETWORK_STACK_CAP_EFF=PASS          LIBEXP_LOADED=PASS
ZZIC_CRASHDUMP_IDENTITY PASS        ZZIC_VENDOR_PROVENANCE=PASS_AVB
ZZIC_MODULE_POLICY=ALLOW            ZZIC_MODULE_BINDING=PASS
patch #1..#6                        all six page-cache writes completed
[DFR][MARKER] df=1 helper=1 ns=1 bind=1 exec_fail=0
[DFR][BOOTSTRAP] PASS helper=-E2BIG namespace=private bind=complete
runAll done res=0
```

Then the post-root wait ran its full 120 s and refused:

```text
[DFR][POST_ROOT] pending: completion record absent or empty
```

State observed afterwards, in the same boot:

| Observation | Value |
|---|---|
| `getenforce` | `Enforcing` |
| `su` | `uid=0(root) … context=u:r:ksu:s0` |
| `/data/system/dfreroot-post-root` | **absent — never written** |
| `/data/system/dfreroot-ksud` (staged) | absent; consumed after staging |
| `/data/adb/ksud` | `99aaa607…`, **4,892,712** bytes, mtime inside the run |
| `grep -c POST_ROOT_COMPLETE /data/adb/ksud` | **0** |

The pinned DFR daemon is `14fb9eaf…` at 6,670,272 bytes and **contains** that
string — `tools/profile_binding_audit.py` fails the build if the bundled asset
does not. The daemon left in control therefore is not it.

### What was observed, and what is inferred from it

The distinction matters here more than usual, because the two are easy to blur
and only one of them is evidence.

**Observed.** At observation time the bytes installed at `/data/adb/ksud` are not
the pinned daemon and contain the closeout string zero times. The staged
`/data/system/dfreroot-ksud` was consumed. No completion record was ever
published. Root works, SELinux is `Enforcing`, and the device carries a KernelSU
userspace predating the run: the manager app `me.weishu.kernelsu`, `/data/adb/ksu/`
with an allowlist dated months earlier, and modules (LSPosed, Zygisk Next,
Shamiko, TrickyStore, Specter, bindhosts, meta-overlayfs). The device's own
`sulog` records that installation running `libksud.so install`, which is how
`/data/adb/ksud` gets written there.

**Inferred, and not established.** Which daemon was executing during the run. A
process that has already `execve`d continues from its image even if the file it
came from is later replaced or unlinked, so post-run file contents cannot say who
was running, who caused the timeout, or who owned the session. Three mechanisms
fit every observation above equally well:

1. the DFR daemon ran and took the upstream `install` path, which copies the
   manager's `libksud.so` over `/data/adb/ksud` — overwriting itself before
   reaching the closeout;
2. it exited early on finding an existing installation, and that installation's
   daemon took over;
3. it died after `execve` (which leaves no `dfm4`, since that marker is created
   only when `execve` itself fails).

**Established since**: the installed bytes are byte-identical to the manager
APK's own daemon.

```text
/data/adb/ksud                                     99aaa607…
…/me.weishu.kernelsu-…/lib/arm64/libksud.so        99aaa607…
```

That is identity, not resemblance, and it fixes the *source* of the bytes: they
were copied from the installed manager APK during the run (the file's mtime falls
inside it, and `/data/adb/ksu/bin` and `lib` were rewritten in the same minute,
which is what a KernelSU `install` does).

It still does not name the process that performed the copy, and the two remaining
candidates lead to different fixes:

| Who copied | What it would mean |
|---|---|
| the DFR daemon itself, via the upstream `install` path | a defect in the DFR ksud build: its install path replaces its own binary with the manager's before the closeout can run. The fix is in `RMGLabs-Payloads`, and it would bite on any device with a manager installed |
| the manager app, running its own `install` at that moment | a competing writer, not a defect. Uninstalling the manager for the acceptance run is then sufficient |

**What separates them**, still with no new build: when the manager's process
started. Its window is in logcat (`am_proc_start` / `Start proc` for
`me.weishu.kernelsu`). A process that started *after* the file was written cannot
have written it, which would leave the DFR daemon's own install path as the only
candidate. KernelSU's `sulog` — present on this device but switched off, its July
log ending in `feature set sulog 0` — records every root `execve` and would bind
the active daemon to its binary directly on the next attempt.

### What this run does and does not establish

- It does **not** promote Gate I: no same-boot `POST_ROOT_COMPLETE`, so no PASS.
  The UI refusing success with root visibly working is the contract behaving
  exactly as designed — "it worked" and "I verified it worked" are different
  claims, and only the second one is a gate.
- It does **not** count as a Gate-I FAIL either: the automatic closeout was never
  reached, so nothing about it was tested.
- It **does** show that a foreign KernelSU daemon can end up installed over the
  pinned one during a run, on a device carrying its own KernelSU userspace, and
  that the completion record does not appear when that happens. Whether that is
  cause or consequence is the open question above.
- It **does** re-confirm, on hardware and in one boot, every gate before the
  handoff — including the exact ZZIC module binding and all six page-cache writes
  — on `v2.0.5-zzic`.

### The precondition, stated at the width the evidence supports

An earlier version of this record turned the inference into a rule: "the
acceptance requires a device with no pre-existing KernelSU or Magisk userspace".
That is both unsupported and, more importantly, **wrong for what this tool is**.
DFReroot is a *reroot*: from the second use onward `/data/adb` is populated —
with modules, an allowlist and a daemon — precisely because the tool put them
there. A rule demanding an empty `/data/adb` would exclude the tool's own normal
state.

What the evidence supports is narrower: the **manager app is the source of the
foreign bytes** in both plausible mechanisms, so an acceptance run should be made
with no KernelSU manager package installed, and the manager should not be opened
during the run. That costs uninstalling one app, not the module set.
`docs/PHYSICAL_TESTING.md` §1 checks for it and says so.

### Fourth physical run — `v2.0.5-zzic`, Gate I closed

The automatic closeout ran to completion on hardware, unaided, in one boot.

```text
boot_id=62e8538c-31c5-4531-9bbe-0045e23cf519
```

Everything through the handoff passed as in the previous run, and then:

```text
[DFR][MARKER] df=1 helper=1 ns=1 bind=1 exec_fail=0
[DFR][BOOTSTRAP] PASS helper=-E2BIG namespace=private bind=complete
runAll done res=0
[DFR][POST_ROOT] WAIT_POST_ROOT: native bootstrap complete; final success is still pending
[DFR][POST_ROOT] pending: completion record absent or empty
[DFR][POST_ROOT] POST_ROOT_COMPLETE=PASS boot_id=62e8538c-31c5-4531-9bbe-0045e23cf519
                 ksu_version=32601 uapi_version=2 runtime_mode=late-load selinux=1
[DFR][POST_ROOT] ROOT_RESULT=SUCCESS
```

The one `pending:` line before the PASS is the wait doing its job: the record did
not exist when the first poll ran, and appeared during the window.

**Evidence, separated by who observed it.** This matters for a gate whose whole
subject is whether a claim can be trusted.

| Fact | Observed by | Value |
|---|---|---|
| same-boot completion record | ksud (telemetry), read and validated by the app | `state=POST_ROOT_COMPLETE`, `boot_id=62e8538c…`, `ksu_version=32601`, `uapi_version=2`, `runtime_mode=late-load`, `selinux=1` |
| live SELinux at the end of the run | the app, as a term of its own verdict | `1` |
| **SELinux, independently** | operator, `su -c 'getenforce; cat /sys/fs/selinux/enforce'` | `Enforcing` / `1` |
| **KernelSU control alive** | operator, `su -c 'id; cat /proc/self/attr/current'` | `uid=0(root) … u:r:ksu:s0` |
| **same boot** | operator, `/proc/sys/kernel/random/boot_id` | `62e8538c…`, equal to the record's |
| **the daemon in place is the pinned one** | operator, `sha256sum /data/adb/ksud` | `14fb9eaf…`, 6,670,272 bytes |

The last row is the direct contrast with the previous run, where the same path
held `99aaa607…` at 4,892,712 bytes. It is a measurement, not an inference.

**What is promoted.** Gate I — automatic safe end state — to **physical PASS**.
The chain now reaches, without human intervention: KernelSU control proven,
SELinux restored to `Enforcing` and read back, control proven again, a same-boot
record published, and only then a green UI. Three of those five are corroborated
by operator-side reads that do not pass through the daemon's own telemetry.

**What is not resolved.** Why the third run did not publish. Two things changed
between the two runs and the reboot changed both at once:

- the manager app was not opened during this run;
- in the failed run the `system_server` side was hosting a **stale APK path** —
  its `classloader` named `~~LNLuKJ9…` while `network_stack` had `~~ZM-pqZr…`,
  and `NATIVE_PAYLOAD_PACKAGED` came back `UNKNOWN (NoSuchFileException)`. In this
  run both name the same path and it reads `PASS`. The app had been updated
  without a soft reboot, so the old `LoadedApk` was still resident.

One trial does not isolate a cause between two changed variables, so neither is
recorded as the reason. The staged bytes were verified identical in both runs
(`KSUD_IDENTITY=PASS`), so the difference is not in what was staged.

## Post-root compatibility — DEFEX / Zygisk Next / LSPosed

This is a separate compatibility axis from Gate I's root-safe-completion state.

The exact ZZIC KernelSU build already includes the permanent narrow
LSPosed/DEFEX compatibility patch. The isolated exact-port workflow in
`igorcv88/RMGLabs-Payloads` applies:

```text
KernelSU-v3.3.0-samsung-kdp-rkp-defex.patch
apply-v330-staged-daemon-hotfix.py --profile <rmg|dfreroot>
apply-v330-lsposed-defex-fix.py
```

before building the exact ZZIC `kernelsu.ko`, and then embeds that module in the
corresponding ksud. The workflow checks that the compiled module retains the
`LSPosed app_process64 exception enabled` signature.

The exception is intentionally narrow: root `app_process64` opening the exact
LSPosed Zygisk library path:

```text
/data/adb/modules/zygisk_lsposed/zygisk/arm64-v8a.so
```

It does not globally disable Samsung DEFEX and must not be widened during the
post-root closeout work.

Current evidence must be kept separate:

| Question | State |
|---|---|
| Is the LSPosed/DEFEX patch present in the exact ZZIC KernelSU build? | **PASS (build-time)** |
| Is that patched exact module embedded in the DFR-specific ZZIC ksud? | **PASS (build-time)** |
| Did a KernelSU module containing that patch late-load successfully on ZZIC? | **physical PASS** |
| Does the LSPosed-specific exception itself work on ZZIC under the final Enforcing state? | **PENDING physical validation** |
| Was the equivalent narrow exception previously proven on S938BXXUCZZI4? | **physical PASS on ZZI4 only** |

Therefore the next ZZIC release must preserve the patch while rebuilding the
DFR-specific ksud, but `POST_ROOT_COMPLETE` must not depend on LSPosed being
installed. After the core safe-completion state is proven, a separate physical
post-root test should validate Zygisk Next + LSPosed while SELinux is Enforcing.

The strongest ZZIC evidence should include:

```text
POST_ROOT_COMPLETE=PASS
getenforce=Enforcing
/sys/fs/selinux/enforce=1
expected LSPosed library path present
new app_process64/app process exercises the compatibility path
no matching DEFEX Immutable Root violation
LSPosed active for new processes
KernelSU root remains functional
```

If the framework side requires a controlled zygote restart, perform it only
after the core post-root completion state has been captured, then additionally
verify `system_server` maps the LSPosed Zygisk library and `LSPosedBridge`
appears without returning SELinux to permissive.

Track that outcome separately as, for example,
`POST_ROOT_LSPOSED_COMPAT=PASS|FAIL|SKIP_NOT_INSTALLED`. A failure here is a
post-root compatibility regression, not evidence that the root chain itself
failed.

The concrete implementation/test plan is merged into `docs/HANDOFF.md` Phase 3
and the later test/physical-acceptance phases.

## Historical hardware collection procedure (before v2.0.4)

The commands below are retained as provenance for how the earlier unknowns were
closed. They are **not** the current work queue. The current remaining work is
the automatic post-root closeout described in `docs/HANDOFF.md`.


```sh
# Identity, provenance and Gate G inputs — one read-only pass
sh tools/zzic_collect.sh > zzic-identity.txt 2>&1

# Gate B/C/D — run DFReroot, capture logcat tagged DFReroot / [DFR]
adb logcat -s DFReroot DirtyFrag | grep '\[DFR\]'

# Gate F — pull the artefacts and audit against the pinned hashes
adb pull /system/lib64/libc++.so ./pulled/
python3 tools/elf_audit.py --root ./pulled

# Gate G — resolve UNVERIFIED with the ZZIC kernel symbol table
python3 tools/ko_audit.py app/src/main/jni/dirtyfrag-android15-6.6.ko \
    --symvers Module.symvers --kallsyms kallsyms.txt

# Gate H — audit the device packages.xml (or the .bak-df-installer backup)
adb shell su -c 'CLASSPATH=/data/local/tmp/df_installer.apk app_process /system/bin \
    com.polygraphene.df.installer.InjectMain --diag-zzic'
```

## Historical Gate-G bring-up record

One blocker remains. The two that `v2.0.2-zzic` stopped at are closed.

### Closed — `crash_dump64` SHA-256

Captured from the device and pinned in both places (the CI drift check enforces
that they agree, and now also that the top-level field and the `targets[]` entry
in `tools/zzic_profile.json` agree with each other):

```
9249d66445837c52322c2c86ee62efa64e49a7c1b72084c1ce98f72c12a1151f
```

It is a direct runtime SHA-256 check, because — unlike the vendor ELF —
`crash_dump64` **is** readable from the domain the chain runs in.

### Closed — vendor ELF identity

Redesigned as `ZZIC_VENDOR_PROVENANCE`; see "Vendor ELF: why the direct hash was
the wrong proof" above. Still fail-closed, still refuses on any divergence, but
the proof no longer requires a read the architecture itself avoids.

### Closed — a Gate-G validated kernel module

The device confirms `CONFIG_MODVERSIONS=y`. The bundled
`dirtyfrag-android15-6.6.ko` shares the ZZIC kernel's GKI base (`6.6.127`) and
page tag (`4k`) but ships an **empty `__versions` table**, so no symbol-CRC
agreement can be demonstrated. It is `UNVERIFIED`, and an ABI-mismatched module
can fault the kernel.

Matching the base version and the page size is **not sufficient** with
`CONFIG_MODVERSIONS=y`, and must never be treated as if it were.

`Module.symvers` is a kernel **build** artefact. It is not present on a running
Android filesystem, so searching the device for it is not a valid route. One of
these is needed:

- the `Module.symvers` from the exact ZZIC kernel build;
- a module rebuilt from the matching source, config and toolchain;
- another verifiable source of that kernel's symbol CRCs.

Then:

```sh
python3 tools/ko_audit.py <new-module.ko> \
    --symvers <exact-Module.symvers> --kallsyms <captured-kallsyms.txt>
```

#### Modversion coverage is part of that verdict

Comparing only the entries `__versions` *happens to contain* is fail-open. The
kernel's `check_version()` walks the table for the symbol it is resolving and
refuses the load when the table exists but names no version for it (`no symbol
version for %s`); `CONFIG_MODULE_FORCE_LOAD` is not set on this kernel, so there
is no escape hatch. A table covering three of four imports is therefore
**unloadable** — yet an entries-only diff finds every present entry in agreement
and would read `COMPATIBLE`.

So `ko_audit.py` requires, and reports separately:

```text
MODVERSION_COVERAGE          imports_requiring_modversion - __versions entries == {}
modversion_missing_entries   the imports with no entry, named
modversion_unresolvable_imports  imports absent from Module.symvers entirely
SYMBOL_HAS_MODVERSION_ENTRY  per symbol, distinct from MODVERSION_MATCH
```

Rules that follow from that:

- A hole in the table is `INCOMPATIBLE` when a `Module.symvers` is supplied, and
  is reported as a **hole**, never as a CRC mismatch — different failure,
  different fix.
- An import absent from `Module.symvers` is a separate, harder failure: the load
  dies on `Unknown symbol` before any version check runs.
- A weak (`STB_WEAK`) undefined symbol is exempt **only when the kernel does not
  export it**. `resolve_symbol()` runs `check_version()` whenever it finds the
  symbol and returns `ERR_PTR(-EINVAL)` on failure; an error pointer is not NULL,
  so `simplify_symbols()`' `!ksym && STB_WEAK` escape hatch does not apply. An
  *exported* weak import with no entry fails the load like a strong one. The
  hatch only covers a weak symbol the kernel exports nowhere, which stays
  unresolved at zero. With no `Module.symvers` this is undecidable: reported
  `UNDECIDED`, refused under `--require-modversion-coverage`, never assumed
  exempt.
- Coverage is decidable from the `.ko` alone, so it is always reported. Without a
  `Module.symvers` the verdict still stays `UNVERIFIED` — absent evidence is not
  a defect in the module — unless `--require-modversion-coverage` is passed, which
  the new-module acceptance path **must** pass:

```sh
python3 tools/ko_audit.py <new-module.ko> --require-modversion-coverage \
    --symvers <exact-Module.symvers> --kallsyms <captured-kallsyms.txt>
```

`tools/tests/test_ko_audit.py` carries one negative case per element, including
the one this rule exists for: a partial table whose every present entry agrees.
`tools/profile_binding_audit.py` exercises `ko_audit` on the bundled modules and
fails if a named hole ever stops being fatal, so the rule cannot be refactored
away silently.

`MODULE_VS_ZZIC_KERNEL = COMPATIBLE` is the only result that justifies setting
the three profile fields, and they move together or not at all:

```c
.ko_zzic_verified = 1,
.ko_filename      = "<exact filename>",
.ko_sha256        = "<sha256 of exactly those bundled bytes>",
```

`tools/profile_binding_audit.py` fails the build if the flag is set without a
digest, if the digest does not match the bundled file, or if a digest is left
pinned while the flag is 0. The module imports only `sprint_symbol`, `_printk`,
`memset`, `__stack_chk_fail`; it resolves `kallsyms_lookup_name` and
`selinux_state` at runtime rather than importing them, so those two need
existence evidence, not export evidence.

### Gate G is four boundaries, not one

Collapsing them hides which risk is still open. Each has its own evidence and its
own answer.

| Sub-gate | Question | State |
|---|---|---|
| **G1** loader / import ABI | does the exact ZZIC `dirtyfrag.ko` load? | **physical PASS**; before hardware execution the exact module already audited `COMPATIBLE`, `COMPLETE (5/5)` |
| **G2** symbol discovery | does the runtime `sprint_symbol` scan find `kallsyms_lookup_name` and `selinux_state`? | **physical PASS**; the helper reached the success path and changed the observed enforcing state |
| **G3** `selinux_state` layout | is `enforcing` the first field used by the helper? | **physical PASS**, consistent with the exact ZZIC BTF prediction (128-byte struct, `enforcing` at bit offset 0) |
| **G4** write safety | is writing 0 there viable on this running kernel? | **physical PASS**; the phone remained operational, KernelSU late-load completed and root worked |

#### G1 — what closed it, and what it cost to find out

`dirtyfrag-android15-6.6-S938BXXUCZZIC.ko`, built by
`.github/workflows/build-zzic-dirtyfrag.yml` (run 36166575861), bundled at
`app/src/main/jni/`:

```text
sha256    b941d3234ad57235083f5778ff33c52cd4691aaf620d98be43fbaedc74ae3017
size      6592 bytes (stripped)
vermagic  6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k SMP preempt
          mod_unload modversions aarch64
__versions  5 entries, 0x140 bytes

tools/ko_audit.py <that file>
  --symvers            evidence/zzic/gate-g/ZZIC-derived-minimal.symvers
  --symvers-provenance evidence/zzic/gate-g/ZZIC-modversion-provenance.json
  --require-modversion-coverage
=> MODVERSION_COVERAGE  = COMPLETE (5/5)
   MODULE_VS_ZZIC_KERNEL = COMPATIBLE
   symvers               = 340b840d63f3dd6fabe589aff9b52d365ee1c568e8303b47a052c3da7ac0a5dd (DERIVED)
```

An independent local build in the same image produced the **same digest**, so the
artefact is reproducible rather than one runner's output.

Two findings came out of getting there, both of which had been silently defeating
the build:

**The DDK ships a modpost that cannot emit versions.**
`ghcr.io/ylarod/ddk-min:android15-6.6-20260828` has two lines commented out of
`scripts/mod/modpost.c` — `s->module = exp->module;` in `check_exports()`, and
that function's only call site. No import is ever matched to an export, so
`add_versions()` skips every symbol and writes an **empty** table, with no
warning, because the code that would have warned is the code that was removed.
Three runs produced a 0-byte `__versions` and a green exit. The workflow now
restores both lines, rebuilds `modpost` from the restored source, and refuses if
the rebuilt binary is byte-identical to the shipped one.

**`module_layout` is required and nobody imports it.** With modpost fixed, the
table gained a fifth entry carrying the DDK's `0x4e276f37` instead of the
target's `0x81972209`. `check_modstruct_version()` version-checks that symbol
before resolving any other, and its CRC summarises the layouts the loader itself
walks — but the module never references it, so it is absent from the undefined
symbol table and an import-driven coverage rule cannot see it. A module with the
DDK value passes every offline check and is refused at `insmod`. It is now in the
derived table (its CRC read out of the same kernel-ratified witness bytes), in
`ko_audit.py`'s `KERNEL_CHECKED_WITHOUT_IMPORT`, and in the workflow's
committed-evidence gate.

A correction belongs here too, because this document rests on it: the claim that
the kernel refuses a load when `__versions` exists but names no version for a
symbol being resolved is **false** on this kernel. `check_version()` warns once
and the load proceeds. Coverage is still required — a hole stops the *checking*,
not the module, so it loads with that symbol unverified, which is the failure this
gate exists to prevent. The refusal is "unverified", not "unloadable".

**The generic android15-6.6 module is untouched.** It still carries an empty
table and is still what every other android15/6.6 device gets. The ZZIC image is
reachable only from the `DFR_TARGET_S25U_ZZIC` branch in `patch_ko()`, never from
`dfr_select_ko_image()`, because family selection keys on `(15, 6, 6)` and cannot
tell the two apart. `tools/profile_binding_audit.py` fails if that image ever
appears in `ko_images[]`, or if the identity branch stops selecting it.

Two consequences worth stating plainly.

**`CONFIG_MODVERSIONS` protects G1, not G4.** A CRC agreement says the loader will
accept the imports. It says nothing about whether the module's own logic — finding
an address by name and writing to it — is safe. Those are different claims and
must never share a verdict.

**An `insmod` test of the real helper is not a clean G1 experiment.** The helper
writes `selinux_state.enforcing = 0` in its init path, so a successful `insmod`
performs G4's risky write as a side effect: you cannot separate "the loader
accepted it" from "the write happened". To close G1, G2 and G3 with no write risk,
build a **probe variant** from the same source with the write compiled out, which
resolves the symbol and reports the address and the layout it sees. A load failure
there is a clean loader/ABI answer (`disagrees about version of symbol` is the
expected shape of a CRC mismatch), and a success plus a reported address closes
G2 and G3 empirically — leaving G4 as the single remaining question, isolated.

### Strict Gate-G policy

The override marker that once let the owner accept the kernel-crash risk was
removed rather than kept, and CI now rejects its reintroduction under any name
(`tools/profile_binding_audit.py` scans every DFReroot runtime source for a
`/data/local/tmp` reference, not just the one historical token). The practical
consequence is worth stating plainly: until a Gate-G `COMPATIBLE` module exists,
the chain cannot be exercised end to end on this firmware at all — not even
deliberately. That is the intended trade-off, and reversing it is a policy
decision for the repository owner, made in the open, not a patch an agent applies
on its own.

### Runtime evidence captured on hardware

The v2.0.4 run supplied the downstream runtime evidence that was missing when
this section was originally written. Keep the table below as a map from evidence
to boundary; current gate states are authoritative in the matrix above.


Everything else in the gate matrix needs a logcat capture from the device, and
each item names the boundary that produces it:

| Needed | Produced by | Log line |
|---|---|---|
| AMS / ProcessRecord / IApplicationThread shapes (Gate C) | run DFReroot, capture logcat | `[DFR][AMS] *` |
| `scheduleReceiver` overload shape | same | `[DFR][AMS] scheduleReceiver/<n>` |
| network_stack identity (Gate D) | StageReceiver in network_stack | `[DFR][PROCESS] REMOTE_COMPONENT_REACHED` |
| `libexp.so` actually loaded | StageReceiver | `[DFR][PROCESS] NATIVE_LIBRARY_DISCOVERABLE` + load outcome |
| packages.xml semantics (Gate H) | `InjectMain --diag-zzic` | `[DFR][INSTALLER] *` |

```sh
adb logcat -c && adb logcat -s DFReroot DirtyFrag | tee zzic-run.log
grep '\[DFR\]' zzic-run.log
```

`scheduleReceiver` is **no longer an unknown**: the 12-parameter overload the
hop invokes was observed on Android 17 / One UI 9 and worked (see "Gate C"
above). The rule that produced that outcome still stands for the next firmware —
never guess a fallback overload, because invoking an unknown shape with
fabricated arguments runs inside `system_server`. Wire a new shape only from an
observed `[DFR][AMS] scheduleReceiver/<n> params=[...]` line.

Record `/proc/sys/kernel/random/boot_id` with any capture: per dossier section 45,
states from different boots must never be combined into one successful chain.

## Runtime evidence fields added in this pass

`Diagnostics.processIdentity()` now records, at every boundary it is called from:

- the full capability/hardening set as separate fields — `CapInh`, `CapPrm`,
  `CapEff`, `CapBnd`, `CapAmb`, `NoNewPrivs`, `Seccomp`, `Seccomp_filters`
  (dossier §17 and §44), so a denial can be attributed to the right mechanism
  rather than to "the CapEff bit the profile happens to pin";
- `boot_id` from `/proc/sys/kernel/random/boot_id` (§45), so states captured
  across different boots cannot be combined into one apparently successful chain;
- `REMOTE_COMPONENT_REACHED`, requiring observed uid **and** process name **and**
  SELinux context to agree with the profile.

`NETWORKSTACK_PROCESS_FOUND` and `REMOTE_COMPONENT_REACHED` remain **separate**
signals with separate values (§22, §48): one says a network_stack-uid process was
observed, the other says our component actually executed inside it. They are not
collapsed into a single indicator.

`StageReceiver` reports `LIBEXP_LOADED=PASS|FAIL` as its own boundary (§23),
distinct from `NATIVE_LIBRARY_DISCOVERABLE`: the library existing on disk and a
successful `dlopen` inside the network_stack domain are different facts.


### Fifth physical run — `2.0.6-zzic`, unattended after a full reboot

The acceptance run for `AUTO_ROOT_FULL_BOOT`. Nothing was pressed: the device was
rebooted, unlocked, and root was present.

```text
boot_id=2e447aaf-dc02-4cb7-851c-d79f73f94282
```

`/data/system/dfreroot-autoroot-journal`:

```text
boot_id=2e447aaf-dc02-4cb7-851c-d79f73f94282
phase=COMPLETE
attempts=1
native_started=1
```

`/data/system/dfreroot-post-root`:

```text
state=POST_ROOT_COMPLETE
boot_id=2e447aaf-dc02-4cb7-851c-d79f73f94282
ksu_version=32601
uapi_version=2
runtime_mode=late-load
selinux=1
```

Operator-verified in the same boot: `getenforce` → `Enforcing`,
`/sys/fs/selinux/enforce` → `1`, `id` → `uid=0(root) … context=u:r:ksu:s0`,
`/proc/uptime` → 380 s.

**Why this promotes the gate and a working `su` would not have.** The journal is
written by `DfrAutoRootService` and by no other code path — `MainActivity` never
touches it. So `phase=COMPLETE` on this `boot_id` is the only artefact that
distinguishes "the automatic service ran the chain" from "the chain ran". Root
being present after a cold boot proves the chain ran (KernelSU is late-loaded and
does not survive a kernel restart); it does not, on its own, say which caller
started it.

**`attempts=1` is the load-bearing detail for the two risks this audit had
flagged.** It means the *first* `AutoRootPolicy.evaluate()` already allowed: at the
first broadcast `sys.boot_completed` was 1, no marker existed, SELinux read 1 and a
NetworkStack process was visible. No readiness poll was ever recorded, so the
10-minute readiness budget and the 12-poll backstop were nowhere near binding, and
the CONTROLLER arrived well inside even the 30 s manual deadline.

**What this run does NOT establish.** Whether `LOCKED_BOOT_COMPLETED` (pre-unlock)
or `BOOT_COMPLETED` (post-unlock) drove it. Had the LOCKED broadcast driven it with
`sys.boot_completed` still 0, the journal would read `attempts≥2`; it reads 1. So
the question of whether `/data/system` is readable by this app before the user
unlocks remains open, and the run is not evidence either way. It degrades safely —
a pre-unlock read failure only loses the earlier of two triggers.

**Evidence that was lost, and why.** No `[DFR][*]` line survived in logcat. This
firmware defaults to a **128 KiB** ring buffer per log buffer (`logcat -g`), which
`system_server` saturates in seconds; the whole boot-time trace had rotated out
before a root shell existed to read it. `persist.logd.size=16M` is silently out of
range on this build — `logcat -G 16M` answers `MAX log buffer size is 5 MiB` — so
`5M` is the value that can be honoured at boot. This is why the verdict is now also
posted as a notification: the two `/data/system` records plus the notification are
the evidence channels that do not depend on the log buffer.


### Sixth physical run — `2.0.7-zzic`, and what the soft-reboot button found

The `2.0.7-zzic` release built and installed (`versionCode=20007`), which also
confirms the `compileReleaseKotlin` break in `claimSoftReboot` is fixed. Three
findings, in order of what they change.

**1. No automatic attempt ran in boot `f40c5b44…`, and that is correct.** The
journal still named the previous boot:

```text
current boot   f40c5b44-f92d-4573-9c72-08963fa6ff88
journal        boot_id=2e447aaf-…  phase=COMPLETE  attempts=1
post-root      boot_id=f40c5b44-…  ksu 32601  uapi 2  late-load  selinux=1
```

`DfrAutoRootService.attempt()` always writes the journal, so an untouched journal
means no automatic attempt completed. The reason is the version bump: the
qualification on disk was recorded for `versionCode 20006` and the installed build
is `20007`, so `AutoRootPolicy.buildMatches()` invalidates it. Root in that boot came
from the operator's manual run, which then wrote a fresh `20007` qualification and
armed opt-in for the *next* full boot.

A "Root restored" notification appearing about a minute later was read as a second
automatic run. It was not: `RootNotifier.notifyRunVerdict` is posted by **both**
callers, the manual path included, and the notification does not auto-cancel. The
journal is the discriminator and it says no service run happened. `logcat` could not
corroborate either way — see finding 3.

**Consequence for the acceptance sequence:** step 6 (a later full boot making exactly
one attempt) was not exercised by this boot and is still owed. It is now reachable on
the next full reboot, since the `20007` qualification is armed.

**2. The soft-reboot digest gate was unsatisfiable by construction.** The first tap
produced:

```text
Soft reboot refused
no candidate ksud matches the pinned digest 14fb9eaf…;
found: /data/system/dfreroot-ksud=unreadable /data/adb/ksud=unreadable
```

Both candidates are unreadable to this app, permanently:

```text
ls /data/system/dfreroot-ksud   -> No such file or directory
ls -ldZ /data/adb              -> drwx------ root root u:object_r:adb_data_file:s0
ls -lZ  /data/adb/ksud         -> -rwxr-xr-x root root u:object_r:ksu_file:s0  6670272
```

The staged copy is **consumed** by the chain — `stage1.S` calls
`stage_daemon_from("/data/system/dfreroot-ksud")` — and the daemon it installs sits
in a directory uid 1000 cannot traverse. Note the size: 6,670,272 bytes is exactly
the pinned `ksud_size`, so `/data/adb/ksud` *is* the pinned daemon; it is the reading
that was impossible, not the identity that was wrong.

This is the failure AGENTS.md 3.3 describes, committed by this repository rather than
caught by it. The fix follows that rule's own remedy — the proof changes form, not
whether one is required: the digest is now taken through the proven root shell
(`su -c "sha256sum …"`), still compared to the pinned value, still before the
privileged call. An earlier note in `docs/AUTO_ROOT.md` said `/data/adb/ksud` "was
observed" holding the manager's build; it was observed **as root, from a shell**, and
that was conflated with the app being able to read it.

**3. `persist.logd.size` does not resize the buffers that matter on this firmware.**
After a full boot with `persist.logd.size=5M` set:

```text
main:   ring buffer is 128 KiB
system: ring buffer is 128 KiB
crash:  ring buffer is 128 KiB
kernel: ring buffer is 5 MiB
```

Only `kernel` took the value. `ro.logd.size` and `ro.logd.size.main` are both empty,
so nothing read-only is overriding it. `persist.logd.size.main` / `.system` have been
set and are untested. Until one of them works, `[DFR][*]` evidence from a boot-time
run does not survive to when a root shell exists, and the two `/data/system` records
plus the verdict notification remain the only channels that do.


### Seventh physical run — `2.0.8-zzic`: acceptance step 6 passes

**Step 6 of `docs/AUTO_ROOT.md` — a later full boot making exactly one automatic
attempt — is a physical PASS.** Boot `7d1cea20-f2d7-4285-b6d1-53511a11f3a4`:

```text
journal    boot_id=7d1cea20-…  phase=COMPLETE  attempts=1  native_started=1
post-root  boot_id=7d1cea20-…  ksu 32601  uapi 2  late-load  selinux=1
operator   Enforcing / sysfs 1 / id -> u:r:ksu:s0
```

And for the first time the logcat survived to corroborate it, because
`persist.logd.size.main=5M` works where the global property did not (see below):

```text
13:48:57.026 [DFR][AUTOROOT] boot=android.intent.action.BOOT_COMPLETED handed to DfrAutoRootService
13:48:57.043 [DFR][MARKER] probe of /dev/df failed: errno=13
13:48:57.043 [DFR][MARKER] probe of /dev/dfm1 failed: errno=13
13:48:57.043 [DFR][MARKER] probe of /dev/dfm2 failed: errno=13
13:48:57.043 [DFR][MARKER] probe of /dev/dfm3 failed: errno=13
13:48:57.265 [DFR][AUTOROOT] REFUSED Auto Root already completed in this boot
```

That fragment is the **second** broadcast of the boot being refused because the
journal already recorded `COMPLETE` — which is exactly the one-attempt-per-boot rule
firing, observed rather than inferred. The run itself happened on the earlier trigger.

**A marker-probe observation, recorded because it changes which mechanism is
load-bearing.** After the chain has run, `Os.stat` of `/dev/df*` returns `errno=13`
(`EACCES`) from `system_server`, not `ENOENT` — the markers are `---------- root root`
and the probe cannot see them. `AutoRootPolicy` maps that to `MARKER_UNKNOWN` and
refuses, which is the fail-closed direction, so nothing is weakened. But it means the
marker probe is effectively blind *after* a run, and the **journal** is what actually
carries the one-attempt guarantee. Before the first run of a boot the markers do not
exist, the probe reads `ENOENT` → `MARKER_ABSENT`, and the chain proceeds; that path is
unaffected.

**The log buffer question is settled.** `persist.logd.size` alone moved only the
`kernel` buffer. `persist.logd.size.main` (and `.system`) do work, and were honoured
across two full boots:

```text
main:   ring buffer is 5 MiB (4 MiB consumed, 22 MiB readable)
system: ring buffer is 5 MiB
```

371 `[DFR]` lines were captured from the manual run in boot `6ae7dd04`, against 0 in
every earlier attempt.

**The soft-reboot button answered `NO_ROOT_TRANSPORT`,** and the answer is narrower
than the previous entry in this dossier implied:

```text
[DFR][SOFT_REBOOT] no root transport: java.io.IOException:
  Cannot run program "su": error=2, No such file or directory
```

`ENOENT` from inside `system_server`, while `su` works from Termux. Two causes fit —
the uid is not on KernelSU's allowlist, or `su` is somewhere this process's `PATH` does
not list — and **neither is established**: the KernelSU sources that would settle it
are not at the paths tried for the pinned revision from this environment. The code now
tries `/system/bin/su`, `/debug_ramdisk/su` and `/sbin/su` before the bare name and
logs which started, which **narrows** the `PATH` cause to three conventional locations
without eliminating it: the path of the `su` that works in Termux was never captured,
so a wrapper or an executable anywhere else still explains `ENOENT` from all four. The
observation that closes it is `command -v su` / `readlink -f` read off the device; it
is owed, and until it lands the next tap's `ENOENT` remains ambiguous between the two
causes.

**Step 5 — a framework-only restart triggers nothing — recorded here, which it was
not before.** The observation belongs to boot `2e447aaf…` on `2.0.6-zzic`: after a
soft reboot, `/proc/sys/kernel/random/boot_id` was unchanged and the journal still
read `boot_id=2e447aaf…` / `phase=COMPLETE` / `attempts=1`, i.e. **no new attempt was
recorded**. Root was already present from the earlier automatic run, so nothing
observable would have changed either way; the journal is what carries it.

What that run does **not** establish, stated because it was nearly skipped: the log
buffer was still 128 KiB at the time, so the refusal line itself was never seen, and
an unchanged journal is equally consistent with "the receiver never fired" and "it
fired and refused" — a refusal writes no journal. The mechanism was corroborated
later, in boot `7d1cea20…`, where the **second** `BOOT_COMPLETED` of a boot whose
journal said `COMPLETE` logged exactly the refusal step 5 asks for:

```text
[DFR][AUTOROOT] REFUSED Auto Root already completed in this boot
```

That is the same code path under the same condition (unchanged boot, journal already
COMPLETE), reached by a second broadcast rather than by a deliberately induced
framework restart. Together the two observations cover step 5; neither does alone,
and that is why both are written down.

**Step 7 is NOT closed by what was observed.** Updating to `2.0.8` unticked the Auto
Root box and the following full boot started nothing until a manual run. That is the
**version** refusal, not the opt-in one: the qualification on disk was
`version_code=20007` against an app at `20008`, so `AutoRootPolicy.buildMatches()`
invalidated it before `opt_in` was ever consulted. Step 7 requires a **valid**
qualification for the installed build, the box then unticked, and a full boot that
starts nothing — the `"Auto Root is not opted in"` path. Different code, different
evidence, still owed.

### Ninth investigation — paired Apply Modules transport implemented, physical result owed

The v9 notification action tried `/system/bin/su`, `/debug_ramdisk/su`,
`/sbin/su` and bare `su`; every start failed with `ENOENT`. Termux simultaneously
showed `/system/bin/su` and could use it. `/proc/<system_server>/root/system/bin/su`
was absent, closing the PATH ambiguity: the processes see different mount
namespaces.

The pinned KernelSU source explains the split. sucompat intercepts
`/system/bin/su` only after `ksu_is_allow_uid_for_current(uid)` passes. The DFR app
is uid 1000 in `u:r:system_server:s0`; a Manager grant would therefore target the
shared platform uid, not one app, and is not an acceptable fix.

RMGLabs-Payloads PR #3 added a DFR-profile-only `KSU_IOCTL_GRANT_ROOT` permission.
It requires uid/euid 1000 and the policy-owned `system_server` SID for both helper
and real parent. Mutable task names are not authority; `dfreroot-ksud` remains an
additional contract check only. The normal allowlist and sucompat paths are
unchanged, and workflow guards reject a build that widens uid 1000 or trusts the
parent `comm`.

The manual exact-port build published the paired helper:

```text
ksud-pa3q-S938BXXUCZZIC-dfreroot-v3.3.0
sha256=f9ba5d98d23606f278d86ea4c60101092da22043486a889f5794c7bf23bac97c
```

DFReroot now stages and verifies that helper. A packaged, root-owned launcher
opens it once, hashes the open file description, rewinds it and uses
`execveat(AT_EMPTY_PATH)` on that same descriptor before `debug su --global-mnt`.
This binds the digest to the bytes actually launched instead of to a mutable
pathname, while retaining the `dfreroot-ksud` task name checked by the paired
module. The root shell probes `id`, hashes candidate daemons and re-checks the
chosen daemon in the same shell immediately before `exec ... soft-reboot`.
This is an implementation result, not a physical PASS.
The final APK still owes proof that `system_server` can execute the staged helper
under enforcing SELinux, that the ioctl returns uid 0, and that the soft-reboot
handoff reaches the expected dispatch outcome without changing `boot_id`.

### The exec proof came back negative — 2026-09-29 (tenth physical run)

The paragraph above ends by naming the proof the build still owed: that
`system_server` can execute the staged helper under enforcing SELinux. The
device answered, and the answer is **no**.

```text
[DFR][SOFT_REBOOT] NO_ROOT_TRANSPORT
  IOException: Cannot run program ".../lib/arm64/libdfr_verified_exec.so":
  error=13, Permission denied
```

`SYSTEM_SERVER_EXEC_APK_DATA_FILE = REFUTED`. The verdict is named after the type
that was actually executed, because SELinux decides `execute_no_trans` per target
type: this run tested `apk_data_file` (the packaged launcher) and nothing else.
`SYSTEM_SERVER_EXEC_SYSTEM_DATA_FILE` — the former target, `/data/system/
dfreroot-ksud` — is `UNVERIFIED`, and an absent test is not a refusal any more than
it is a pass. What would settle it is one command, with a file of that label that
the run can remove again:

```sh
su -c 'cp /system/bin/toybox /data/system/dfr-exectest &&
       chcon u:object_r:system_data_file:s0 /data/system/dfr-exectest &&
       chmod 755 /data/system/dfr-exectest &&
       runcon u:r:system_server:s0 /data/system/dfr-exectest true; echo rc=$?;
       rm -f /data/system/dfr-exectest'
```

The redesign below does not wait on that answer, because it removes the exec from
`system_server` altogether; the question matters only to anyone tempted to move the
artefact to a different label and try again.

Four observations fix the verdict that was tested, and none of them rests on an
absent log line:

| observation | what it rules out |
|---|---|
| `PINNED_TRANSPORT_LAUNCHER` passed, i.e. `isFile()` and `canExecute()` (`access(X_OK)`) both true, and `ls -Zl` shows `-rwxr-xr-x system system u:object_r:apk_data_file:s0` | a missing file, a lost `x` bit, a DAC refusal |
| `su -c "<launcher>"` from `u:r:ksu:s0` prints `DFR_VERIFIED_EXEC_USAGE` | a broken ELF, a bad interpreter, a `noexec` mount on `/data` |
| `runcon u:r:system_server:s0 <launcher>` → `Permission denied`, reproduced from a root shell with no app involved | the app, the `ProcessBuilder` argv, the receiver thread |
| `dmesg`: `audit_lost=5545 audit_rate_limit=5 audit_backlog_limit=64` | "no `avc:` line appeared" meaning anything at all — the audit backlog is saturated and dropping records |

The denial is bound to the **domain**, not to the artefact: the same file runs
from `u:r:ksu:s0` and is refused from `u:r:system_server:s0`. `app/src/main/
AndroidManifest.xml` sets `android:process="system"`, so every component of this
app — `DfrSoftRebootReceiver` included — runs inside `system_server` at that
second context. Commit 3f801f2 moved the exec target from `system_data_file`
(`/data/system/dfreroot-ksud`) to `apk_data_file` (the packaged launcher). That
did not fix anything, and the evidence here does not say it could not have: it
says the executing domain never changed, and that the type it moved *to* is
refused. Whether the type it moved *from* is refused as well is the `UNVERIFIED`
question above.

**This refutes the transport's shape, not its authorization boundary.** The
paired module's `dfr_system_server_child_transport()` requires the caller to
*hold* the `system_server` SID, which is to say it requires an `execve` out of
`system_server` with no domain transition — precisely what the policy forbids for
`/data`. Contract and policy are incompatible as long as root is obtained *after*
an exec. Obtaining it *before* one is not blocked by the same rule: the module
reads `current`, so a plain `fork()` of the app's thread already satisfies uid,
caller SID and real-parent SID with nothing executed, and `escape_with_root_
profile()` then calls `setup_selinux(profile->selinux_domain)` — observed on this
device as `u:r:ksu:s0`, a domain that does execute the same file, per the second
row of the table above.

That redesign is not implemented here. It needs the KernelSU v3.3.0 UAPI at
`932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e` (the `ksu fd` seen installed in
`dmesg`, and the grant ioctl on it), which is not in this repository. Until it
is read first-hand, `SOFT_REBOOT_TRANSPORT` stays `BLOCKED` and no code here
claims otherwise.

### The supercall rebooted the device — 2026-09-29 (eleventh physical run)

The grant-before-exec transport shipped and was tapped once. The device did a
full reboot and lost root; Auto Root re-rooted it on the next boot, which is why
the session that produced this evidence had root at all.

**`KSU_DRIVER_FD_SUPERCALL = DESTRUCTIVE_ON_ZZIC`**, and the daemon was never
reached. What proves the second half is an absence, and it is worth stating
exactly because a later run will not have this luxury:

| record | state after the reboot | what it means |
|---|---|---|
| `/data/system/dfreroot-softreboot-lock` | **absent** | created with `createNewFile()` before ksud is invoked, and only replaced by a newer claim — so no dispatch was ever claimed |
| `/data/system/dfreroot-post-root` | present, **current** boot_id | Auto Root ran after the reboot and completed; the root in hand is the new one |
| `/sys/fs/pstore/`, `logcat -L` | empty | no pre-reboot log survives on this device |
| `/proc/last_kmsg` | bootloader (ABL) log only | `reboot_reason = 0x4`; not a kernel log, so it names nothing about the cause |

With the daemon excluded, the teardown happened inside the probe, and the probe
had gained exactly one privileged syscall over the previous build: the magic
supercall that asks for the KernelSU driver fd,
`syscall(__NR_reboot, 0xdeadbeef, 0xcafebabe, 0, &fd)`, read out of the pinned
daemon's own bytes. The causal link is circumstantial — no kernel log survived —
but the cost asymmetry is not: every test of it costs a reboot and a root
session.

**That paragraph's original sequel was wrong, and is corrected here.** It said
the call could not have worked because `CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y`
leaves no supercall handler. Reading the KernelSU source at the pinned SHA
(`932014ab…`, `kernel/supercall/supercall.c`) shows otherwise:

- `ksu_supercalls_init()` is called unconditionally from `kernelsu_init()` and
  registers a kprobe on `__arm64_sys_reboot`. It is independent of the syscall
  dispatcher and of `NO_PATCH_TEXT`, so the handler **was** present;
- `reboot_handler_pre()` performs **no permission check at all** — it compares
  the two magics, queues a `task_work` that calls `ksu_install_fd()`, and
  returns 0. So the driver fd is available to any caller, including a
  `system_server` child;
- returning 0 does not suppress the syscall, so the real Samsung
  `__arm64_sys_reboot` runs afterwards **by design**, not for want of a handler;
- KernelSU treats that syscall as one these callers normally may not make:
  `ksu_handle_setresuid()` whitelists `__NR_reboot` in the task's seccomp cache
  for the manager and for allowlisted uids only.

So the cause of the reboot is **UNEXPLAINED**, not "an unhandled supercall". The
removal stands on the observation alone: it happened, ksud did not run, and no
pre-reboot log survives to say more.

The supercall is removed, and AGENTS.md 3.6.1 now forbids naming the reboot
syscall in any source that ships inside this app, enforced by mechanism.

**What this leaves.** `init_driver_fd` in the same bytes tries the safe half
first: scan `/proc/self/fd` for a link containing `[ksu_driver]`. That half
stays, and on this firmware it finds nothing, so the transport refuses at
`DFR_SU_STEP_DRIVER_FD` and executes nothing. `dmesg` shows where the fd does
come from here — `sys_execve su found` immediately before `ksu fd installed` —
i.e. the sucompat interception, whose Samsung pre-filter
(`samsung_sucompat_should_redirect`) gates on `ksu_is_allow_uid_for_current()`,
the uid allowlist, not on the `allowed_for_su()` predicate the DFR patch
extends. Allowlisting uid 1000 remains the wrong boundary: it is the shared
platform uid.

**The module-side blocker stated here was also wrong.** It read: "the fd install
has to accept the caller `allowed_for_su()` already accepts". It already does —
the install is ungated, and `KSU_IOCTL_GRANT_ROOT` is gated by `allowed_for_su()`,
which the DFR patch already extends to this caller. No module change is needed
for either step.

What is actually missing is a **non-destructive way to trigger the install**.
The only trigger in the source is the magic reboot, which AGENTS.md 3.6.1 now
forbids until the reboot is explained. `SOFT_REBOOT_TRANSPORT` therefore stays
`BLOCKED` on that, and the shape of any module change is different from what was
written here: not widening an authorization, but adding a trigger that does not
fall through to `sys_reboot`.

### The panic record named it — 2026-09-29 (the reboot, explained)

Samsung keeps a panic summary that survives `panic=-1` even at
`ro.debug_level=0x4f4c` (LOW), where `pstore` and `logcat -L` are empty. It
ends the investigation:

```text
$ cat /sys/class/sec/sec_hw_param/extra_info
"RR":"KP","RWC":"559","KTIME":"61.884533","CPU":"3","TASK":"dfreroot-ksud",
"FAULT":"pgd=0000000000000000 VA=0000000000000000 ...",
"PANIC":"synchronous external abort",
"PC":"allowed_for_su+0x12c/0x248 [kernelsu]",
"LR":"allowed_for_su+0x11c/0x248 [kernelsu]"

$ cat /sys/class/sec/sec_hw_param/extrc_info      (kernel log at the panic)
[61.884299] [3: dfreroot-ksud:16452] KernelSU: ksu fd installed: 96 for pid 16452
[61.884311] [3: dfreroot-ksud:16452] KernelSU: [16452] install ksu fd: 96
[61.884451] [3: dfreroot-ksud:16452] Internal error: synchronous external abort:
            0000000096000010 [#1] PREEMPT SMP
```

`/proc/reset_summary` states the same verdict in words: `UPLOAD CAUSE =
0xc8000000 = KERNEL PANIC ( panic_msg = synchronous external abort: Fatal
exception  PC = allowed_for_su+0x12c/0x248 [kernelsu] )`.

**`SUPERCALL_DESTRUCTIVE = REFUTED`.** The magic reboot did exactly what it was
supposed to: `ksu fd installed: 96`, for a task named `dfreroot-ksud` — the
forked `system_server` child this transport creates, with the `prctl` name the
paired module's contract asks for. The fd install works for this caller, as the
source said it would.

**`GRANT_PANICS_ON_KDP = CONFIRMED`.** 152 µs later the kernel took a
synchronous external abort (ESR `0x96000010`: EC `0x25`, ISS `0x10` — SEA not on
a translation-table walk) with the PC inside `allowed_for_su()`, which is where
the DFR predicate is inlined. `panic_on_oops=1` and `panic=-1` made that an
immediate reboot with no log, which is why three earlier rounds of reasoning had
nothing to stand on and two of them guessed wrong.

**The cause is a missing KDP wrapper in the paired module.** The predicate added
by `apply-v330-staged-daemon-hotfix.py` reads the real parent's credentials as:

```c
parent_cred = get_task_cred(parent);
parent_is_system_server = is_system_server(parent_cred);
put_cred(parent_cred);
```

The only other `get_task_cred()` in the module, in `kernel/hook/tp_marker.c`, had
its `put_cred()` replaced with `ksu_put_cred()` by the Samsung KDP patch —
because with `CONFIG_KSU_SAMSUNG_KDP=y` a `struct cred` is hypervisor-protected
read-only and its refcount must go through `kdp_usecount_dec_and_test()`. The
DFR predicate was written afterwards and kept the raw `put_cred()`. Touching
that refcount is a write to a stage-2 read-only page, which is precisely a
synchronous external abort.

This is a **bug**, not an authorization boundary: the fix changes how a
credential is read, not who may pass. Reading the parent's SID under the RCU
lock already held — `__task_cred(parent)`, no reference taken — is both
KDP-safe and smaller than what is there now.

**Consequences for the record.** Two verdicts written earlier in this file were
attributions without evidence and are withdrawn: the supercall is not
destructive, and this firmware is not the reason it looked that way. The
standing verdicts are the two above. Whether the app restores the supercall is
the owner's decision and depends on the module fix landing first; until then the
transport still refuses at `DFR_SU_STEP_DRIVER_FD` and executes nothing.
