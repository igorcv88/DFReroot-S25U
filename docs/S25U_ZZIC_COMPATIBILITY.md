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
| Reference version | upstream `v2.0.1`; this fork builds as `2.0.2-zzic` |
| Base commit | `9f1d6cd592d898b42d2e0c2d25ee1577e2aabe77` |
| Branch | `claude/dfreroot-s25u-zzic-support-dgw8fi` |
| Architecture preserved | build system, packages, module table, exploit flow unchanged |

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

`tools/tests/run_tests.sh` (host `cc`, no Android). **36/36 pass.**

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
Execution requires the device (logcat capture) → **BLOCKED** here.

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

## Gate matrix (never auto-promoted to global compatibility)

| Gate | Result | Evidence |
|---|---|---|
| A — Target identity | **PASS** | fail-closed classifier implemented; 36/36 host tests incl. exact ZZIC, all required negatives, and the Gate-G policy verdicts |
| B — Kernel/userspace identity | **BLOCKED** | validation code + pinned hashes implemented; runtime SHA-256/symlink/page-size checks need the ZZIC device |
| C — Java/system-server compat | **BLOCKED** | `[DFR][AMS]` deterministic dumps implemented; needs on-device logcat to compare Android 17 shapes |
| D — NetworkStack identity | **BLOCKED** (process facts already observed on HW) | `[DFR][PROCESS]` instrumentation implemented; runtime capture pending |
| E — Native packaging | **PASS** | real `./build.sh`; `libexp.so` AArch64, all JNI symbols, hashes recorded (apk_audit) |
| F — Userspace ELF audit | **BLOCKED** | tool implemented + host-verified; awaits pulled ZZIC ELFs |
| G — Module ABI compatibility | **UNKNOWN / UNVERIFIED** (runtime-enforced) | ko_audit ran on the real generic `.ko`; empty `__versions`, verdict UNVERIFIED without ZZIC `Module.symvers`. On ZZIC **every** page-cache stage (`patch_ko`, `patch_libc`, `patch_cxx`) refuses while the module is unverified — there is no override — and a `ko_zzic_verified=1` claim is bound to `SHA-256(bundled bytes) == ko_sha256` at run time and in CI |
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

## What is still needed to make the ZZIC path executable

The code is complete and builds; what remains is **evidence**, and the gates are
deliberately wired so that missing evidence refuses rather than assumes. Two
values are hard blockers, in this order.

### 1. `crash_dump64` SHA-256 — blocks Gate B, one command

```sh
adb shell sha256sum /apex/com.android.runtime/bin/crash_dump64
# and, for the full section 26 record:
adb pull /apex/com.android.runtime/bin/crash_dump64 ./pulled/apex/com.android.runtime/bin/
python3 tools/elf_audit.py --root ./pulled
```

Then set the value in **both** places (the CI drift check enforces that they
agree):

- `app/src/main/jni/target_profile.c` → `.crashdump_sha256 = "<hex>"`
- `tools/zzic_profile.json` → `"crashdump_sha256": "<hex>"`

Until then every ZZIC run stops at
`[DFR][USERSPACE] ZZIC_CRASHDUMP_IDENTITY FAIL required hash is not pinned`.

### 2. A Gate-G validated kernel module — blocks the module load

The bundled `dirtyfrag-android15-6.6.ko` shares the ZZIC kernel's GKI base
(`6.6.127`) and page tag (`4k`), but ships an **empty `__versions` table** while
the ZZIC kernel has `CONFIG_MODVERSIONS=y`, so no symbol-CRC agreement can be
established offline. It is `UNVERIFIED`, and an ABI-mismatched module can fault
the kernel. Resolve with the ZZIC kernel's symbol table:

```sh
python3 tools/ko_audit.py app/src/main/jni/dirtyfrag-android15-6.6.ko \
    --symvers Module.symvers --kallsyms kallsyms.txt
```

`MODULE_VS_ZZIC_KERNEL = COMPATIBLE` is the only result that justifies flipping
the flag, and the flag alone is not enough — all three fields go together:

```c
.ko_zzic_verified = 1,
.ko_filename      = "dirtyfrag-zzic-6.6.127.ko",
.ko_sha256        = "<sha256 of exactly those bundled bytes>",
```

`tools/profile_binding_audit.py` fails the build if the flag is set without a
digest, if the digest does not match the bundled file, or if a digest is left
pinned while the flag is 0.

Without a positively validated module, the ZZIC path remains blocked at Gate G —
at **all three** page-cache stages, not just the module write. There is no runtime
escape hatch for an `UNVERIFIED` module; compatibility must be established by
evidence and bound to the exact bundled bytes.

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

### 3. Runtime evidence that no static check can supply

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

`scheduleReceiver` is the one runtime unknown the code cannot work around: the
hop invokes the **12-parameter** overload, and if Android 17 changed that shape
the hop fails with the observed overloads logged. It is deliberately not guessed
at — invoking an unknown overload with fabricated arguments runs inside
`system_server`. Send the `[DFR][AMS] scheduleReceiver/<n> params=[...]` line and
the correct shape can be wired precisely.

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
