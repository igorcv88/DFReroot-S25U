# DFReroot S25U / ZZIC — handoff

**Where to pick up.** This file is the moving part: current state, what is
blocked, what closes it. It is the only one of the three that is expected to go
stale, so trust it least and re-derive from the audits when in doubt.

- **`AGENTS.md`** (symlinked as `CLAUDE.md`) — the standing rules. Read it
  first, before changing anything. It holds nothing version-specific.
- **`docs/S25U_ZZIC_COMPATIBILITY.md`** — the authoritative gate matrix and
  evidence record. If this file and that one disagree about what is *proven*,
  that one wins.

**State is POST-PHYSICAL-TEST.** It reflects the first hardware execution of the
chain — `v2.0.2-zzic` (versionCode 5) on SM-S938B / `S938BXXUCZZIC` — and the
fixes that run produced, which ship as `2.0.3-zzic` (versionCode 6, PR #8).

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

- the `Module.symvers` from the exact ZZIC kernel build; **or**
- a table derived from the `__versions` sections of stock modules of the exact
  firmware, under the conditions AGENTS.md §3.5 now states — produced only by
  `tools/derive_zzic_symvers.py`, never typed.

The second route is the one that is actually available, and the evidence for it
is committed: `evidence/zzic/gate-g/`.

The resulting module must carry a `__versions` table consistent with
`CONFIG_MODVERSIONS=y`. Matching the GKI base (`6.6.127`) and the 4k page tag is
**not** sufficient and must never be treated as if it were. A captured
`/proc/kallsyms` supplies existence evidence for the two runtime-resolved
symbols.

```sh
python3 tools/ko_audit.py app/src/main/jni/dirtyfrag-android15-6.6.ko \
    --require-modversion-coverage \
    --symvers Module.symvers --kallsyms kallsyms.txt
```

`--require-modversion-coverage` is mandatory on the acceptance run for a newly
built module. A `__versions` table that covers only *some* imports cannot load
(`check_version()` refuses with `no symbol version for %s`, and
`CONFIG_MODULE_FORCE_LOAD` is not set), so the audit requires
`imports_requiring_modversion - __versions entries == {}` and names every hole.
A weak undefined symbol is exempt only when the `Module.symvers` does not export
it — `check_version()` still runs on an exported weak symbol, so one with no
entry fails the load like a strong one; with no symvers it is `UNDECIDED` and
refused under the strict flag. An import absent from `Module.symvers` altogether
is reported separately, as the harder `Unknown symbol` failure.

The audit also records the symvers' digest, because a `Module.symvers` names no
kernel. A module built against a GKI DDK with `kernel.release` forced to the
target string and `KBUILD_MODPOST_WARN=1` gets a full `__versions` table of DDK
CRCs, and audited against that same DDK symvers it reads `COMPATIBLE` about the
wrong kernel. RMGLabs-Payloads builds its `insmod`-loadable DEFEX helper exactly
that way — which is evidence the approach produces a *loadable* module on this
kernel family, and is **not** a substitute for the target's own symbol table.

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

### 5. Dead pins: the four `network_stack_*` fields

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
`docs/S25U_ZZIC_COMPATIBILITY.md`. Today: Gates A, B (kernel / `crash_dump64` /
vendor provenance), C, D, E and H are `PASS` — A/B/C/D/H from the physical run;
Gate G is `UNVERIFIED`; Gates F and I remain `BLOCKED`.
