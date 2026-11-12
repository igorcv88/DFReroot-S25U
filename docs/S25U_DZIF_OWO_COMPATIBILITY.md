# S25U DZIF/OWO compatibility and evidence record

Authoritative gate matrix and evidence record for `S25U_DZIF_OWO`, the exact
profile for One UI 9 Stable `S938BXXUCDZIF` on the **OWO** multi-CSC.

Companion to `docs/S25U_DZIF_COMPATIBILITY.md` (the OXM sibling) and
`docs/S25U_ZZIC_COMPATIBILITY.md`. Per AGENTS.md §4, when this file and
`AGENTS.md` disagree about what is *proven*, this file wins.

## Identity

| Field | Value |
|---|---|
| profile id | `S25U_DZIF_OWO` |
| class | `DFR_TARGET_S25U_DZIF_OWO` (4) |
| model / device | `SM-S938B` / `pa3q` |
| display | `CP2A.260605.016.S938BXXUCDZIF` |
| fingerprint | `samsung/pa3qxxx/pa3q:17/CP2A.260605.016/S938BXXUCDZIF_OWOCDZIF:user/release-keys` |
| SDK / release | 37 / 17 |
| kernel | `6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCDZIF-4k` |
| `uname -v` | `#1 SMP PREEMPT Sat Sep 19 07:11:26 UTC 2026` |
| arch / page / ABI | `aarch64` / 4096 / `arm64-v8a` |

### Regional scope — read this before describing the profile

This profile pins the `_OWOCDZIF` fingerprint and **nothing else about
region**. It is an **OWO-compatibility** profile, not a ZTO-exclusive one.

The capture does record the sales code, and the property names are now known
rather than guessed:

```
ro.boot.sales_code=ZTO
ro.csc.sales_code=ZTO
ro.boot.carrierid=ZTO
ro.omc.multi_csc=OWO
ro.omc.build.version=S938BOWOCDZIF
mdc.omc.config_version=SAOMC_SM-S938B_OWO_ZTO_17_0008
```

So a ZTO-exclusive gate is *possible*. It is deliberately **not built**: the
owner's decision was OWO compatibility. The consequence is explicit — another
ZTO-less OWO device on this exact firmware classifies as exact, and that is the
documented intent, not an oversight.

`ro.boot.carrier_id`, `ro.csc.carrierid`, `ro.csc.omc_version`, `ro.omc.version`
and `persist.sys.omc_sales_code` all read `UNAVAILABLE` on this firmware. If a
ZTO gate is ever added, use a property that was actually observed, and read it
from the domain that does the checking.

## Evidence provenance

One read-only capture, one boot, no writes:

| | |
|---|---|
| `boot_id` | `52ee18f7-3937-4f99-8dca-c0f51d5d5204` (begin == end) |
| captured | 2026-11-11T12:21:51Z → 12:21:53Z; AVB blobs 09:27Z, same `boot_id` |
| reader | `uid=0(root) gid=0(root) context=u:r:ksu:s0` |
| SELinux | `Enforcing` (`/sys/fs/selinux/enforce` = 1) |
| completeness | `COLLECTION_COMPLETE=YES` |

Evidence from two boots would not be a chain, which is why the `boot_id` is
recorded on both halves and why the AVB manifest's on-device path carries it.

## Artefact hashes

Every value below was read **directly on the OWO device** in that boot. All four
written artefacts hash **identically to OXM** — that was previously an
assumption nobody was allowed to act on, and it is now an observation.

| Artefact | Path | Size | SHA-256 |
|---|---|---|---|
| crash_dump64 | `/apex/com.android.runtime/bin/crash_dump64` | 567912 | `9249d664…1151f` |
| vendor ELF | `/vendor/lib64/libstagefrighthw.so` | 51632 | `308b254a…f8049` |
| libc | → `/apex/com.android.runtime/lib64/bionic/libc.so` | 1330432 | `88fba68b…e861` |
| libc++ | `/system/lib64/libc++.so` | 1152760 | `cb118e98…4d78` |
| BTF | `/sys/kernel/btf/vmlinux` | 6425607 | `e13df32a…950c` |

`kernel_image_sha256` (`b1b300e7…13aa`) was **not** read live — a running kernel
does not expose its own Image. It is carried over from the OWO kernel reference
ZIP recorded in `RMGLabs-Payloads` `support/candidates/pa3q-DZIF-OWO.pending.json`.
The live BTF match is what makes that a carry-over of *evidence* rather than an
assumption, and it remains the weaker of the two kernel anchors.

## Vendor-ELF provenance (AGENTS.md §3.3)

`/vendor/lib64/libstagefrighthw.so` cannot be `open`ed from
`u:r:system_server:s0` or `u:r:network_stack:s0`, so the runtime establishes its
identity through the AVB chain instead. All eleven anchors are pinned and were
observed in the capture boot:

| Anchor | Value |
|---|---|
| `ro.boot.vbmeta.digest` | `b9e6d6cf…14c7` |
| `vbmeta.avb_version` / `hash_alg` | `1.2` / `sha256` |
| `verifiedbootstate` | `green` |
| `vbmeta.device_state` | `locked` |
| `flash.locked` | `1` |
| `veritymode` | `enforcing` |
| `/vendor` fstype / mount | `erofs` / read-only (`dm-10`) |
| vendor ELF size / label | 51632 / `u:object_r:vendor_file:s0` |

**The digest is not merely observed.** It is reproduced offline from the four
committed vbmeta blobs by `tools/verify_dzif_owo_avb.py`:

```
reproduced : b9e6d6cfa5bb6c1f542bcb94dbf68b803126bcac62c05da6eab1ea0ee4b014c7
pinned     : b9e6d6cfa5bb6c1f542bcb94dbf68b803126bcac62c05da6eab1ea0ee4b014c7
chain      : dtbo -> optics -> prism   (avbtool 1.4.0)
VBMETA_DIGEST_REPRODUCIBLE = PASS
```

The signed `vendor` hashtree descriptor also matches the **live** dm-verity
table captured in the same boot, on every parameter — root digest, salt,
version, algorithm, block sizes, 860461 data blocks, hash start, fec offset and
2 fec roots. See `evidence/dzif-owo/avb/README.md`.

`tools/dzif_owo_profile_binding_audit.py` refuses if the reproduced digest, the
JSON profile and the native profile do not all three agree, and refuses if the
live-table comparison is ever skipped.

## NetworkStack

Observed live: pid 4310, `Uid 1073`, `context=u:r:network_stack:s0`,
`CapEff 0000000800003c00`. Pinned as `0x800003c00`.

## Gate matrix

| Gate | State | Basis |
|---|---|---|
| A — identity | **PASS** | every compared field read in the capture boot; 103/103 host checks |
| B — artefact hashes | **PASS (host)** | all four pinned from direct reads; one negative case per field |
| F — ELF | inherited from DZIF | same `/system` and `/vendor` bytes as OXM, confirmed by hash |
| G — module | **as DZIF** | same kernel image; live BTF equals the digest the DZIF witness table was derived from. Shares `DFR_DZIF_KO_*`, so a demotion moves both profiles |
| V — vendor provenance | **PASS** | eleven anchors pinned; digest reproduced offline; live dm table compared |
| ksud / daemon | **PASS (host)** | pinned to the audited DFR managerless build; digest, size and asset bytes agree — see below |
| Physical | **FAIL** | one run, 2026-11-12, refused at the closeout; see below |

## The physical run — 2026-11-12, FAIL

One run. The bootstrap completed (`runAll=0`) and the closeout did not, so the
chain reported FAIL and no `POST_ROOT_COMPLETE` record was published. The
refusal was correct; what this record exists for is what happened before it.

**The device was already rooted by the RMG managerless pair when the run
started.** That single fact produced everything observed:

| Observation | Cause |
|---|---|
| DFR daemon skipped `load_module()` | `ksuinit::has_kernelsu()` was true — the RMG module was live |
| no `/data/system/dfreroot-ko-loaded` | the record is written inside the load branch, which was skipped. Correct, and by design: no record means no `transport_fix`, which means `PostRootStatus.transportFixAllowed()` refuses the supercall |
| `finish_install()` → `EPERM` | its first step relabels `/data/adb/ksud`, and upstream states the precondition in one line: *"The remaining install steps require KernelSU policy"*. That policy arrives when `load_module()` changes the process's security context. On the skip path it never arrives, so the process kept its DirtyFrag bootstrap credentials |
| `/data/adb/ksud` changed from `95b2cc36…` (5 797 976 B) to `6b7246e5…` (5 817 624 B) | `utils::stage_daemon_from()` completes the handoff with `rename(2)` onto that path, unconditionally, **before** the `has_kernelsu()` check. The RMG daemon was replaced by a run that then failed |
| `/data/system/dfreroot-ksud` gone | same `rename(2)` — it was the source |
| cleanup `EACCES` with Enforcing preserved | the daemon's `dfr_restore_selinux_enforcing()` failed from the same constrained context. Enforcing held because `stage1.S` performs its own proven restoration (`x28` + `/system/bin/setenforce 1`); the daemon's attempt is redundant |

Two reporting defects were found while reconstructing this and are fixed:
`apply_modules_offered=true` was logged after `success=false` (the line logged
the caller's parameter, not the action actually attached — none was), and the
coordinator's post-root reader collapsed every read error into "record absent".

### What this does and does not prove

It does **not** demote gate A, B, G or V: every host-side anchor still holds,
and the chain reached its own closeout, which means identity, module and
transport all behaved. It does not promote anything either.

What it establishes is a **contract boundary that was not stated before**:
one device, one persistent KernelSU daemon. `utils::finish_install` has no
parameterised destination — disassembly of this exact daemon shows it does two
things about the daemon, `lsetxattr security.selinux` on `/data/adb/ksud` and a
symlink of `/data/adb/ksu/bin/ksud` at it — so DFReroot and the RMG pair cannot
both own that path. The chain must refuse on a device carrying the other pair,
rather than take the path from it. `RMGLabs-Payloads` PR #29 proposes the two
gates that would make it a refusal before the `rename(2)` instead of after.

**The newly pinned daemon carries both DFR ownership gates.** It was built in
RMGLabs-Payloads workflow `43271383389` and passed the host-side source,
KernelSU module and Secure Late-Load audits. These checks are in the new
candidate, unlike the older `6b7246e5â€¦def2` daemon used in the failed physical
run recorded above. The earlier run and its filesystem changes remain an
unaltered historical observation; the gates have **not** been physically
qualified on this device.

**Another DirtyFrag run is not authorized on a device that still has the RMG
KernelSU module loaded or its foreign daemon persisted.** The new daemon will
refuse before touching `/data/adb/ksud`, but that daemon gate runs after the
native DirtyFrag stage. The owner must separately approve a recovery or
migration procedure before pursuing a new physical Gate 3.

## New ownership-gated candidate: two physical failures, 2026-11-12

The replacement DFR daemon (`30428cd2…9232a33`) was used in two attempts,
with different boot IDs and a full reboot between them. Neither qualified
physical root.

| Boot ID | DirtyFrag bootstrap | Post-root observation | Verdict |
|---|---|---|---|
| `200c9cb5-d329-4c4c-a92f-b20b5fcd40f2` | `df=1 helper=0 ns=0 bind=0`, `runAll=4` | Helper did not take over; daemon never reached | FAIL before daemon |
| `577fab44-5f22-4082-ac9a-616025f500fe` | `df=1 helper=1 ns=1 bind=1`, `runAll=0` | `POST_ROOT_COMPLETE` absent after 120 s | FAIL |

For the **second** boot, the RISH/Shizuku shell (UID 2000) captured decisive
`logcat` lines without root:

```text
16:29:54.307 late-load bootstrap pid=17844 uid=0 selinux=u:r:vendor_modprobe:s0
16:29:54.308 POST_ROOT_COMPLETE=FAIL error=DFR_DAEMON_OWNERSHIP=UNREADABLE
             refusing to replace a daemon whose current bytes could not be read:
             Operation not permitted (os error 1)
16:29:54.323 POST_ROOT_FAILURE_CLEANUP=FAILED
             SELINUX_RESTORE_FAIL=READ_AFTER: Permission denied (os error 13)
```

The daemon **ran**, reached ownership gate 2 and refused before staging over
`/data/adb/ksud`. Since gate 1 did not refuse, that invocation did not
identify a live KernelSU module. The command read of `/data/adb/ksud`
returned EPERM in the `vendor_modprobe` bootstrap context; UID 0 did
not grant access. RISH could also not read its hash, so **the identity of the
persistent daemon is still unknown**. `UNREADABLE` is not proof of FOREIGN.
No same-boot `dfreroot-post-root`, `dfreroot-ko-loaded` or readiness
marker was found. SELinux was Enforcing when observed via RISH, despite
the daemon's failed read-back.

The ownership fix must therefore remain *fail-closed*. The follow-up
RMGLabs patch distinguishes `phase=metadata` from `phase=read` and refuses
non-regular entries, including dangling symlinks; it does not grant access
to the protected daemon. The follow-up DFReroot app preflight tries to
establish presence and, where possible, byte identity **before** another
DirtyFrag transaction. A denied lookup/read is an early refusal; matching
bytes only passes the early tripwire and never bypasses the daemon gate.
These are source-level changes until built and reviewed.

No third physical attempt is authorised by these changes. A safe, explicit
migration or restore procedure for the RMG pair remains separate work.

## The persistent daemon's identity, read as root — 2026-11-12

Closed. The owner captured this through a root shell in boot
`19671080-6ce0-431e-a034-7b5c2b79e1d2` — the same boot in which the app's
preflight answered `errno=13`.

| Reading | Value |
|---|---|
| root identity | `uid=0(root)`, context `u:r:ksu:s0` |
| SELinux | Enforcing |
| `/data/adb/ksud` | `-rwxr-xr-x root root u:object_r:ksu_file:s0`, 5,797,976 bytes |
| SHA-256 | `95b2cc363f420b075c1b1301cb959d29d2cd5845372eb3e89b849d020981d8a5` |
| mtime | 2026-11-12 17:55:46 −0300 |
| `/data/adb/ksu/bin/ksud` | symlink → `/data/adb/ksud` |
| `/proc/modules` | `kernelsu 180224 2 - Live 0x0 (O)` |
| `/sys/module/kernelsu` | ENOENT |

What this establishes:

- **The daemon at that path is the RMG managerless build**, by digest — the same
  `95b2cc36…981d8a5` the dossier recorded before the failed run. The earlier
  note that the 2026-11-12 run "replaced its on-disk daemon with the older DFR
  binary" is superseded for the current state: whatever happened, the RMG binary
  is what is there now, and the mtime says it was written at 17:55. **Which
  operation wrote it is not established** by this capture.
- **The failed run did not damage the RMG installation.** It refused at
  `DFR_DAEMON_OWNERSHIP` before `stage_daemon_from()`, which is the gate working.
- **Root works through the RMG pair in that boot**, which is what makes the
  companion route worth building before anything else.

What it does **not** establish, and must not be read as:

- **It is not an attestation of the loaded module's bytes.** `/proc/modules`
  names `kernelsu` and says `Live`; the name is shared by both pairs and the
  entry carries no digest. A working `su` plus a pinned daemon on disk is strong
  circumstantial evidence and is not the same claim (AGENTS.md §3.12). So this
  capture does not promote `RMG_ACTIVE_VERIFIED`, and the classifier is right to
  report `FOREIGN_KSU_ACTIVE` from it.
- **The missing `/sys/module/kernelsu` is not evidence of absence.**
  `/proc/modules` reports the module Live with a refcount of 2. The sysfs
  directory's absence is unexplained here and nothing depends on it.
- The 5,797,976-byte size alone would classify `DAEMON_FOREIGN` against this
  profile's pinned 5,822,240 — *if* the app could `lstat` it, which from
  `u:r:system_server:s0` it cannot. The evidence above exists only because it
  was read through root.

## `/proc/modules` from an unprivileged shell — 2026-11-12

Captured through RISH/Shizuku (`u:r:shell:s0`, uid 2000), **without root**:

```text
$ stat -c %a /proc/modules
444
$ cat /proc/modules
kernelsu 180224 1 - Live 0x0000000000000000 (O)
... ~400 further vendor/Samsung modules ...
```

What it settles:

- **DAC is not the obstacle.** Mode `0444`, so the file is world-readable, and a
  domain that is allowed it can read the whole list.
- **The RMG pair does not hide itself from this file**, at least in this boot:
  `kernelsu` is listed `Live`. Read with no privilege at all.
- **Exact-match is the right comparison.** The capture contains one entry the
  probe's name set selects (`kernelsu`) out of roughly four hundred. A substring
  match over a list that size is how a vendor driver becomes a false
  `FOREIGN_KSU_ACTIVE`, and a false FOREIGN refuses a route the owner is
  entitled to — which is why `RootEnvironmentProbe` compares the first column
  for equality.

What it does **not** settle, and it is the half that matters:

- **Whether `u:r:system_server:s0` may read it.** `shell` is a different domain,
  and on AOSP `/proc/modules` is labelled `proc_modules` with read granted per
  domain — the file mode says nothing about that. Every component of this app
  runs in `system_server` (`android:process="system"`), so the `shell` capture
  does not transfer. Recording it as settled would be the same error as reading
  a wrapper's success as a fact about a path (AGENTS.md §3.5.1).

**No further manual probe is needed to close it.** This build prints the route
reading at startup on this profile, so the next install answers it from logcat
in one line: `[DFR][ROOT_ENV] PROC_MODULES=KSU_LIKE_LOADED name=kernelsu`
(readable, and the state becomes `FOREIGN_KSU_ACTIVE`) or
`PROC_MODULES=UNREADABLE …` (denied, and the state stays `UNKNOWN`). Either
answer is fail-closed; only the precision of the refusal differs.

## The reuse route, evidenced — 2026-11-12

`RMG_ACTIVE_VERIFIED` was unreachable by construction when the route classifier
landed, because no component running at `u:r:system_server:s0` can attest the
loaded module. The companion closes that: it holds the grant this uid cannot
hold, and its attestation is recorded in `docs/COMPANION.md` §0.

| Element | Value |
|---|---|
| attestation | `RMG_CONTRACT` (re-derived client-side, not taken on trust) |
| root operation | PASS, bound to the call's nonce (`a9d2897721ef…`) |
| ksud digest, before / after | `95b2cc36…981d8a5` both reads |
| contract ioctl round-trip | PASS (`0xc0104b1e`, revision 1, operation 0 — no write) |
| SELinux | Enforcing, provider **and** local read |
| grant | `com.polygraphene.df.companion` uid 10516, `profile=present root=true` |

What this promotes: nothing that was gated on DFR's own acquisition. The
acquisition route still refuses on this device, `/data/adb/ksud` is untouched,
and `ROOT_RESULT=SUCCESS` remains a claim about DFR and only DFR.

What it does not establish: a cryptographic attestation of the loaded module's
bytes. The round-trip proves the module *implements* the managerless contract;
no userspace reading can prove more, and every consumer inherits that boundary.

## Route classification replaces the unconditional ownership preflight

**Source-level change only. It qualifies no gate and authorises no physical
attempt.** What it changes is which question is asked, where, and by a reader
that can answer it.

The preflight imported with the candidate above asked "do we own
`/data/adb/ksud`?" ahead of *every* run, from `u:r:system_server:s0`. On this
device the lookup answers `EACCES`, so the run refused with
`[DFR][DAEMON_PREFLIGHT] UNREADABLE phase=lstat errno=13` and the refusal was
unfalsifiable: the process demanding the evidence could not obtain it. That is
the AGENTS.md §3.5.1 defect (a gate whose own reader cannot read) and §3.3's
correction applies — an unreadable artefact changes which proof is required,
never whether one is required.

The reading is unchanged, byte for byte, in
`RootEnvironmentProbe.readPersistentDaemon()`. What moved is the decision:
`RootEnvironment` (pure, host-tested) classifies the boot and says which route
it permits, because taking the persistent daemon over is the only operation
that needs that answer.

| State | Reached when | Permits |
|---|---|---|
| `DFR_ACTIVE_VERIFIED` | a same-boot `PostRootStatus` verdict is complete | reuse of that session; no second run |
| `RMG_ACTIVE_VERIFIED` | an authorized provider attests the loaded module is the RMG pair | the reuse route |
| `FOREIGN_KSU_ACTIVE` | a KernelSU-like module is loaded, provenance unestablished | nothing |
| `INCOMPLETE_DFR_BOOT` | our module loaded, or a marker armed, with no completion | nothing |
| `NO_ACTIVE_KSU` | attested that no module is loaded | the acquisition route, **only** with the daemon absent or pinned |
| `UNKNOWN` | everything else | nothing |

Three properties are what make this not a relaxation:

- **`RMG_ACTIVE_VERIFIED` is currently unreachable, by construction.** Granting
  the reuse route needs a positive attestation of the loaded module. Nothing at
  `u:r:system_server:s0` can produce one: `/proc/modules` names a module, and
  both pairs load as `kernelsu`, so a hit is `FOREIGN_KSU_ACTIVE` and an empty
  read is `UNKNOWN` (a module can hide itself from that file). The KernelSU
  prctl UAPI is out of reach for the same reason the transport is — this domain
  has `map`/`read` but not `execute`/`execmod` on `apk_data_file`. So the state
  is modelled, negative-tested, and stays unreachable until an authorized
  companion provider exists.
- **`NO_ACTIVE_KSU` is equally unreachable today**, because it also requires an
  attestation. The practical consequence on this device is that the acquisition
  route still refuses — with a verdict that names the state and the missing
  evidence instead of an errno, and without spending the boot's destructive
  transaction.
- **The persistent-daemon migration is a constant refusal**, not an input:
  `Classification.persistentMigrationAllowed()` returns `false` and is derived
  from no observation, so no data can flip it. `tools/profile_binding_audit.py`
  fails if it becomes a parameter.

Scoped to `S25U_DZIF_OWO` (`KsudStage.requiresRootEnvironmentGate()`). ZZIC and
DZIF/OXM keep the boot contracts they were physically qualified under; this
change re-earned no evidence for them and therefore changes nothing there.

Evidence for the change itself is host-side only: `RootEnvironmentTest` 49/49
(one negative per element, including every unrecognised enum value and the
default-constructed observation), `test_post_root_contract` 59/59, and the
routing guards in `tools/profile_binding_audit.py`.

## The daemon

This APK bundles the DFR-only managerless Secure Late-Load candidate produced
by RMGLabs-Payloads workflow `43296818818`, from source commit
`925046c63123b45874bcfef186d5d22796a725d0`, with
`staging_profile=dfreroot`, `secure_late_load=true`,
`managerless_app_grants=true`, and `publish_artifacts=false`.

| Identity | Audited value |
|---|---|
| Daemon SHA-256 | `ea71739be0f800d9669491ae77408dd309e86aa569c8447ff869536e7685fa2c` |
| Daemon size | 5,822,240 bytes |
| Daemon ELF build-id | `b6a9dfd034da27d17907fa36662d3906ec675fef` |
| Embedded KernelSU module SHA-256 | `4b8965cdd3c733315c84767d3d26c1f71eaec9071b07d13fa08940bd4fe8731c` |
| Embedded module size | 3,634,632 bytes |
| Embedded module build-id | `e61c877018ef31e9e0bf2148e8f556ad3f63473e` |
| KernelSU base | `932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e` (32601, UAPI 2) |
| Capability verdict | `SECURE_LATE_LOAD_INDICATORS_CONSISTENT` |
| Attestation | `BOUND_TO_THIS_BINARY` |
| Physical Gate 3 for this new daemon | **NOT PERFORMED** |

The workflow verified that the module embedded in the daemon matches the
standalone module, and the capability report records
`forbidden_present=[]` and `required_missing=[]`. The new source includes
fail-closed checks for a foreign live KernelSU module and a foreign
`/data/adb/ksud` before `stage_daemon_from()`.

The audit does **not** establish runtime reachability or physical acceptance.
Its `still_owed` items include the forbidden-CLI refusal check and review of
the compiled call graph. A device previously carried the RMG managerless
daemon (`95b2cc36â€¦981d8a5`), but the failed 2026-11-12 run replaced its
on-disk daemon with the older DFR binary. Its current state must be inspected;
do not infer it is already restored to RMG or change it as part of this import.

The original physical FAIL record above remains historically accurate for the
old daemon. This candidate has only a host-side build/audit PASS.

## Verification

```sh
sh      tools/tests/run_tests.sh                       # includes the OWO cases
python3 tools/dzif_owo_profile_binding_audit.py         # profile + AVB + Gate G
python3 tools/verify_dzif_owo_avb.py                    # the chain on its own
python3 tools/dzif_profile_binding_audit.py             # OXM must not regress
python3 tools/verify_zzic_avb.py                        # ZZIC must not regress
```

On a Windows checkout with `core.autocrlf=true`, the Gate-G audits fail because
git rewrites `evidence/*/gate-g/*-derived-minimal.symvers` to CRLF, changing its
SHA-256. The provenance records the LF digest — what `git show :<path>` produces
— so they pass on the Linux runner. Confirmed by comparing all three digests.

## What is still owed

- The CLI-level refusal test on the pinned daemon: every forbidden subcommand
  must be unrecognised. Needs a device or an emulator, so the capability audit
  still reports `reachability_claim = NOT_ESTABLISHED_BY_THIS_TOOL`.
- Every physical gate. A green CI run proves host logic, compilation and
  packaging; it proves nothing about `system_server`, the Samsung linker, kernel
  stability, Wallet or Play Integrity.
- `kernel_image_sha256` is still a carry-over rather than a live read.
- The loaded module's build-id, which the capture could not read.
- **An authorized provider that can attest the loaded module.** Without it
  `RMG_ACTIVE_VERIFIED` and `NO_ACTIVE_KSU` are unreachable, which means both
  routes refuse on this device. This is the single blocker for a functioning
  flow, and it is not a gate that can be promoted by evidence — it needs the
  companion app and grant contract to be built.
- **A DFR runtime mode that does not require taking `/data/adb/ksud` over.**
  Until it exists, `DAEMON_FOREIGN` has no route that can act on it, and the
  only alternative is a migration with its own recovery and rollback evidence.
- ~~The identity of the daemon currently at `/data/adb/ksud`.~~ **Closed
  2026-11-12** by a root capture: it is the RMG build `95b2cc36…981d8a5`. See
  the section above for what that does and does not establish.
- Whether `/proc/modules` is readable from `u:r:system_server:s0`. DAC is
  answered (`0444`, read without root from `u:r:shell:s0`); the SELinux half is
  not, and `shell` does not stand in for `system_server`. This build's own
  startup line answers it on the next install — no manual probe required.
