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

## The daemon

This APK bundles the DFR-only managerless Secure Late-Load candidate produced
by RMGLabs-Payloads workflow `43271383389`, from source commit
`05a5f6477b5c5f2dc26dc8824321736bfa7ce4b8`, with
`staging_profile=dfreroot`, `secure_late_load=true`,
`managerless_app_grants=true`, and `publish_artifacts=false`.

| Identity | Audited value |
|---|---|
| Daemon SHA-256 | `30428cd21fd03eea16dd216ed95a95a925f49864c6ace4fa61d957a609232a33` |
| Daemon size | 5,820,784 bytes |
| Daemon ELF build-id | `a696370f4d9ef202afa7063389bd8da164cf355f` |
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
