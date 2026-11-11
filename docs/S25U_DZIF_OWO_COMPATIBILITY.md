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
| Physical | **NOT PERFORMED** | nothing in this record was obtained by running the chain |

## The daemon

`ksud_sha256` is `6b7246e5…def2` and `ksud_size` is `5817624`, naming the
audited DFR managerless Secure Late-Load daemon bundled as
`app/src/main/assets/ksud-dzif-owo`.

This profile first landed with the daemon at `NULL`/`0`, which made
`KsudStage.currentSpec()` return null and `DfrRootCoordinator` refuse **before
the hop** — ahead of the first page-cache write — because no DFR pair existed
for the `dfreroot` staging contract. `RMGLabs-Payloads` PR #28 built one.

### Provenance

| | |
|---|---|
| run | `43028391105`, 22 steps, all `success` |
| source commit | `ae3607778e815e6461d499d1da4e3be066c750fe` |
| cargo features | `secure-late-load,managerless-app-grants` |
| KernelSU | `932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e` (versionCode 32601, UAPI 2) |
| daemon | `6b7246e519d3a2c6419a2a833a4239bb81343da6bda6b1c00a0fa2f4d63bdef2`, 5817624 B, build-id `85e4c750…` |
| embedded module | `4b8965cdd3c733315c84767d3d26c1f71eaec9071b07d13fa08940bd4fe8731c`, 3634632 B, build-id `e61c8770…` |
| publication | refused — `publish_artifacts=false`, the publish step skipped |

### What qualification established

- All eleven DFR closeout markers survive the Secure Late-Load rewrite, so the
  `dfreroot` staging contract is intact rather than compiled out.
- The module embedded in the daemon digests to the module this run built, so
  the daemon cannot late-load a different one.
- That module's modversions (156/156) and manual relocations (64/64) resolve
  against the DZIF kernel release, which OWO shares; no `S938BXXUCZZIC` leak.
- `tools/ksud_capability_audit.py` returns
  `SECURE_LATE_LOAD_INDICATORS_CONSISTENT`, `forbidden_present = []`,
  `attestation_binding = BOUND_TO_THIS_BINARY`.
- `/data/local/tmp/.ksud-stage` is absent from the binary: it stages only from
  `/data/system/dfreroot-ksud`.

### What it did not

The capability audit's own `still_owed` list keeps the CLI-level refusal test
— every forbidden subcommand must be unrecognised — which needs a device or an
emulator, and reports `reachability_claim = NOT_ESTABLISHED_BY_THIS_TOOL`. An
indicator present proves the code is in the binary, not that the CLI dispatches
to it. Pinning does not discharge the physical gates below.

### Do not substitute the daemon already on the device

`/data/adb/ksud` is `95b2cc36…81a5` (5797976 B), the **RMG** OWO managerless
review daemon. It carries the `rmg` staging contract
(`/data/local/tmp/.ksud-stage`), not `/data/system/dfreroot-ksud`, and it is the
pair currently preserving the owner's Wallet and Play Integrity state. The two
are distinct in both halves — daemon `6b7246e5…` vs `95b2cc36…`, module
`4b8965cd…` vs `a7d03cb9…` — and that digest is listed in
`RMG_DAEMONS` in the binding audit so bundling the wrong file fails on the host.

The loaded module's build-id could not be read in the capture
(`loaded_kernelsu_build_note_hex=UNREADABLE`), so the running `kernelsu` module
is identified only by `lsmod` (`kernelsu 180224 2 - Live`). The Wallet/Integrity
state the owner reports is therefore attributable to the **daemon** digest
above, not yet to a specific module build-id.

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
