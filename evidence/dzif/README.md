# DZIF physical and module evidence (2026-10-12)

Target: `SM-S938B / pa3q`, `S938BXXUCDZIF`, kernel
`6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCDZIF-4k`.

The owner ran RMG Labs 0.1.37-lab Manual Root on this firmware. The exported
`RootMyGalaxy-20261012-165352-succeeded.log.txt` has SHA-256
`d96ea38f3917bd1e0725425dd484df75b4b565ebd2ef4ffd1a28cc08a7886480`.
It records exact profile `pa3q-S938BXXUCDZIF`, the physical P0 oracle with
`P0_PHYS_OFFSET=0x80000000`, `P0_KERNEL_PHYS_LOAD=0xa8000000`, fingerprint
best=8/second=1, slide `0x50000`, physical-alias kernel base
`0xffffffc080050000`, root and KernelSU late-load on attempt 1/24, and
KernelSU control version 32601, UAPI 2. The owner independently observed
`uid=0`, `u:r:ksu:s0`, and SELinux Enforcing after that run. This proves the
RMG route for this boot, not the DFReroot StageHop or DirtyFrag chain.
The owner subsequently read `/proc/sys/kernel/random/boot_id` as
`eaa89295-080e-41c2-8904-7462442949d6`, exactly the boot ID in the RMG
log. The root, `lsmod`, and live module hashes below belong to the same boot.

Runtime AVB values observed on the rooted DZIF device:

| Anchor | Value |
|---|---|
| vbmeta digest | `be1e4709a8e7befe4479147f914341cab7fd43c615fa1cfaf1fa1511bb87a0a6` |
| AVB version / hash | `1.2` / `sha256` |
| verified boot / device state / flash locked | `green` / `locked` / `1` |
| verity mode | `enforcing` |
| `/vendor` | `erofs`, `ro`, `/dev/block/dm-10` |

Root-side `sha256sum` and file metadata:

| File | SHA-256 | Size | SELinux context |
|---|---|---:|---|
| `/apex/com.android.runtime/bin/crash_dump64` | `9249d66445837c52322c2c86ee62efa64e49a7c1b72084c1ce98f72c12a1151f` | 567912 | `u:object_r:crash_dump_exec:s0` |
| `/vendor/lib64/libstagefrighthw.so` | `308b254a82c51695015182fc3b78b5d0cbb6e36cd6cf8f2f282452f8a47f8049` | 51632 | `u:object_r:vendor_file:s0` |
| `/system/lib64/libc.so` (resolves to `/apex/com.android.runtime/lib64/bionic/libc.so`) | `88fba68b3d1fded4bfd25197f6de24f5b8794d3253de860ee261a4272be9e861` | 1330432 | `u:object_r:system_lib_file:s0` |
| `/system/lib64/libc++.so` | `cb118e98c74d3454858921123b9b51ba13df9cad7dfa141dd892c453661a4d78` | 1152760 | `u:object_r:system_lib_file:s0` |

The four file digests happen to match the earlier ZZIC capture. The DZIF
vbmeta digest and exact firmware identity remain distinct and must be pinned
under a separate profile.

## Gate G witness stage

`gate-g/lsmod-target.txt` is the owner's `/proc/modules` capture from this
rooted boot (SHA-256
`bee5f32c9bc3bc8a9fa32587b043000bd49a014881b08aafe17add7449560e89`).
It lists both `qca_cld3_kiwi_v2` and `camera` as loaded. Their on-device `.ko`
files were hashed independently, matching the stock DZIF bundle bytes:

| Device path | SHA-256 |
|---|---|
| `/vendor_dlkm/lib/modules/qca_cld3_kiwi_v2.ko` | `85058c74df0d4c20131d01acf84fc36e0eea1909336ad274c0ce64bc9351cd24` |
| `/vendor_dlkm/lib/modules/camera.ko` | `25fdcff59003f3de6a7600259a84bb2f4ec1b796018f733d6452e217b6f4c13c` |

`gate-g/DZIF-derived-minimal.symvers` and the companion provenance JSON were
derived from the `__versions` of these exact-release stock modules with the
existing `derive_zzic_symvers.py --release <DZIF release> --lsmod ...` tool.
Its legacy name and report heading refer to ZZIC; the pinned release and
module digests in the output are DZIF. `CONSENSUS=COMPLETE` for five required
symbols, with no conflicts. `sprint_symbol` has only the loaded Wi-Fi module
as witness; the other four have two independent loaded witnesses.

This establishes CRC evidence for building the DZIF DirtyFrag module. Gate G
remains incomplete until the *final* `.ko` is built, has full `__versions`
coverage, and passes strict `ko_audit.py` against this DZIF-derived table.
