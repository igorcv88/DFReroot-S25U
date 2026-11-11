# DZIF/OWO `/vendor` AVB evidence

The four vbmeta blobs the OWO device dumped, plus its own `sha256sum` manifest
and the live dm-verity table for `vendor-verity`.

Verified offline by `tools/verify_dzif_owo_avb.py`, and again as part of
`tools/dzif_owo_profile_binding_audit.py`.

## Why these files are here

`DFR_PROFILE_DZIF_OWO.vbmeta_digest` began as an **observation**: `getprop`
reported `b9e6d6cf…14c7`, and the vendor ELF hashed correctly when read from
`u:r:ksu:s0` in that boot. That is the weakest evidence this repository accepts
anywhere, and a reviewer would have had to take it on trust. ZZIC had already
closed the same gap for itself (`tools/verify_zzic_avb.py`), so OWO closes it
the same way: the digest is **re-derived** from the signed blobs and compared
against both the JSON profile and the native profile.

The chain the verifier walks:

```
committed vbmeta blobs
  -> reproduced vbmeta digest == pinned ro.boot.vbmeta.digest
    -> signed hashtree descriptor for `vendor`
      -> root digest + salt + dm-verity geometry
        -> the LIVE dm-verity table captured in the same boot
          -> /vendor, erofs, read-only, veritymode=enforcing
            -> /vendor/lib64/libstagefrighthw.so == vendor_target_sha256
```

## Provenance

Everything here, and every artefact hash in `tools/dzif_owo_profile.json`, comes
from **one boot**:

| | |
|---|---|
| `boot_id` | `52ee18f7-3937-4f99-8dca-c0f51d5d5204` |
| captured | 2026-11-11T12:21:51Z → 12:21:53Z (identity), 09:27Z (blobs) |
| reader | `uid=0(root) … context=u:r:ksu:s0` |
| SELinux | `Enforcing` |
| boot state | `verifiedbootstate=green`, `vbmeta.device_state=locked`, `flash.locked=1`, `veritymode=enforcing` |

Evidence from two boots would not be a chain: the digest proves which image is
mounted *in that boot*, so a hash read in a different boot is not covered by it.
The manifest's `/sdcard/Download/DFR_OWO_AVB_<boot_id>/` paths carry the same
`boot_id`, which is what ties the blobs to the identity capture.

The manifest is committed **verbatim**, with its on-device paths intact.
`read_manifest()` keys by basename for that reason — rewriting the paths would
mean maintaining a second copy of the same digests, which is the drift this
repository checks for everywhere else. So `sha256sum -c` will not work from this
directory; the tools compare by basename.

## Files

| File | What it is |
|---|---|
| `vbmeta.img` | top-level vbmeta, 8384 B, `avbtool 1.4.0`, chains `dtbo -> optics -> prism` |
| `dtbo-vbmeta.img` | chained vbmeta footer, 2112 B |
| `optics-vbmeta.img` | chained vbmeta footer, 2176 B |
| `prism-vbmeta.img` | chained vbmeta footer, 2176 B |
| `SHA256SUMS-avb.device.txt` | the device's own manifest for the four blobs |
| `vendor-verity-dmctl.raw.txt` | live `dmctl table vendor-verity`, same boot |

## What OWO has that ZZIC does not

A committed `vendor-verity-dmctl.raw.txt`. ZZIC records `SKIP
LIVE_DM_VERITY_TABLE` because that artefact was never captured. Here the live
table was read in the same boot, so the **signed** descriptor is checked against
what the kernel actually instantiated:

| Parameter | Signed descriptor | Live dm table |
|---|---|---|
| root digest | `dcfb9c58…1e09` | `dcfb9c58…1e09` |
| salt | `613c9e09…48c0` | `613c9e09…48c0` |
| version / algorithm | 1 / sha256 | 1 / sha256 |
| data / hash block | 4096 / 4096 | 4096 / 4096 |
| data blocks | 860461 | 860461 |
| hash start (blocks) | 860461 | 860461 |
| fec offset (blocks) | 867238 | 867238 |
| fec roots | 2 | 2 |

The binding audit **fails** if that comparison is ever skipped, rather than
reporting PASS with its strongest check silently absent.

## Relationship to the OXM sibling

`tools/dzif_profile.json` (OXM) has no `vendor_avb` block and no AVB evidence
directory, so this proof currently exists for OWO and ZZIC only. The two One UI
9 images share build number, kernel and `/vendor` **geometry** — `data_blocks`,
`tree_blocks`, `fec_offset_blocks` and `fec_blocks` are identical to ZZIC's —
but the `salt` and `root_digest` differ, which is what being a different signed
image means.

## Not a runtime gate

Deliberately, and for the reason `tools/verify_zzic_avb.py` documents at length:
reading the live dm-verity table needs a DM ioctl that has never been measured
from `u:r:network_stack:s0`. A gate the chain's own domain cannot satisfy is the
trap that broke 2.0.2. These values therefore live in the JSON profile only and
are **not** mirrored into `target_profile.c`; the runtime keeps comparing the
anchors it can actually read.
