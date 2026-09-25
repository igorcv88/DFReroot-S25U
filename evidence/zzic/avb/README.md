# ZZIC AVB evidence — what these bytes are, and what they prove

Four vbmeta images from the official `S938BXXUCZZIC` OTA, committed so that the
`/vendor` provenance claim can be **re-derived** rather than taken on trust.

| File | Role |
|---|---|
| `vbmeta.img` | top-level vbmeta: the signed hashtree descriptor for `vendor`, plus three chain-partition descriptors |
| `dtbo-vbmeta.img`, `optics-vbmeta.img`, `prism-vbmeta.img` | the chained vbmetas the top-level image points at |
| `SHA256SUMS-avb.device.txt` | the manifest the device produced, committed **verbatim**, `/sdcard` paths and all |

`SHA256SUMS-avb.device.txt` is the single source of these hashes. It is not
rewritten to repo-relative paths, because a second copy of the same digests is
the drift class this repository checks for everywhere else;
`tools/verify_zzic_avb.py` matches its entries by basename.

## Why all four, and not just `vbmeta.img`

`ro.boot.vbmeta.digest` is **not** a hash of `vbmeta.img`. It is SHA-256 over
the top-level vbmeta blob (header + authentication block + auxiliary block,
without the partition's trailing padding) followed by the same blob of every
chained vbmeta, walked in descriptor order. So `vbmeta.img` alone reproduces
nothing; the three children are load-bearing.

```sh
python3 tools/verify_zzic_avb.py
```

```text
chain order       : dtbo -> optics -> prism
digest reproduced : 23a0e0b0a5b421d5a75b62de40edb37489a4e6d441d54e58ee6f930c1a9a3f62
digest pinned     : 23a0e0b0a5b421d5a75b62de40edb37489a4e6d441d54e58ee6f930c1a9a3f62
```

The reproduced value is exactly the `ro.boot.vbmeta.digest` the bootloader
published on the device and the value pinned in `target_profile.c` and
`tools/zzic_profile.json`. The tool parses AVB itself (`tools/avb.py`), so the
check needs no AOSP checkout and no `avbtool` — a reviewer with `python3` can
redo it.

## The chain this closes

```text
committed vbmeta blobs
  -> reproduced vbmeta digest == pinned ro.boot.vbmeta.digest
    -> signed hashtree descriptor for `vendor`
      -> root 794944fa… salt 336ad2aa… sha256, 4096/4096,
         860461 data blocks + 6777 tree blocks = 867238 = FEC start
        -> /vendor, erofs, read-only, veritymode=enforcing, green/locked
          -> /vendor/lib64/libstagefrighthw.so == vendor_target_sha256
```

## What is deliberately NOT here

- **No runtime gate on any of this.** Reading the live device-mapper table needs
  a DM ioctl that works from `u:r:ksu:s0`, fails from `u:r:untrusted_app_27:s0`,
  and has **never been measured** from `u:r:network_stack:s0` — the domain the
  chain actually runs in. Pinning root digest and salt as runtime fields would
  rebuild the 2.0.2 trap: a gate the chain's own domain cannot satisfy. The
  runtime keeps comparing what it can read (`vbmeta.digest`, `avb_version`,
  `hash_alg`, green/locked/enforcing, `/vendor` ro/erofs).
- **No `vendor.img`.** With verity *enforcing* and a root digest matching a
  signed descriptor, reading the file from the verified mount is equivalent to
  extracting it offline. 3.5 GB of redundant forensics is not a missing link.
- **No `vendor-verity-dmctl.raw.txt` yet.** Drop a raw
  `dmsetup table vendor-verity` capture in this directory and the verifier
  compares it against the signed descriptor automatically. While it is absent
  the tool reports `LIVE_DM_VERITY_TABLE = SKIP (artefact absent)` — an explicit
  skip, never implicit agreement.
- **No `prism` or `optics` pins.** Neither is on the exploit chain, which writes
  `crash_dump64`, the vendor ELF, `libc` and `libc++`. Their geometry is
  reported as corroboration that the extraction method is sound
  (`prism`: 399590 data blocks, FEC at block 402738 — both whole blocks) and
  `tools/verify_zzic_avb.py` **fails** if either is ever pinned in the profile.

## One question this settled

The live table prints `fec_blocks 867238 fec_start 867238`. That repetition
looked like a possible transcription slip. It is not: in dm-verity's parameter
syntax both are block offsets into the same device, and the FEC *data size* is a
separate quantity the signed descriptor carries as `fec_size = 28082176` bytes
= 6856 blocks. The profile pins `fec_offset_blocks = 867238` and
`fec_blocks = 6856`, which are different numbers describing different things.
