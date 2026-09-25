# Gate G evidence — the ZZIC symbol CRCs, and where each one comes from

`Module.symvers` is a kernel *build* artefact. It does not exist on a running
Android filesystem and the Samsung build tree is not available, which for a while
read as "Gate G needs something nobody has".

It does not. The firmware ships modules built against that exact kernel, and each
carries a `__versions` table of the CRCs *its* build recorded. That is a witness.

## What is committed here

| File | What it is |
|---|---|
| `ZZIC-derived-minimal.symvers` | the five CRCs the build needs, read out of witness bytes |
| `ZZIC-modversion-provenance.json` | every witness bound to `device_path` + `SHA-256` + `vermagic`, per symbol |

```text
__stack_chk_fail   0xf0fdf6cb
_printk            0x92997ed8
memset             0xdcb764ad
sprint_symbol      0x661601de
module_layout      0x81972209
```

The first four are what the helper calls. `module_layout` is the one the helper
never mentions and the kernel checks **first**: `check_modstruct_version()`
version-checks it before resolving any symbol, and the DDK that compiles this
module ships a different CRC for it (`0x4e276f37`). Derive four and let the
toolchain supply the fifth and the result passes every offline check, then is
refused by the target at `insmod`. See AGENTS.md, "`module_layout` is required,
and it is not an import".

Regenerate, never hand-edit:

```sh
python3 tools/derive_zzic_symvers.py /path/to/qca_cld3_kiwi_v2.ko \
    --origin "/path/to/qca_cld3_kiwi_v2.ko=/vendor_dlkm/lib/modules/qca_cld3_kiwi_v2.ko" \
    --out evidence/zzic/gate-g/ZZIC-derived-minimal.symvers \
    --provenance evidence/zzic/gate-g/ZZIC-modversion-provenance.json
```

## The witness

```text
/vendor_dlkm/lib/modules/qca_cld3_kiwi_v2.ko
SHA-256  bc6595275164fcf7ff1c3ac582a1be236ae9d5693c83e6ea0bc05b84fa6dd16a
size     20,338,264
module   qca_cld3_kiwi_v2   ("WLAN HOST DEVICE DRIVER", Qualcomm Atheros)
license  Dual BSD/GPL
vermagic 6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k SMP preempt mod_unload modversions aarch64
__versions  588 entries
```

**The module itself is not committed.** It is 20 MB of vendor driver, and
redistributing it here buys nothing the digest above does not already provide: the
provenance binds each CRC to those exact bytes, and anyone who pulls the file from
the same firmware can re-derive and get the same table or a hard failure.

## All five rest on one witness, and that is stated rather than averaged

Earlier analysis reported witness counts of 374 / 319 / 138 / 1 across many stock
modules. Only `qca_cld3_kiwi_v2.ko` was supplied here, so the committed
provenance records **one witness for each of them** — `witness_count: 1`
throughout. That is the honest number for this evidence set, and
`tools/derive_zzic_symvers.py` prints it as `<- single witness` rather than
letting a reader assume redundancy that is not in the record.

More witnesses would raise the count, and any that disagreed would be a **hard
failure** rather than a vote: one kernel's CRCs are self-consistent, so a conflict
means an input is not from that kernel.

### The witness is kernel-ratified — captured

Witness count is not the best evidence available. Under `CONFIG_MODVERSIONS` the
kernel refuses a load when a CRC disagrees, so a stock driver that is **actually
loaded** has had its entire table ratified by the kernel itself.

`evidence/zzic/gate-g/lsmod-target.txt` is that capture, and the provenance
records it per witness (`kernel_loaded: true`, plus the capture's own digest):

```text
qca_cld3_kiwi_v2    13144064  0
ipam                 4448256  20 qca_cld3_kiwi_v2,rmnet_core,ipanetm,rmnet_ctl
cnss2                 471040  1 qca_cld3_kiwi_v2
cfg80211             1142784  3 qca_cld3_kiwi_v2,wonder,mac80211
…
```

So all five CRCs rest on one witness **whose 588 entries the target kernel
accepted at load time** — `module_layout` among them, which means the kernel
has already compared that exact value and agreed. That is stronger than 374 unratified agreements: the
kernel is the authority these CRCs are supposed to match, and it already voted.

The evidence is still one module. If a future capture adds witnesses, any that
disagreed would be a hard failure — see `--lsmod` and the conflict rule.

## What this does and does not establish

Establishes: the CRC values the final LKM's `__versions` must carry, traceable to
bytes.

Does **not** establish that the LKM loads, that the runtime symbol scan is
reliable, that the `selinux_state` layout assumption holds at run time, or that
writing to it is safe. Those are separate boundaries — see the G1–G4 split in
`docs/S25U_ZZIC_COMPATIBILITY.md`.

## Columns that are not observable

`__versions` records a CRC and a name. It does not record which module exports the
symbol, nor whether the export is GPL-only. The generator fills those columns with
`vmlinux` / `EXPORT_SYMBOL_GPL` and says so in the file's own header — an
assumption, not an observation. It errs strict on purpose: a GPL-only export is
usable by a GPL module, and the helper is `license=GPL`, so this direction can
only make a build stricter, never wrongly permit one.

## How the audit treats this file

`ZZIC-derived-minimal.symvers` carries the marker `DFR-DERIVED-SYMVERS v1`.
`tools/ko_audit.py` keys on it and then **requires** the provenance record,
refusing to reach `COMPATIBLE` without one that holds up: consensus complete, no
conflicts, every witness bound to a digest and to this exact kernel release, and
every symbol in the table backed by a witness. A table with no provenance is a
typed-in number wearing a filename.

An unmarked file is treated as an authoritative `Module.symvers` and needs no
record — this tool cannot verify that claim, so it records the digest and the
operator owns it, as has always been the case.
