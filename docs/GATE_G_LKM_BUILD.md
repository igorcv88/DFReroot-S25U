# Gate G1 — exact ZZIC `dirtyfrag.ko` build record

Gate G1 is **closed offline**. This file is now the reproducible build record for
the exact helper rather than a plan for a missing artefact. The bundled module is
`app/src/main/jni/dirtyfrag-android15-6.6-S938BXXUCZZIC.ko`, SHA-256
`b941d3234ad57235083f5778ff33c52cd4691aaf620d98be43fbaedc74ae3017`,
6592 bytes, with `MODVERSION_COVERAGE = COMPLETE (5/5)` and
`MODULE_VS_ZZIC_KERNEL = COMPATIBLE`. G2/G4 and the downstream chain still
require hardware evidence.

**Where each step runs matters.** Read the machine column before copying anything.

| Step | Machine |
|---|---|
| 1. Build the LKM | a Linux host with a **working Docker daemon** (PC, VM, WSL2) |
| 2. Accept it | the same host, or any machine with `python3` and this repo |
| 3. Bundle + pin | the repository (a commit) |
| 4. Signed release | `release.yml`, one dispatch |
| 5. Physical run | the S25 Ultra |

Not the phone: Termux has neither Docker nor a kernel headers tree. Not the cloud
session either — it has a `docker` client but no daemon, which is why this file
exists instead of a built module.

---

## 0. What is already done

```text
evidence/zzic/gate-g/ZZIC-derived-minimal.symvers       the five CRCs
evidence/zzic/gate-g/ZZIC-modversion-provenance.json    each bound to witness bytes
evidence/zzic/gate-g/lsmod-target.txt                   the witness is kernel-loaded
```

```text
module_layout     0x81972209
__stack_chk_fail  0xf0fdf6cb
_printk           0x92997ed8
memset            0xdcb764ad
sprint_symbol     0x661601de
```

Read out of `/vendor_dlkm/lib/modules/qca_cld3_kiwi_v2.ko` (`bc659527…`), whose
`vermagic` is exactly the ZZIC release and which `lsmod` shows **loaded** — so the
target kernel accepted all 588 entries of its `__versions` table at load time.

## 1. Build the LKM

The DDK image is the **toolchain and headers only**. Its own `Module.symvers`
holds GKI CRCs, which are *not* the Samsung kernel's — feeding those to `modpost`
is precisely the trap `ko_audit.py` now detects and refuses. So the five CRCs in
that table get replaced with the derived ones.

**Do not copy the derived table over `Module.symvers`.** It exists for
`ko_audit.py`, which reads only the CRC and the symbol name, and it is not
modpost input:

- it carries a `#` header, and `scripts/mod/modpost` reads its symbol dump as
  tab-delimited records with no comment handling — the first header line has no
  tab, so `read_dump()` takes its `goto fail` and calls
  `fatal("parse error in symbol dump file")`;
- its rows have four fields, while `Module.symvers` gained a namespace column in
  Linux 5.8, so a 6.6 tree expects five
  (`CRC  symbol  namespace  module  export-type`).

`tools/patch_symvers_crcs.py` edits the kernel's **own** table instead: each row
keeps its exact shape and only the CRC field of the five named symbols changes.
That is format-agnostic — four columns or five, it does not care — and it refuses
rather than writes when a required symbol is absent from the base table, because
modpost would otherwise leave the module with no `__versions` entry for it and the
load would fail on the device instead of in the build. It also demands the derived
table's provenance, exactly as the audit does, so it cannot become a side door
into hand-edited CRCs.

```sh
# The workflow .github/workflows/build-zzic-dirtyfrag.yml does all of this and
# audits the result; prefer dispatching it over running these by hand. The
# commands below are the same steps, for a host without a runner.
# On the Linux host, in a clone of this repo.
R=6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k
docker pull ghcr.io/ylarod/ddk-min:android15-6.6-20260828

docker run --rm -v "$PWD":/src -w /src \
  -e R="$R" ghcr.io/ylarod/ddk-min:android15-6.6-20260828 bash -lc '
    set -eux
    test -n "$KDIR" && test -d "$KDIR"

    # Make the module claim the exact target release. vermagic is necessary,
    # never sufficient - the CRCs below are what actually decide loadability.
    mkdir -p "$KDIR/include/config" "$KDIR/include/generated"
    printf "%s\n" "$R"                      > "$KDIR/include/config/kernel.release"
    printf "#define UTS_RELEASE \"%s\"\n" "$R" > "$KDIR/include/generated/utsrelease.h"

    # THE point of the whole exercise: modpost must resolve the imports against
    # the TARGET CRCs, not the DDK ones. The derived table is not modpost input
    # (comments, and four columns instead of five), so patch the tree own table.
    cp "$KDIR/Module.symvers" "$KDIR/Module.symvers.ddk.bak"
    python3 tools/patch_symvers_crcs.py \
      --base "$KDIR/Module.symvers.ddk.bak" \
      --derived evidence/zzic/gate-g/ZZIC-derived-minimal.symvers \
      --out "$KDIR/Module.symvers"

    # This DDK ships a PATCHED modpost: check_exports() has its
    # `s->module = exp->module;` commented out AND its only call site is
    # commented out too. No import is ever matched to an export, add_versions()
    # skips every symbol, and the table comes out EMPTY - silently, because the
    # function that would have warned is the one removed. Restore both lines and
    # rebuild modpost from the restored source, or nothing below means anything.
    MP=/opt/ddk/src/android15-6.6/scripts/mod/modpost.c
    sed -i -e "s|^//\([[:space:]]*\)\(s->module = exp->module;\)|\1\2|" \
           -e "s|^//\([[:space:]]*\)\(check_exports(mod);\)|\1\2|" "$MP"
    grep -nE "^[[:space:]]+(s->module = exp->module|check_exports\(mod\));" "$MP"
    ( cd "$KDIR" \
      && eval "$(sed -n "s|^savedcmd_scripts/mod/modpost\.o := ||p" \
                   scripts/mod/.modpost.o.cmd)" \
      && eval "$(sed -n "s|^savedcmd_scripts/mod/modpost := ||p" \
                   scripts/mod/.modpost.cmd)" )

    # No KBUILD_MODPOST_WARN. An unresolved symbol must FAIL the build here,
    # because that warning is another way to end up with an incomplete
    # __versions table - one that loads while verifying nothing.
    make -C dirtyfrag-lkm KDIR="$KDIR" clean
    make -C dirtyfrag-lkm KDIR="$KDIR"
    test -s dirtyfrag-lkm/dirtyfrag.ko
  '
```

Then the size diet `dirtyfrag-lkm/build.sh` already applies — the module is
written through the exploit page by page, so bytes are pages:

```sh
docker run --rm -v "$PWD":/src -w /src ghcr.io/ylarod/ddk-min:android15-6.6-20260828 \
  llvm-objcopy --strip-unneeded \
    -R .comment -R .note.gnu.build-id -R .note.gnu.property -R .note.Linux \
    -R .note.GNU-stack -R .BTF -R .BTF.base -R .llvm_addrsig \
    -R .hyp.text -R .hyp.bss -R .hyp.rodata -R .hyp.event_ids \
    -R .hyp.patchable_function_entries -R .hyp.data \
    dirtyfrag-lkm/dirtyfrag.ko
```

**Strip before hashing.** `--strip-unneeded` changes the bytes, and the profile
pins the bytes that ship. Any later re-strip, re-sign or `.modinfo` edit
invalidates the pin.

## 2. Accept it

```sh
python3 tools/ko_audit.py dirtyfrag-lkm/dirtyfrag.ko \
    --require-modversion-coverage \
    --symvers evidence/zzic/gate-g/ZZIC-derived-minimal.symvers
```

The only acceptable output:

```text
machine                     = AArch64 (EM_AARCH64)  (OK)
vermagic                    = 6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCZZIC-4k …
MODVERSION_COVERAGE         = COMPLETE (5/5)
symvers kind                = DERIVED
provenance                  = … (consensus COMPLETE)
  module_layout / __stack_chk_fail / _printk / memset / sprint_symbol
                               MODVERSION_MATCH = True
missing entries             = []
unresolvable imports        = []
CRC mismatches              = []
MODULE_VS_ZZIC_KERNEL       = COMPATIBLE
```

Anything else leaves Gate G closed. The audit finds the provenance record beside
the table on its own and **refuses** without one, so the five CRCs can never
degrade into typed-in numbers.

Optional, and worth it: `--kallsyms <capture>` to record existence evidence for
`kallsyms_lookup_name` and `selinux_state`, which the helper resolves at run time
rather than importing. Zeroed addresses are fine; only the names are read.

## 3. Bundle and pin — CLOSED

The required code change is implemented and guarded by
`tools/profile_binding_audit.py`.

The generic `dirtyfrag-android15-6.6.ko` remains in the family table unchanged.
The ZZIC module has its own `.incbin` and is reachable only from the explicit
`DFR_TARGET_S25U_ZZIC` branch in `patch_ko()`; it is never eligible through
`dfr_select_ko_image()`. The profile pins all three fields together:

```c
.ko_zzic_verified = 1,
.ko_filename      = "dirtyfrag-android15-6.6-S938BXXUCZZIC.ko",
.ko_sha256        = "b941d3234ad57235083f5778ff33c52cd4691aaf620d98be43fbaedc74ae3017",
```

At runtime `patch_ko()` hashes the exact selected bytes before the first
page-cache write. The binding audit also verifies that the ZZIC image never
leaks into generic family selection.

## 4. Release — CLOSED

`v2.0.4-zzic` was published as the stable release from commit
`9f3c3efc983cc0ad527cb9d508cbe47d795f55cc`. The signed release workflow ran
the strict exact-module audit against the provenance-bound ZZIC table before
building. Release assets include both APKs, `SHA256SUMS.txt` and
`build-provenance.txt`.

A locally built APK is **not** a substitute: the signing keys live in repository
secrets, and DFInstaller injects DFReroot's certificate into `packages.xml`.

## 5. The physical run

Gate G is one of four boundaries and closing it closes only the first.

| Sub-gate | What closes it |
|---|---|
| **G1** loader / import ABI | **closed offline**: exact vermagic + target-derived COMPLETE (5/5) modversions + byte pin; the first hardware run still supplies the physical loader observation |
| **G2** symbol discovery | the runtime `sprint_symbol` scan finds its targets |
| **G3** `selinux_state` layout | the ZZIC BTF already supports it: 128 bytes, 9 fields, `enforcing` at bit offset 0 |
| **G4** write safety | **nothing above establishes this** |

**Do not test with the real helper via `insmod`.** It writes
`selinux_state.enforcing = 0` in its init path, so a "test" load performs G4's
risky write as a side effect and you cannot tell "the loader accepted it" from
"the write happened". Build a **probe variant** from the same source with the
write compiled out: it reports the resolved address and the layout it sees,
closing G1–G3 empirically and isolating G4 as the one remaining question.

A CRC mismatch, by contrast, fails the load cleanly (`disagrees about version of
symbol`) — that is the module loader working, not a crash.

### Collecting the run

This is the first build whose trace reaches logcat at all
(`MainActivity.append()` used to write only to the screen), so:

```sh
adb logcat -c && adb logcat -s DFReroot DirtyFrag | tee zzic-run.log
grep '\[DFR\]' zzic-run.log
adb shell cat /proc/sys/kernel/random/boot_id
```

Every boundary logs `boot_id`. States captured across different boots must never
be combined into one apparently successful chain.

Signals to expect, and what each one is *not*:

```text
TARGET_PROFILE=S25U_ZZIC  PASS exact identity
ZZIC_VENDOR_DIRECT_HASH=UNAVAILABLE_EACCES     expected; EACCES changes which
ZZIC_VENDOR_PROVENANCE=PASS_AVB                proof is required, never whether
PROCESS_LOOKUP=PASS                            via mProcessNames fallback
REMOTE_COMPONENT_REACHED=PASS                  our code ran in network_stack…
LIBEXP_LOADED=PASS                             …and dlopen succeeded there
NATIVE_PAYLOAD_PACKAGED=PASS                   the .so is in the APK
NATIVE_PAYLOAD_EXTRACTED=NO                    expected with extractNativeLibs=false
NETWORK_STACK_CAP_EFF=PASS                     newly enforced; was a dead pin
ZZIC_MODULE_POLICY=ALLOW                       only with ko_zzic_verified=1
ZZIC_MODULE_BINDING=PASS                       bundled bytes == pinned digest
```

`/dev/df` plus `dfm1..dfm3` present and `dfm4` absent is the expected marker set.
**No single `/dev/df*` marker means end-to-end compatibility.**

## 6. After root — not DFReroot's job

KernelSU, Zygisk Next and LSPosed on this firmware are already solved in
RMGLabs, including the permanent narrow DEFEX exception for
`zygisk_lsposed/zygisk/arm64-v8a.so` inside the ZZIC KernelSU. DFReroot must not
reimplement any of it, and must not depend on the standalone
`defex_lsposed_compat.ko`, which was a diagnostic instrument and would also
require a world-writable path this repository forbids (§3.6).

The DFReroot-profile ZZIC `ksud` is now built, bundled and pinned:
SHA-256 `b82c194db398ace90fa777bed4d8419c70041eb99d7bbe2915caa900100de75f`,
staged at `/data/system/dfreroot-ksud`, with pre- and post-write identity checks.
The remaining post-root item is restoration of SELinux to `Enforcing` after a
proven KernelSU readiness boundary; that path is still unimplemented/unverified
and must not be assumed.
