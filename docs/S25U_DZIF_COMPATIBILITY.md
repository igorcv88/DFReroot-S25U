# DFReroot — Galaxy S25 Ultra SM-S938B / One UI 9 Stable / DZIF

Offline-only record for the firmware `S938BXXUCDZIF`. It is the firmware the
owner's device updates to from `S938BXXUCZZIC`, which is what every physical
result in `docs/S25U_ZZIC_COMPATIBILITY.md` was observed on.

The rules this evidence is judged against — fail-closed, exact identity, proof
may change form but never be skipped — are in `AGENTS.md`, not restated here.

> **There is no DZIF target profile, and this document does not create one.**
> Nothing here was observed on a DZIF device. Every statement below is about
> firmware *files*. §2 states the limit precisely: **no satisfiable DZIF
> profile can be published yet with the inputs available** — which is not the
> same as "a DZIF profile is impossible". The distinction is load-bearing and
> §2 explains why.

## 1. What the current code does on a DZIF device: it refuses

This is the one property worth stating first, because it is the one that
protects the device, and it needed no change.

`DFR_PROFILE_ZZIC` pins `.model = "SM-S938B"` and `.device = "pa3q"`. A DZIF
device asserts both. Per `AGENTS.md` 3.1 a device that asserts the pinned model
or codename and deviates in any pinned field is a hard `MISMATCH` — it refuses
everything and does **not** fall through to the generic upstream path, where it
would run the chain against a kernel whose artefact hashes nobody pinned.

`tools/tests/test_target_profile.c` now asserts that directly, with the DZIF
values read from the firmware rather than invented:

```text
SM-S938B + DZIF (observed fingerprint)      -> MISMATCH
SM-S938B + DZIF (CSC-suffixed fingerprint)  -> MISMATCH
refusal names the firmware fields:  display=0 fingerprint=0
                                    kernel_release=0 kernel_version=0
anchors still asserted:             manufacturer, model, device, sdk,
                                    android_release, page_size, abi, kernel_arch
DZIF uname parses to android15/6.6  (module family only, never identity)
```

The per-field assertion matters as much as the verdict: a refusal that happened
because an *anchor* failed would mean the 3.1 case was not being exercised at
all. Both fingerprint shapes stay in the test now that the real one is known:
one is the value a DZIF device reports, the other the partition-level string
that is easy to mistake for it, and neither may pass.

## 2. Why no satisfiable DZIF profile can be published yet

`DFR_PROFILE_ZZIC` pins twelve identity fields and eight artefact/provenance
facts. The identity side is now **complete** for DZIF; the artefact side is
still largely unpinned, because those values are *runtime or vendor-partition*
captures.

The input set has grown since this record was first written, and the table
below reflects that: beyond the original kernel bundle and the
system/product/system_ext/system_dlkm/vendor_dlkm file tree, the owner has
since supplied `DZIF_BL_CORE.tar.gz` and `DZIF_STOCK_MODULES.tar.gz` and read
`Build.FINGERPRINT` off the device. What those closed is recorded in §6a.

| profile field | DZIF status |
| --- | --- |
| `manufacturer`, `model`, `device`, `abi`, `kernel_arch`, `page_size` | known (unchanged) |
| `sdk` = 37, `android_release` = 17 | known, from `system/build.prop` |
| `display` = `CP2A.260605.016.S938BXXUCDZIF` | known, from `system/build.prop` |
| `kernel_release` = `6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCDZIF-4k` | known, from the Image |
| `kernel_version` = `#1 SMP PREEMPT Sat Sep 19 07:11:26 UTC 2026` | known, from the Image |
| `kernel_image_sha256` | known: `b1b300e7e70d1aea03fcaff33dfc203b06f6322ac7ca177e6b9a39b6599713aa` |
| `btf_sha256` | known: `e13df32a16b5536c43897542b4dbc2c7082f2aefb91249bc94a06bfc5870950c` (byte-identical to ZZIC, by extraction) |
| `fingerprint` | **KNOWN** — `samsung/pa3qxxx/pa3q:17/CP2A.260605.016/S938BXXUCDZIF_OXMCDZIF:user/release-keys`, read with `getprop ro.build.fingerprint` on DZIF hardware and pinned in the RMG target header. It is the shape the ZZIC entry predicted, which is exactly why it had to be read rather than written down |
| `crashdump_sha256` | **UNKNOWN, but obtainable offline** — the path the chain hashes is `/apex/com.android.runtime/bin/crash_dump64` (`exp.c:82`, `target_profile.h:105`), *not* `/system/bin/`. The runtime APEX is not in the bundle (only the ART and Tethering ones are), but it ships inside `system_a.img`, which was extracted and hashed — so this needs an APEX extraction, not a device |
| `vendor_target_sha256`, `vendor_target_size` | **UNKNOWN** — `/vendor/lib64/libstagefrighthw.so` needs `vendor_a.img`, which was not extracted. Offline once it is |
| `vendor_target_context` | **UNKNOWN, device-only** — the live SELinux label |
| `vbmeta_digest` | **STILL UNKNOWN** — the DZIF top-level `vbmeta.img` arrived in `DZIF_BL_CORE.tar.gz`, but the digest is not a hash of that file: it is SHA-256 over its blob followed by the blob of each chained vbmeta. DZIF chains the same three as ZZIC (`dtbo`, `optics`, `prism`, in that order), and none of those three was supplied, so the digest cannot be reproduced. §7a says exactly which bytes close it |
| `vbmeta_hash_alg` | **known: `sha256`** — read from the signed descriptors in the DZIF `vbmeta.img` |
| `vbmeta_avb_version` | **STILL UNKNOWN, device-only** — and it is *not* the `required_libavb_version` in the vbmeta header, which reads `1.0` on DZIF and `1.0` on ZZIC alike while ZZIC pins `1.2`. `ro.boot.vbmeta.avb_version` is the AVB library version the *bootloader* used; the header field is the minimum version an image requires. Reading the header value into this field would pin the wrong quantity and would make ZZIC's own profile fail |
| the signed `vendor` hashtree descriptor (root digest, salt, dm-verity geometry) | **KNOWN, read out of the DZIF `vbmeta.img`** — and it differs from ZZIC in exactly the way that matters. See §2a |
| `verified_boot_state`, `vbmeta_device_state`, `flash_locked` | **known: `green`, `locked`, `1`** — read off the DZIF device |
| `verity_mode`, `vendor_fstype`, `vendor_mount_ro` | **UNKNOWN, device-only** — `ro.boot.veritymode` and the live `/vendor` mount, which no firmware file can answer |
| `libc_sha256`, `libcxx_sha256` | **UNKNOWN, but obtainable offline** — bionic ships in the runtime APEX, same extraction as `crash_dump64` |
| `network_stack_cap_eff` | **known: `0x800003c00`** — read from the live `network_stack` process on DZIF, together with uid 1073 and `u:r:network_stack:s0`. It is the same bitmask ZZIC carries, which is a fact about this capability set and not a reason to copy anything else across |
| `ksud_sha256`, `ksud_size` | **UNKNOWN** — the exact RMG DZIF daemon has not been built |

## 2a. The `/vendor` hashtree: same geometry, different bytes

Read with `tools/avb.py` out of each firmware's own top-level `vbmeta.img` -
the DZIF one from `DZIF_BL_CORE.tar.gz`
(`71755bbe966b44919ce47b948de6469a8b6f43bff07f736394e1491b8a9231e3`, which
matches that bundle's own manifest), the ZZIC one from
`evidence/zzic/avb/vbmeta.img` already in this repository:

| signed `vendor` hashtree field | ZZIC | DZIF |
| --- | --- | --- |
| data blocks (4 KiB) | 860,461 | **860,461** |
| tree blocks | 6,777 | **6,777** |
| FEC offset / size, in blocks | 867,238 / 6,856 | **867,238 / 6,856** |
| `dm_verity_version`, `hash_algorithm`, block sizes, `fec_num_roots` | 1, sha256, 4096/4096, 2 | **identical** |
| salt | `336ad2aa…cada6` | `613c9e09…848c0` |
| root digest | `794944fa…b42a3f` | `dcfb9c58…1c1e09` |

Both images are `avbtool 1.4.0`, both require libavb 1.0, and both chain
`dtbo -> optics -> prism`.

The geometry being identical is unsurprising: `/vendor` inherits the same
`15/AP3A.240905.015.A2` base on both builds, so the partition is the same size
with the same layout. **The root digest differing is the load-bearing fact.** It
proves the DZIF `/vendor` image is not bit-identical to ZZIC's, which means no
`/vendor`-derived pin can be carried over - not the hashtree fields, and above
all not `vendor_target_sha256`. Before this, that was an assumption the record
politely called "UNKNOWN"; it is now a measurement.

It cuts the other way too, and that is the useful half: `AGENTS.md` §3.3 makes
the vendor ELF's identity rest on the AVB chain precisely because the file
cannot be opened from the chain's own domain. The DZIF half of that chain is
now one field short - the reproduced `vbmeta_digest` - rather than entirely
absent.

A profile written with those fields absent or copied from ZZIC would be the
exact defect `AGENTS.md` §2 exists to prevent: a verdict with no evidence
behind it. In particular the vendor-ELF provenance chain (§3.3) cannot be
"partially" pinned — every element is compared and any divergence refuses, so a
chain with unknown elements is not a weaker gate, it is an unsatisfiable one.

**The correct state is therefore the current one: no DZIF profile, and a DZIF
device classifying `MISMATCH`.**

### "Not publishable yet" is not "not possible"

Worth stating plainly, because collapsing the two would mix an incomplete
implementation with a technical incompatibility, and they call for different
work.

Nothing about DZIF makes this profile unachievable. The kernel is the same
`android15-6.6` family, the BTF is byte-identical, the reference fixes are
absent in the same four compiled windows, and the Java/AMS and SELinux
surfaces the chain needs are present (§5). The *shape* of a
`DFR_PROFILE_DZIF` — its struct, its twelve identity fields, the gates that
compare them, the stage-scoped artefact masks — is already written and
already exercised by the host tests; porting it is a mechanical edit that
could be done today.

What is missing is **values**, not design: the provenance and runtime
quantities in §2's table. A profile carrying unknown or inherited values
would compile and would classify, and that is exactly the danger — it would
be a gate that cannot be satisfied honestly, or worse, one satisfied by
another firmware's evidence. So the profile is withheld at *activation*, not
abandoned at design.

Practically: do not read this document as "DZIF is incompatible". Read it as
"DZIF has no evidence yet, and here is precisely which bytes supply each
missing field".

But "not pinned yet" is not the same as "needs a device", and the table above
now says which is which, because conflating them sends the next investigation
to the wrong place. Most of the artefact set is **offline work on firmware
material nobody has extracted yet**: the runtime APEX out of `system_a.img`
gives `crash_dump64`, `libc` and `libc++`; `vendor_a.img` gives the vendor ELF
and its size; the firmware's vbmeta blobs give the digest, the AVB metadata and
the signed `vendor` hashtree descriptor, re-derived by
`tools/verify_zzic_avb.py` exactly as the ZZIC chain was. That tool exists
*because* a digest that was only ever observed once on a device is not the
standard this repository holds anywhere else, and treating DZIF's whole AVB
chain as device-only would throw that away.

What genuinely needs a booted DZIF device is narrow: `Build.FINGERPRINT`, the
boot-state properties (`verifiedbootstate`, `device_state`, `flash.locked`,
`veritymode`), `/vendor`'s live filesystem type, read-only flag and SELinux
label, and `network_stack`'s runtime `CapEff`. Plus the `ksud` digest, which
needs the RMG DZIF build rather than a device.

## 3. Kernel-side reference-fix state — re-derived, not quoted

Each window below was re-hashed here from the exact `Image_DZIF`: the symbol
address and extent come from the recovered symbol table (extent = distance to
the next symbol address), the bytes from the Image. All five reproduce the
digests the collection recorded.

| symbol | offset | size | SHA-256 |
| --- | ---: | ---: | --- |
| `esp_input` | `0x0101803c` | 868 | `3fd93a0fba3a40625542254a84ed57f0c6750d0e3fb62f90281207af74e7ea95` |
| `esp6_input` | `0x010acffc` | 868 | `4386799d9b0d501ff089dc3c76ee1df39c83eff9a31cf30ede77d12acd4577a1` |
| `__ip_append_data` | `0x00f9963c` | 3812 | `d68090fd43061212bdd23f961ab7fd7a496c95b629de3884f1ad52ff01042e01` |
| `__ip6_append_data` | `0x0105a538` | 3908 | `1950e21642a6d2b0efbe5382581a557bcb69a7eb0d1ba02adc0d763b7213f621` |
| `remove_waiter` | `0x011665ac` | 628 | `00d4af77e34c366ce36e08f1b4bdd657a5e8f16be2e136563aeb240701d88487` |

All five are byte-identical to the corresponding ZZIC windows.

| route | DZIF state |
| --- | --- |
| CVE-2026-43284 (Dirty Frag) | reference fix **ABSENT** in the compiled code |
| CVE-2026-43499 (`remove_waiter`, the RMG primitive) | reference fix **ABSENT** |
| CVE-2026-43074 (eventpoll), CVE-2026-64560 (POSIX CPU timers), CVE-2026-46242 (second Bad Epoll), CVE-2026-64468 (Binder UAF) | reference fix absent (collection analysis, not re-derived here) |

`AGENTS.md` §7 applies verbatim and is the reason this section says
"`ABSENT`" and nothing more: this is an independent static fact about compiled
bytes. **It is not proof of exploitability and must not be used to promote any
gate.** The userspace and runtime chain has to pass on its own evidence, and on
DZIF none of it has been observed.

## 4. CVE-2026-49881 is FIXED — the Telecom entry is gone

The original LSPromise entry
(`Telecom CVE-2026-49881 -> system_server -> network_stack -> DirtyFrag`) is
not available on DZIF. Verified here against the exact DZIF `Telecom.apk`
(SHA-256 `7c44d1bdeac3c8d253ac559029f803e149d1a16572507585c42983e524e195e4`,
changed from ZZIC's `1b6cc8210a…`), by scanning the decompressed
`classes.dex` string data:

```text
serviceClassExists                      0 occurrences
android.telecom.CLASS_EXISTENCE_CHECK   0
CLASS_EXISTENCE_CHECK                   0
control: "android.telecom"            127   (so "absent" is not "wrong file")
control: "TelecomService"             131
```

**This does not block DFReroot.** This fork does not use that entry: the
installer persists a system-UID app, and after the soft reboot `DFReroot` is
already inside `system_server` and hops to `network_stack` with `StageHop`.
`app/src/main/java/com/polygraphene/df/reroot/StageHop.kt` already documents
that difference from the original. Nothing in the tree needed changing for
this, and CVE-2026-49881 must not be revived or treated as a requirement.

## 5. StageHop — static state on DZIF

| component | DZIF | consequence |
| --- | --- | --- |
| `/system/framework/framework.jar` | **byte-identical** to ZZIC (`663b0469b19a5434cb3cef106d7d57065bf7bf3e5180efba07142b6f29f69133`) | the `IApplicationThread.scheduleReceiver` contract is the same bytecode that Gate C physically passed on ZZIC |
| `/system/bin/app_process64` | **byte-identical** (`08891284f79ebd9411d7ebd2e267bd2c083e8d5a02f2f192629fb126fabfeec8`) | the root `app_process` path the installer uses is unchanged |
| `NetworkStackGoogle.apk` | **byte-identical** (`f822e451a195043ce7df034bab5d793c2dcc376a647356c842832452697ac0e5`); its manifest still declares `com.android.networkstack.process` | the target process name is unchanged |
| `NetworkStackGoogle-arm64_v8a.apk` | **byte-identical** (`77a9f3a03e2a1b28ff88e2e8604573503047581fd74b2399edf88add391b4212`) | — |
| `/system/framework/services.jar` | **CHANGED**: `14e052a2d29af90c13ca609b5eacb1831333d16df706f31b61d58a61c17f13a2` (ZZIC: `abbf4aa4790783fcaf6fdf57f939cbaf13a7f672cdbee69e887395ebce999786`) | the reflection surface is the part that has to be re-checked |

Every name `StageHop` reflects on is still present in the changed DZIF
`services.jar` dex string data: `mOnewayThread` (1), `mThread` (29),
`mProcessList` (11), `mProcessNames` (2), `ProcessMap` (8), `ProcessRecord`
(35), `ApplicationThreadDeferred` (3), `ActivityManagerService` (106),
`getProcessRecordLocked` (1).

A string count is weak evidence and is recorded as such: it shows the member
names have not been removed or renamed. It says nothing about signatures,
declaring classes or call shapes, and in particular it cannot confirm the
collection's finding that `getProcessRecordLocked`'s shape/location moved. The
`mProcessList -> mProcessNames -> ProcessMap.get(name, uid)` fallback the fork
already implements is the path that should be relied on, and whether reflection
actually resolves inside the real process is a Gate C/D runtime question.

### SELinux — read out of the DZIF policy

From the bundled `system/etc/selinux/plat_sepolicy.cil` of this firmware:

```text
(allow network_stack self (netlink_xfrm_socket (read write create getattr
    setattr lock append map bind connect getopt setopt shutdown) ...
(allow network_stack self (netlink_xfrm_socket (nlmsg_read nlmsg_write) ...
(allow network_stack self (netlink_xfrm_socket (nlmsg) ...
(allow network_stack self (capability (net_bind_service net_broadcast
    net_admin net_raw) ...
```

The XFRM socket class and `CAP_NET_ADMIN` are granted to `network_stack`, so
the policy side is favourable offline. The `nlmsg` permission is new relative
to what the ZZIC notes recorded; it is an additional grant, not a removal.
`AGENTS.md` §2 still applies: no `avc: denied` is not evidence of permission,
and a grant in the policy is not evidence that the operation succeeds at
runtime.

## 6. Nothing here promotes a gate

The gate matrix stays in `docs/S25U_ZZIC_COMPATIBILITY.md` and is about ZZIC.
Per `AGENTS.md` §3.8 evidence is per-boot, and more fundamentally these are two
different kernels: a ZZIC physical PASS is evidence about the ZZIC image. The
DZIF column of that matrix is empty and must stay empty until a DZIF boot
produces its own records.

Two blockers are independent of firmware and are unchanged by this document:

- **Gate G (the module) is still unverified at run time**, and `AGENTS.md` §3.6
  means the chain cannot be exercised end to end while it is — not even
  deliberately, since the at-own-risk marker was removed by mechanism. What
  changed is that its *offline* half is no longer undecided for DZIF: see §6a.
  A module built for the ZZIC release string remains a different kernel's
  answer, the generic `dirtyfrag-android15-6.6.ko` is not a substitute, and
  neither is the upstream `ksud`.
- **`POST_SOFT_REBOOT_STABILITY` is a physical FAIL on ZZIC** in two distinct
  shapes (bootchecker rollback, and the `lmkd` stall). Neither has a DZIF
  observation, and neither becomes less likely because the firmware changed.

## 6a. What the later inputs closed

Recorded here because this document previously listed all three as open, and a
dossier that reports a settled question as unsettled sends the next
investigation to work that is already done. The work is the owner's, in
`igorcv88/RMGLabs-Payloads` (PR #7); the authoritative record is
`docs/SM-S938B-S938BXXUCDZIF.md` there, not this file.

| was open here | now | route |
| --- | --- | --- |
| `Build.FINGERPRINT` unread | **read** | `getprop ro.build.fingerprint` on DZIF hardware |
| `P0_KERNEL_PHYS_LOAD` not re-derived from DZIF bytes | **derived** | `xbl_config.elf` in `DZIF_BL_CORE.tar.gz`: FDT node `/soc/memorymap/memory@A8000000` with `reg=<0 0xa8000000 0 0x10000000>` and `mem-label="Kernel"`, against the Image header's `text_offset=0` |
| kernel symbol-version coverage undecided | **derived and cross-checked** | `DZIF_STOCK_MODULES.tar.gz`: 446 of 449 modules at the exact DZIF release, 4,973 symbols with CRC witnesses, zero conflicting CRCs, `module_layout=0x81972209` witnessed by all 446 |

Two details are worth carrying forward because both correct something stated
earlier in this repository's own instructions:

- **This platform has no `sboot.bin`.** `AGENTS.md`-adjacent guidance and an
  earlier revision of this file both pointed at `sboot.bin.lz4`, which is the
  Exynos path. `pa3q` is Qualcomm: the kernel load address lives in the XBL
  FDT, and the DZIF BL archive contains no `sboot.bin` at all. Anyone closing
  this field on a future Qualcomm Samsung target should read `xbl_config.elf`.
- **The three rejected witnesses are the right three.** `wonder.ko`,
  `spcom.ko` and `spss_utils.ko` carry the shortened
  `6.6.127-p33f4ffe-abogkiS938BXXUCDZIF-4k`, not the kernel's own release, so
  they are a different build's answer and are refused — `AGENTS.md` §3.5's
  witness rule, applied. That count independently matches what this
  investigation derived from `module_vermagic.txt` before any module bytes
  existed: 97 `system_dlkm` plus 349 `vendor_dlkm` at the exact release, three
  outside it.

What this does **not** establish: that the CRCs are right because many modules
agreed. They are right because each was read out of named module bytes whose
digest the provenance records, and because no two witnesses disagreed —
`AGENTS.md` §3.5 forbids a majority vote. And it remains an offline gate:
`insmod` on the device is still unobserved.

## 7. What would actually move this forward, in order

1. **RMG DZIF port first.** The exact `pa3q-S938BXXUCDZIF` target now exists in
   `igorcv88/RMGLabs-Payloads`, with its own offsets and P0 fingerprint derived
   from this same `Image_DZIF`, and it is deliberately absent from the support
   feed until `Build.FINGERPRINT` is read. DFReroot depends on that port
   producing a rooted DZIF device; it cannot pin its own profile first.
2. ~~**Read `Build.FINGERPRINT`**~~ — **done**, on DZIF hardware. The value is
   in §2's table, and all three consumers that were waiting on it are now
   filled: the RMG target header, the RMG support feed entry (bound to the
   published artifact digests) and the OneUILiquidGlass allowlist line.
3. **Do the offline half of the artefact set first — it needs no device.**
   Extract `com.android.runtime` from `system_a.img` for `crash_dump64`,
   `libc.so` and `libc++.so`; extract `vendor_a.img` for
   `/vendor/lib64/libstagefrighthw.so` and its size; extract the firmware's
   vbmeta blobs and run `tools/verify_zzic_avb.py` against them for the digest,
   the AVB metadata and the signed `vendor` hashtree descriptor. All of that is
   firmware material that simply has not been unpacked yet, and doing it before
   the update means fewer things to get right on a device with no rollback.
4. **Then capture what only a booted device can answer.** Most of this list
   has since been captured: `Build.FINGERPRINT`, `verifiedbootstate`,
   `device_state`, `flash.locked`, and `network_stack`'s uid, context and
   `CapEff` are all in §2's table. What is left is `veritymode`,
   `/vendor`'s live filesystem type, read-only flag and SELinux label, and the
   bootloader's `vbmeta.avb_version` and `vbmeta.digest`. §7a itemises them.
   Only then can a `DFR_PROFILE_DZIF` be written, and it must be written from
   observed values — `AGENTS.md` §4: if the device disagrees with the profile,
   the profile is wrong.
5. **Build the exact RMG DZIF KernelSU pair** and pin its digest, rather than
   adopting any generic artifact.
6. Only after all of that, re-run the Gate C/D/G questions on DZIF. They are
   runtime questions and no amount of file analysis answers them.

## 7a. The exact reads that are still missing, itemised

Written as a shopping list on purpose. Everything below is a single file or a
single command, and together they are the whole remaining gap between this
record and a `DFR_PROFILE_DZIF` that can be satisfied honestly. The split
matters because it decides where the work happens.

### Needs firmware bytes, no device

| what | where it comes from |
| --- | --- |
| `dtbo`, `optics`, `prism` vbmeta blobs | the DZIF AP tar (`dtbo.img`) and CSC tar (`optics.img`, `prism.img`). Each partition carries an AVB footer in its last 64 bytes - magic `AVBf`, then `vbmeta_offset` and `vbmeta_size` as big-endian u64s - and the blob at that range is what is needed. ZZIC's three are 2,112 / 2,176 / 2,176 bytes, so these are tiny. With them, `tools/avb.py` reproduces `vbmeta_digest` the same way it does for ZZIC, and `AGENTS.md` §3.3's chain stops being one field short |
| `crash_dump64`, `libc.so`, `libc++.so` | `com.android.runtime` APEX out of `system_a.img`. Note the path the chain hashes is `/apex/com.android.runtime/bin/crash_dump64`, not `/system/bin/` |
| `/vendor/lib64/libstagefrighthw.so` and its `st_size` | `vendor_a.img` out of `super.img`. §2a proves this cannot be taken from ZZIC |

### Needs the booted DZIF device

Four of these are one `getprop` each and can be collected in a single session:

| what | command |
| --- | --- |
| `verity_mode` | `getprop ro.boot.veritymode` |
| `vbmeta_avb_version` | `getprop ro.boot.vbmeta.avb_version` (the bootloader's value - see §2) |
| `vbmeta_digest`, to corroborate the reproduced one | `getprop ro.boot.vbmeta.digest` |
| `vendor_fstype`, `vendor_mount_ro` | the `/vendor` line of `/proc/self/mountinfo` |
| `vendor_target_context` | the live SELinux label of the vendor ELF, which needs a domain allowed to `getattr` it; `AGENTS.md` §3.3 records `SKIP` when it is not obtainable, and absence is never agreement |

### Needs a build, not a read

| what | which build |
| --- | --- |
| `ksud_sha256`, `ksud_size` | the DZIF `ksud` under the **dfreroot** staging contract, which stages from `/data/system/dfreroot-ksud` instead of world-writable `/data/local/tmp`. The published DZIF `ksud` is the **rmg** one and is not a substitute - `AGENTS.md` §3.6 is the reason the two contracts exist separately |
| `ko_filename`, `ko_sha256`, `ko_verified` | a DZIF `dirtyfrag-android15-6.6.ko`. The module already built for DZIF is **KernelSU's**, not DirtyFrag's; they are different modules with different imports, and the KernelSU one is no evidence about this one. What its build *can* reuse is the input that was the hard part: the exact Image export table and its provenance now exist in `RMGLabs-Payloads` under `kernelsu/evidence/pa3q-S938BXXUCDZIF/`, so a DZIF DirtyFrag module can be audited against the same CRCs |

### Deliberately not on this list

A `DFR_PROFILE_DZIF` skeleton with the known fields pinned and the rest NULL.
It would compile, it would classify a DZIF device as DZIF, and it would refuse
at the first artefact gate - which is correct behaviour, and is also exactly
what happens today via `MISMATCH`. The only thing it would buy is a refusal
message that names the missing evidence instead of the differing fingerprint,
and the price is a rewrite of the classifier that protects the device, reviewed
against a profile nobody can validate. `AGENTS.md` §8 - keep documentation
behind the code - cuts the same way for the code itself: the profile goes in
when its values exist, with its negative cases, not before.

What that does mean is that the multi-profile work is sequenced *after* the
reads above rather than before them. The shape is unchanged from §2's
"not publishable yet is not not possible": `dfr_classify_target` iterating a
profile table instead of comparing against one, `dfr_target_class` gaining a
DZIF member, and the three gates taking the profile they were handed rather
than assuming which one it is. That is a mechanical edit against a known
target; it is not the blocker, and doing it early would only mean doing it
twice.

## 8. Evidence provenance

Input bundles, both hashed before use:

| bundle | SHA-256 |
| --- | --- |
| `DZIF_KERNEL_CORE.tar.gz` | `9735f7bc4e579264efa9ec9912c1ebb859a6c9bdc2cfbdb4df1fbb2872d107a5` |
| `DZIF_FRAMEWORK_CORE_V3.tar.gz` | `27da2d22fe66f4167a50845c9854ab553cddf7155c3924dc24cb10ce15b5d05d` |
| `DZIF_BL_CORE.tar.gz` | `4549eb06b0457a3987f35391e9082c661ce27281ebe0d76b91d6d4dec6f72972` |
| `DZIF_STOCK_MODULES.tar.gz` | `93069b2fbd9e28a4edc717b8115c89248d7083128da1ec75521f9b82b7ebc900` |
| `DZIF_RUNTIME_NETWORKSTACK.tar.gz` | `57890ad159e3f24d02f410835d174abe1e32614fde10289624bd204310e5b231` |

Each of the seven files in `DZIF_BL_CORE.tar.gz` was checked against that
bundle's own `SHA256SUMS.txt` before being read; the `vbmeta.img` §2a parses is
`71755bbe966b44919ce47b948de6469a8b6f43bff07f736394e1491b8a9231e3`. The
NetworkStack bundle holds the three Mainline APKs only, so it supplies no
artefact digest for the chain - the `CapEff`, uid and context in §2 came from
the device's own runtime read, not from it.

Every file read out of the framework bundle was checked against that bundle's
own `MANIFEST_SHA256.txt` first. `DZIF_FRAMEWORK_CORE_V2.tar.gz` and the
truncated `super.img`
(`967c42ada6d1ba981fc7b92fdef0f25bcfea964b275778614ae4d74ccde71f88`) are
invalid inputs and were not used.

### Named non-inputs

Recorded because an exclusion that is only implicit survives exactly one
careless change.

- **`S938BXXUCZZHL`** — a build identifier the owner reports appearing in
  delta/OTA metadata alongside the DZIF firmware material (`updated_version=`),
  which is **not** `S938BXXUCDZIF`. That metadata was never an input to this
  work: it is absent from both bundles above, and nothing in this document or
  in `tools/tests/test_target_profile.c` reads it. It must not feed the DZIF
  fingerprint, the AVB chain, `crashdump_sha256`, the vendor ELF, or any other
  gate — a delta descriptor names the build it *produces*, and attributing it
  to DZIF would pin another firmware's identity. Until its provenance is
  understood it stays out entirely.
- **`DZIF_FRAMEWORK_CORE_V2.tar.gz`** and the truncated `super.img`
  (`967c42ad…`), as above.

Repository-local:

- [DZIF `MISMATCH` assertions](../tools/tests/test_target_profile.c)
- [the pinned ZZIC profile this refuses against](../app/src/main/jni/target_profile.c)
- [ZZIC compatibility dossier](S25U_ZZIC_COMPATIBILITY.md)
- [handoff](HANDOFF.md)
