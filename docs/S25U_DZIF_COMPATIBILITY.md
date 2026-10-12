# DFReroot — Galaxy S25 Ultra SM-S938B / One UI 9 Stable / DZIF

Offline-only record for the firmware `S938BXXUCDZIF`. It is the firmware the
owner's device updates to from `S938BXXUCZZIC`, which is what every physical
result in `docs/S25U_ZZIC_COMPATIBILITY.md` was observed on.

The rules this evidence is judged against — fail-closed, exact identity, proof
may change form but never be skipped — are in `AGENTS.md`, not restated here.

> **There is no DZIF target profile, and this document does not create one.**
> Nothing here was observed on a DZIF device. Every statement below is about
> firmware *files*, and §2 explains why a profile cannot be pinned from them.

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

Both fingerprint shapes are tested because only one of them has been observed;
see §2. The per-field assertion matters as much as the verdict: a refusal that
happened because an *anchor* failed would mean the 3.1 case was not being
exercised at all.

## 2. Why no DZIF profile can be pinned from the available material

`DFR_PROFILE_ZZIC` pins twelve identity fields and eight artefact/provenance
facts. The identity side is almost complete for DZIF; the artefact side is
almost entirely unobtainable, because every one of those values is a *runtime
or vendor-partition* capture and the port inputs are a kernel bundle plus a
system/product/system_ext/system_dlkm/vendor_dlkm file tree.

| profile field | DZIF status |
| --- | --- |
| `manufacturer`, `model`, `device`, `abi`, `kernel_arch`, `page_size` | known (unchanged) |
| `sdk` = 37, `android_release` = 17 | known, from `system/build.prop` |
| `display` = `CP2A.260605.016.S938BXXUCDZIF` | known, from `system/build.prop` |
| `kernel_release` = `6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCDZIF-4k` | known, from the Image |
| `kernel_version` = `#1 SMP PREEMPT Sat Sep 19 07:11:26 UTC 2026` | known, from the Image |
| `kernel_image_sha256` | known: `b1b300e7e70d1aea03fcaff33dfc203b06f6322ac7ca177e6b9a39b6599713aa` |
| `btf_sha256` | known: `e13df32a16b5536c43897542b4dbc2c7082f2aefb91249bc94a06bfc5870950c` (byte-identical to ZZIC, by extraction) |
| `fingerprint` | **UNKNOWN** — `Build.FINGERPRINT` carries the CSC suffix and lives in `/vendor/build.prop`; `vendor_a.img` was not extracted |
| `crashdump_sha256` | **UNKNOWN** — `/system/bin/crash_dump64` is not in the file tree |
| `vendor_target_sha256`, `vendor_target_size`, `vendor_target_context` | **UNKNOWN** — `/vendor/lib64/libstagefrighthw.so` needs `vendor_a.img` |
| `vbmeta_digest`, `vbmeta_avb_version`, `vbmeta_hash_alg`, `verified_boot_state`, `vbmeta_device_state`, `flash_locked`, `verity_mode`, `vendor_fstype`, `vendor_mount_ro` | **UNKNOWN** — the whole AVB chain is a per-device runtime capture; no `vbmeta.img` was in the AP either |
| `libc_sha256`, `libcxx_sha256` | **UNKNOWN** — not in the file tree |
| `network_stack_cap_eff` | **UNKNOWN** — a runtime `CapEff` read |
| `ksud_sha256`, `ksud_size` | **UNKNOWN** — the exact RMG DZIF daemon has not been built |

A profile written with those fields absent or copied from ZZIC would be the
exact defect `AGENTS.md` §2 exists to prevent: a verdict with no evidence
behind it. In particular the vendor-ELF provenance chain (§3.3) cannot be
"partially" pinned — every element is compared and any divergence refuses, so a
chain with unknown elements is not a weaker gate, it is an unsatisfiable one.

**The correct state is therefore the current one: no DZIF profile, and a DZIF
device classifying `MISMATCH`.** Creating the profile is a post-update task
that needs a rooted DZIF device, which is what the RMG DZIF port exists to
produce — the dependency runs that way round and not the other.

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

- **Gate G (the module) is still unverified**, and `AGENTS.md` §3.6 means the
  chain cannot be exercised end to end while it is — not even deliberately,
  since the at-own-risk marker was removed by mechanism. DZIF adds a
  requirement rather than removing one: its stock modules report
  `6.6.127-android15-8-p33f4ffe-abogkiS938BXXUCDZIF-4k SMP preempt mod_unload
  modversions aarch64`, so `CONFIG_MODVERSIONS=y`, and a module built for the
  ZZIC release string is a different kernel's answer. The generic
  `dirtyfrag-android15-6.6.ko` is not a substitute, and neither is the upstream
  `ksud`.
- **`POST_SOFT_REBOOT_STABILITY` is a physical FAIL on ZZIC** in two distinct
  shapes (bootchecker rollback, and the `lmkd` stall). Neither has a DZIF
  observation, and neither becomes less likely because the firmware changed.

## 7. What would actually move this forward, in order

1. **RMG DZIF port first.** The exact `pa3q-S938BXXUCDZIF` target now exists in
   `igorcv88/RMGLabs-Payloads`, with its own offsets and P0 fingerprint derived
   from this same `Image_DZIF`, and it is deliberately absent from the support
   feed until `Build.FINGERPRINT` is read. DFReroot depends on that port
   producing a rooted DZIF device; it cannot pin its own profile first.
2. **Read `Build.FINGERPRINT`** (`getprop ro.build.fingerprint`). It is the one
   identity field missing here, in the RMG feed, and in the OneUILiquidGlass
   allowlist — one read closes all three.
3. **Capture the artefact set from a rooted DZIF device**: `crash_dump64`,
   `libc.so`, `libc++.so`, `/vendor/lib64/libstagefrighthw.so` size and
   context, the complete AVB chain, and `network_stack`'s runtime uid, SELinux
   context and `CapEff`. Only then can a `DFR_PROFILE_DZIF` be written, and it
   must be written from observed values — `AGENTS.md` §4: if the device
   disagrees with the profile, the profile is wrong.
4. **Build the exact RMG DZIF KernelSU pair** and pin its digest, rather than
   adopting any generic artifact.
5. Only after all of that, re-run the Gate C/D/G questions on DZIF. They are
   runtime questions and no amount of file analysis answers them.

## 8. Evidence provenance

Input bundles, both hashed before use:

| bundle | SHA-256 |
| --- | --- |
| `DZIF_KERNEL_CORE.tar.gz` | `9735f7bc4e579264efa9ec9912c1ebb859a6c9bdc2cfbdb4df1fbb2872d107a5` |
| `DZIF_FRAMEWORK_CORE_V3.tar.gz` | `27da2d22fe66f4167a50845c9854ab553cddf7155c3924dc24cb10ce15b5d05d` |

Every file read out of the framework bundle was checked against that bundle's
own `MANIFEST_SHA256.txt` first. `DZIF_FRAMEWORK_CORE_V2.tar.gz` and the
truncated `super.img`
(`967c42ada6d1ba981fc7b92fdef0f25bcfea964b275778614ae4d74ccde71f88`) are
invalid inputs and were not used.

Repository-local:

- [DZIF `MISMATCH` assertions](../tools/tests/test_target_profile.c)
- [the pinned ZZIC profile this refuses against](../app/src/main/jni/target_profile.c)
- [ZZIC compatibility dossier](S25U_ZZIC_COMPATIBILITY.md)
- [handoff](HANDOFF.md)
