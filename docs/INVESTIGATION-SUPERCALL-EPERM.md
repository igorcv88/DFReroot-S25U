# Investigation — `DFR_SU_STEP=DRIVER_FD errno=1` on Apply Modules

Open investigation, written 2026-09-29 after the twelfth physical run.

This file is a **working record, not authority**. What is proven lives in
`docs/S25U_ZZIC_COMPATIBILITY.md`; what to do next lives in `docs/HANDOFF.md`,
which points here. Fold the conclusion into both and delete this file once the
question in §3 is answered — an investigation note that outlives its question
is how prose drifts ahead of the code (`AGENTS.md §8`).

---

## 1. What just happened

Root itself **succeeded**. The full chain ran clean on boot
`30e61b44-267d-4f60-bb64-0a758f2eeedf`: identity gates, module binding, all six
patches, bootstrap, ksud, `POST_ROOT_COMPLETE=PASS`, `ROOT_RESULT=SUCCESS`,
`AUTO_ROOT_QUALIFIED=1`.

**Apply Modules (soft reboot) refused**, safely, having written nothing:

```
DFR_SU_STEP=DRIVER_FD errno=1
```

No reboot, no panic, no lost root. The transport refused and named its boundary,
which is the machinery working.

## 2. What the verdict proves, and what it does NOT

`errno=1` is `EPERM`. Two things follow, and one thing that looked like it
followed does not.

**Proven: the gate opened.** In `child_main()`, `SUPERCALL_GATED` is emitted
only when `!supercall_allowed && errno == EPERM`. The verdict was `DRIVER_FD`,
so `supercall_allowed` was TRUE — the post-root record for that boot carried
`transport_fix=kdp-cred-1`. The whole marker pipeline (RMGLabs-Payloads #5 and
#6, the per-boot `dfreroot-ko-loaded` evidence, `PostRootStatus`, the threading
through `prepare()` → JNI → `dfr_su_core`) **works end to end**. That is newly
established and should not be re-litigated.

**Proven: the syscall returned `EPERM`.**

**NOT proven — and the first version of this note got it wrong:** that the
supercall was refused *before the handler ran*, or that no fd was installed.
`reboot_handler_pre()` is a **pre**-handler. It queues the fd install as
`task_work` and returns 0 *without suppressing the syscall*, so the real
`sys_reboot` runs afterwards and its verdict says nothing about whether the
install happened. A failing syscall is consistent with both:

- the call never reached the handler (filtered, or refused before it), **and**
- the handler ran, the fd was installed, and the *real* syscall then failed.

Those are different facts and `AGENTS.md §3.7` forbids collapsing them.

The code had the same defect, which is why the log could not tell them apart:
`real_driver_fd()` returned immediately on `rc != 0` and never performed its
post-call scan. **Fixed** — the scan after the supercall is now unconditional
on the call's return value, the out-parameter is trusted only when the call
reported success, and `tools/profile_binding_audit.py` asserts both statically
(the path is unreachable from a host test, so §5's static-check rule applies).
Both assertions were mutation-verified.

**So the next run's token means more than this one's did.** On a build carrying
that fix, `DRIVER_FD errno=1` means the syscall failed **and** no fd exists
afterwards. That is the observation this investigation actually needs, and it
does not exist yet.

## 3. What changed since the run that *did* install an fd

The eleventh run's panic record proves the supercall reached the kprobe then:

```
[61.884299] KernelSU: ksu fd installed: 96 for pid 16452
```

Same shape of caller: a `fork()` of a system_server thread, `prctl(PR_SET_NAME)`
to `dfreroot-ksud`. Note the eleventh run says nothing about the *real*
syscall's return value — nothing read it, because the fd was found and the
chain moved on. So "the syscall used to succeed" is not among the things this
record establishes; it may have returned `EPERM` then too. What changed may
therefore be only the reading, not the kernel. So something between those two
runs changed the outcome from
"fd installed" to "EPERM". Candidates, **none verified**, listed so the next
session tests rather than reasons:

- **Seccomp.** This boot's system_server reports `Seccomp=2` (filter mode),
  `Seccomp_filters=1`. A filter returning `SCMP_ACT_ERRNO(EPERM)` for
  `reboot(2)` produces exactly this, with no kernel-side trace. PR #35's own
  body records that KernelSU whitelists `__NR_reboot` in the task's seccomp
  cache **for the manager and allowlisted uids only**
  (`ksu_handle_setresuid()`), which would make an unlisted caller's reboot a
  filtered syscall. That is a read of the source, not of this device.
- **The module changed.** The pair installed now is the one built by
  RMGLabs-Payloads run #10 (`d0cb516d…`), not the one live during the panic.
  Whether anything in #5/#6 touched the supercall path needs checking — the
  credential fix and the marker fix both claim not to, and both have `--verify`
  asserting the predicate's boundary is unchanged, but neither was written with
  the supercall kprobe in view.
- **Caller context.** The earlier fd install happened in a child that had
  already been through a different code path. Whether `supercall_allowed`,
  `prctl`, or the pipe/fd setup changed the task's state before the syscall is
  worth reading in the current `child_main()` order.

## 4. First moves for the next session

Cheapest-first, and each one distinguishes candidates rather than confirming a
guess:

0. **Re-run Apply Modules on a build carrying the re-scan fix.** Cheapest of
   all, and it may answer the question outright: if the transport now proceeds
   past `DRIVER_FD`, the fd was being installed all along and the only defect
   was the early return. If it still refuses with `DRIVER_FD errno=1`, that
   token now genuinely means "no fd afterwards" and the list below applies.
1. **Confirm the marker really is in the record**, rather than inferring it
   from the step name. `cat /data/system/dfreroot-post-root` and
   `cat /data/system/dfreroot-ko-loaded` as root. If `transport_fix=` is absent
   there, the first inference in §2 is wrong too and the bug is in the step
   mapping — check that first, it is one line.
2. **Ask the device whether the syscall is filtered.** A one-off probe that
   calls `syscall(__NR_reboot, 0xdeadbeef, 0xcafebabe, 0, &fd)` from a
   `u:r:system_server:s0` context and then reports **both** the errno **and**
   whether `[ksu_driver]` appeared in `/proc/self/fd` separates "filtered
   before the handler" from "handler ran, syscall failed". An errno-only probe
   does not, and proposing one was the same collapse as the code's.
   `reboot_handler_pre()` itself does no permission check at all — verified in
   KernelSU at the pinned SHA `932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e`.
3. **Read `dmesg` for the supercall.** A `KernelSU: ksu fd installed` line for
   the boot in question settles it directly. `dmesg | grep -i ksu`. Note
   `audit_lost` has been non-zero on this device — a missing line is not proof.
4. Only then decide whether anything else in the app or the module changes.

## 5. Things already settled — do not re-derive

- `ci.yml` is disabled and stays disabled; every validation runs offline
  (`AGENTS.md §5`). Do not dispatch workflows without asking (`§6.1`).
- The driver-fd supercall's gate is implemented and audited four ways
  (`§3.6.1`), mutation-verified. It is not the thing failing here — it opened.
- `reboot_handler_pre()` performs **no** permission check; the grant ioctl is
  gated by `allowed_for_su()`, which the DFR patch extends to this caller.
- The eleventh run's reboot was the paired module's `put_cred()` on a
  KDP-protected credential, fixed in RMGLabs-Payloads #4/#5. Not this.
- Samsung panic forensics that work here even at `ro.debug_level=0x4f4c`:
  `/sys/class/sec/sec_hw_param/{extra_info,extrb_info,extrc_info}`,
  `/proc/reset_summary`, `/proc/reset_history`, `/proc/reset_reason`.
  `pstore` and `logcat -L` are empty on this device and prove nothing.
- `persist.logd.size.main` and `.system` do raise the log buffer here;
  `persist.logd.size` alone only moves the kernel buffer.

## 6. Current pinned state

| | |
|---|---|
| ksud asset | `d0cb516da0047b1b918f84adf8ce7a389c6285de9282cd6301514a40849af7fc`, 6674552 bytes |
| source | RMGLabs-Payloads exact-port run #10, `main` @ `aa2d86ea` |
| DirtyFrag LKM | `b941d3234ad57235083f5778ff33c52cd4691aaf620d98be43fbaedc74ae3017` (untouched) |
| merged PRs | DFReroot-S25U #35 #36 #37; RMGLabs-Payloads #4 #5 #6 |

`SUPERCALL_GATE_OPEN` can now be promoted from `UNVERIFIED` — the marker
authorised the call on this boot — but the record should say plainly that the
syscall was then refused with `EPERM`, and name no cause.
