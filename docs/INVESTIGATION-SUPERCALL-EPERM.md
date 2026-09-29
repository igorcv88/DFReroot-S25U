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

## 2. The one inference the log supports, and it is tight

`errno=1` is `EPERM`. In `app/src/main/jni/dfr_su_core.c`:

```c
if (ops->driver_fd(&driver_fd, supercall_allowed) != 0) {
    child_fail(status_fd,
               (!supercall_allowed && errno == EPERM)
                   ? DFR_SU_STEP_SUPERCALL_GATED : DFR_SU_STEP_DRIVER_FD,
               errno, NULL);
}
```

and in `real_driver_fd()` there are exactly three ways to return `-1`:

| path | errno | step it produces |
|---|---|---|
| gate withheld (`!supercall_allowed`) | `EPERM` | `SUPERCALL_GATED` |
| `syscall(__NR_reboot, …)` returned non-zero | the syscall's | `DRIVER_FD` |
| supercall returned 0 but no fd appeared | `ENOTTY` | `DRIVER_FD` |

The verdict was `DRIVER_FD` **with** `EPERM`. Row 1 is excluded by the step
name, row 3 by the errno. So:

- **`supercall_allowed` was TRUE.** The post-root record for this boot carried
  `transport_fix=kdp-cred-1`. The whole marker pipeline — RMGLabs-Payloads #5
  and #6, the per-boot `dfreroot-ko-loaded` evidence, `PostRootStatus`,
  the threading through `prepare()` → JNI → `dfr_su_core` — **works end to end.**
  That is newly proven and should not be re-litigated.
- **The supercall itself was refused with `EPERM`**, before any fd was installed.

Everything past that is unknown. **Do not write a cause into any file until the
device says one.** `AGENTS.md §3.6.1` carries three previous attributions in
this exact spot that were wrong, and the rule exists because of them.

## 3. What changed since the run that *did* install an fd

The eleventh run's panic record proves the supercall reached the kprobe then:

```
[61.884299] KernelSU: ksu fd installed: 96 for pid 16452
```

Same shape of caller: a `fork()` of a system_server thread, `prctl(PR_SET_NAME)`
to `dfreroot-ksud`. So something between those two runs changed the outcome from
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

1. **Ask the device whether the syscall is filtered.** From a root shell on the
   current boot, read `/proc/<system_server pid>/status` for `Seccomp` and, if
   available, dump the filter. A one-off C or `strace` probe that calls
   `syscall(__NR_reboot, 0xdeadbeef, 0xcafebabe, 0, &fd)` from a
   `u:r:system_server:s0` context and reports `errno` separates "seccomp
   refuses it" from "the kprobe refuses it" — the kprobe does no permission
   check at all (`reboot_handler_pre()` reads only the two magics, verified in
   KernelSU at the pinned SHA `932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e`).
2. **Confirm the marker really is in the record**, rather than inferring it from
   the step name. `cat /data/system/dfreroot-post-root` as root, plus
   `cat /data/system/dfreroot-ko-loaded`. If `transport_fix=` is absent there,
   the inference in §2 is wrong and the bug is in the step mapping instead —
   check that first, it is one line.
3. **Read `dmesg` for the supercall.** A `KernelSU: ksu fd installed` line for
   this boot would mean the syscall reached the kprobe and something later
   failed; its absence means the syscall never got there. `dmesg | grep -i ksu`.
   Note `audit_lost` has been non-zero on this device — a missing line is not
   proof.
4. Only then decide whether anything in the app or the module changes.

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
