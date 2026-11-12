# The root-operation companion

`companion/` — `com.polygraphene.df.companion`, its own uid, same signing key.

**Nothing here is physically validated.** The module builds, its decisions are
host-tested, and no device has run it. It promotes no gate and it does not yet
change what DFReroot does: wiring it into `RootEnvironment` is a separate
change (the laudo's PR C).

---

## 1. Why a separate app, and not DFInstaller or DFReroot itself

DFReroot runs entirely inside `system_server` (`sharedUserId=
android.uid.system`, `android:process="system"`). Two independent facts follow,
and each on its own is decisive:

- **The RMG managerless grant contract refuses it.** Per
  `RMGLabs-Payloads/docs/security/MANAGERLESS_APP_GRANTS_20261021.md`, grant
  resolution refuses shared-UID peers (including global peers) and requires an
  appId in `10000..19999`. DFReroot's uid is 1000. It cannot be granted — not
  "has not been".
- **That SELinux domain cannot execute or map what it would need.**
  `system_server` holds `map`/`read` but neither `execute` nor `execmod` on
  `apk_data_file`, so it can neither exec a helper from `/data` nor map its own
  native library; the KernelSU prctl/ioctl UAPI is unreachable from there.

**DFInstaller was considered and rejected**, though it is already granted
(observed 2026-11-12: uid 10508, `profile=present root=true`). The grant is a
*runtime* operation — `ksud profile grant <package>` from any full-root KSU
process, no module rebuild — so reusing an existing grant saves one command,
not a build cycle. Against that, DFInstaller owns the `packages.xml` write path,
the one write in this project that can brick the package database (AGENTS.md
§3.9), and the same RMG contract states that **every full-root KSU process is a
grant administrator**. Putting a standing IPC surface on that app points its
most dangerous capability at a new attack surface, permanently, to save a
one-time step. Owner's decision, 2026-11-12: separate module.

## 2. What the companion attests, and what it cannot

Version 1 exposes **two transactions and no command channel**: `TX_DESCRIBE`
(contract version and capabilities, no root, reads nothing) and `TX_ATTEST`.
There is deliberately no "run this as root" transaction — see §4.

`TX_ATTEST` runs one fixed script through `su` and reports every signal
separately (AGENTS.md §3.7):

| Signal | Meaning |
|---|---|
| `ROOT_OPERATION` | uid 0, **this call's** nonce echoed, and a read only root can perform |
| `KSUD_PINNED` | `/data/adb/ksud` digest equals the pinned RMG value **before and after** the invocation, and the size matches |
| `CONTRACT_V1_ROUNDTRIP` | the loaded module answered the RMG-only contract ioctl |
| `SELINUX_ENFORCING` | `getenforce` said Enforcing at the time of the call |
| `MODULE_NAMED` | a `kernelsu` entry exists in `/proc/modules` |

`ATTESTATION` is derived from them: `RMG_CONTRACT` requires `KSUD_PINNED` **and**
`CONTRACT_V1_ROUNDTRIP`; `ROOT_OPERATIONAL` means root was proven and the module
was not attested; `NONE` is everything else.

### Why the contract round-trip is evidence about the *loaded module*

`ksud profile status <pkg>` runs `ensure_uapi_version_matched()` and then
`ioctl::contract(0)` — ioctl `0xc0104b1e`, revision 1, `profile_size` 784,
**operation 0, which the contract defines as performing no write** — and fails
with "paired managerless kernel required" when the loaded module does not
implement it. Upstream KernelSU has no such ioctl. So a well-formed status line
says something about what the kernel is running, which a module *name* does not:
both pairs load as `kernelsu`.

This is why `MODULE_NAMED` is reported and contributes nothing. It is an
observation, kept visible, that is not allowed to stand in for evidence
(AGENTS.md §3.12).

### And it is functional evidence, not a cryptographic attestation of the module

This distinction has to stay explicit, because the gap between the two is where
an over-claim would live. A successful `APP_GRANTS_CONTRACT` round-trip proves
the loaded module **implements the managerless contract this build expects** -
revision 1, 784-byte profile ABI, an ioctl upstream does not have. It does
**not** hash the loaded module's text, and nothing in userspace can: two
differently-built RMG-patched modules would both answer, and so would any module
that implements the same contract.

So the claim `ATTEST_RMG_CONTRACT` licenses is exactly: *the kernel is running a
module that speaks the RMG managerless contract, and the pinned RMG daemon is
what asked it.* Not "the module's bytes are the ones we expect". Anything built
on top of this - PR C's reuse route included - inherits that boundary, and the
owner's review of 2026-11-12 asked for it to remain stated rather than implied.

### What it still cannot establish

- **Which process called.** DFReroot is in a shared uid, so Binder's
  `getCallingUid()` and `getPackagesForUid()` can show that uid 1000 carries
  `com.polygraphene.df.reroot` signed by this key — not that the caller *is*
  it. The platform offers no finer answer. `CallerAuthorization` says so in its
  own verdict text rather than implying it away, and it is the reason v1 can do
  nothing that matters.
- **The daemon's bytes, to the standard the chain's own transport uses.**
  See §3.

## 3. The residual window, stated rather than hidden

AGENTS.md §3.5.1 is explicit: a digest on a mutable path binds a name, not
bytes, and the fix is `execveat(fd, "", AT_EMPTY_PATH)` on the hashed
descriptor. This companion hashes the path, invokes it, and hashes again. The
weaker form is accepted here for three specific reasons:

- the hash, the invocation and the second hash are in **one** root shell,
  sequentially, microseconds apart — not across app logic and boots, which is
  the case §3.5.1 was written about;
- writing `/data/adb/ksud` requires root already, so an attacker who can
  exploit the window already has what it would win them;
- a replacement that persists is caught by the second digest, and a mismatch is
  a refusal.

**It is still owed work**, not a settled question: `dfr_verified_exec_core.h`
in `app/src/main/jni/` already implements the hash-and-`execveat` pattern and is
host-tested, so the fix is a port, not a design. Until it lands, treat
`RMG_CONTRACT` as "the pinned daemon ran, as far as a same-shell double hash can
say".

## 4. The invariants, and where each is enforced

| Invariant | Enforced by |
|---|---|
| No `sharedUserId`, ever | `tools/profile_binding_audit.py` |
| The exported service is signature-permission guarded, and the permission is `signature` | same |
| No caller string reaches a shell; only the constant script does | same |
| The attestation script contains no write-side token (`profile grant`, `insmod`, `setenforce`, `reboot`, …) | same |
| The contract round-trip is still performed | same |
| The root invocation has an enforced deadline and is force-killed on timeout | same |
| No world-writable path is referenced (§3.6) | same |
| Caller refusals: wrong uid, unanswered package lookup, missing client, foreign certificate, absent digest, version skew | `tools/tests/CompanionContractTest.java` |
| Attestation refusals: no nonce, wrong nonce, truncated report, duplicate keys, non-zero uid, no root-only read, foreign daemon, failed or unparsable contract probe, size mismatch, daemon swapped mid-call, a FAILING daemon printing a valid-looking line | same |
| The daemon's exit status is the daemon's, not a pipeline's | `tools/tests/test_companion_attest_script.py` (runs the extracted script against a failing fake daemon) **and** a shape guard in the audit |

The audit's guards were **mutation-tested**: each was broken on purpose and the
audit was confirmed to fail. One did not, and the reason is recorded in the code
— the guards greped raw text, and this file's own prose about `profile status`
satisfied the check meant for the code. They now run on `code_only()`.

**A static guard was not enough, and the record should say so.** The owner's
independent review of `a4ff533` found that the script captured `$?` after a
pipeline, so a daemon that *failed* reported `DFRC_STATUS_RC=0`. No text check
can see that. The script is now extracted from `Attestation.kt` and executed
against a fake daemon that exits non-zero — including one that prints a
plausible status line, which is the shape where the parser's prefix check passes
and the exit code is the only thing left to refuse it. Reverting the fix makes
that test fail; it was verified in both directions.

## 5. Granting it, and the physical acceptance criteria

The grant is the owner's deliberate act, from a root shell. The companion has no
button that asks for root authority on its own behalf:

```sh
su -c '/data/adb/ksud profile grant com.polygraphene.df.companion'
su -c '/data/adb/ksud profile status com.polygraphene.df.companion'
```

Acceptance for the first physical run, from the laudo §9.2 — **none of it has
been attempted**:

```
ROOT_PROVIDER=RMG
ROOT_AVAILABLE=PASS
ROOT_OPERATION=PASS
DFR_ACQUISITION=NOT_ATTEMPTED
PERSISTENT_DAEMON_CHANGED=NO
```

The companion reports the middle three directly. The first and the last belong
to DFReroot, and arrive with PR C.

## 6. What is not wired, deliberately

- **It is not a release artifact.** `./build.sh` builds it (so Gate E compiles
  it in CI) and emits `df_companion.apk`, but `release.yml` neither publishes it
  nor compares its digest. Adding it to the signed release is an explicit owner
  decision: it means a third APK in the release, a third digest in
  `SHA256SUMS.txt`, and generated notes that describe a provider whose physical
  state is unknown.
- **DFReroot does not call it.** `RootEnvironment.MODULE_ATTESTED_RMG` exists
  and is still unreachable until PR C binds this provider to it.
