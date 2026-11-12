# The root-operation companion

`companion/` — `com.polygraphene.df.companion`, its own uid, same signing key.

**Nothing here is physically validated.** The module builds, its decisions are
host-tested, and no device has run it. It promotes no gate and it does not yet
change what DFReroot does: wiring it into `RootEnvironment` is a separate
change (the laudo's PR C).

---

## 0. Physical PASS — 2026-11-12

The companion ran on the owner's device and attested the RMG pair. **This is
the evidence the reuse route rests on**, and it is recorded here rather than
inferred from anywhere else.

```text
exec_failed=false timed_out=false exit=0
ATTESTATION=RMG_CONTRACT ROOT_OPERATION=PASS KSUD_PINNED=PASS
CONTRACT_V1_ROUNDTRIP=PASS SELINUX_ENFORCING=PASS MODULE_NAMED=PASS

DFRC_UID=0
DFRC_SELINUX=Enforcing
DFRC_NONCE=a9d2897721ef58507a3efe5416e35a66
DFRC_KSUD_SHA256_PRE=95b2cc363f420b075c1b1301cb959d29d2cd5845372eb3e89b849d020981d8a5
DFRC_KSUD_SIZE=5797976
DFRC_STATUS=package=com.polygraphene.df.companion user=0 uid=10516 profile=present root=true persistence=not-checked
DFRC_STATUS_RC=0
DFRC_KSUD_SHA256_POST=95b2cc363f420b075c1b1301cb959d29d2cd5845372eb3e89b849d020981d8a5
DFRC_MODULES=kernelsu
DFRC_END=1
```

What it establishes: the companion was granted (uid 10516), a root operation
bound to **this call's** nonce succeeded, the pinned RMG daemon's bytes were
unchanged before and after it, and the loaded module answered the managerless
contract ioctl. The digest matches `95b2cc36…981d8a5` on both reads.

What it does **not** establish, and §2 says why at length: it is functional
evidence about the loaded module, not a cryptographic attestation of its bytes.

Two incidental facts worth keeping:

- the signed review build produced an installable APK with **no NDK installed**,
  even though `:app` declares `externalNativeBuild`. A step to provide one is
  unnecessary; do not re-add it.
- `DFRC_STATUS_RC=0` here is the *fixed* capture: the exit status is the
  daemon's, taken with no pipeline in between. The pre-fix script would have
  printed `0` whatever the daemon did.

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

The owner's physical procedure, 2026-11-12, in order:

1. install the companion normally, with its own uid;
2. grant it with `ksud profile grant com.polygraphene.df.companion`;
3. run the attestation and collect the **separate** signals;
4. confirm `/data/adb/ksud` still hashes `95b2cc36…981d8a5`;
5. confirm SELinux Enforcing and that **no DirtyFrag execution occurred**.

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
  decision — a third APK, a third digest in `SHA256SUMS.txt`, and generated
  notes describing a provider whose physical state is unknown — and the owner's
  decision of 2026-11-12 is: **not yet**, only after a positive physical
  attestation and PR C.
- **An installable, production-signed APK comes from a separate manual
  workflow**: `.github/workflows/companion-review-build.yml`. It is
  `workflow_dispatch` only, it **refuses any ref but the default branch**
  (because it holds the production signing secrets, so no pull-request head and
  no fork may reach the key through it), it runs the offline gates before
  signing anything, and it uploads — never publishes — a bundle of
  `df_companion-review.apk`, `SHA256SUMS.txt` and `build-provenance.txt`. The
  provenance records the commit, the APK digest and the **signing certificate
  fingerprint**, which is the point: the companion's Binder check compares the
  caller's certificate with its own, so an APK signed with another key refuses
  every request from DFReroot. The artefact is named
  `df_companion-review-EXPERIMENTAL-NOT-QUALIFIED` and the provenance leads with
  `STATUS: EXPERIMENTAL - NOT PHYSICALLY QUALIFIED`.

  Its version pair is `0.0.0-companion-review-<short sha>` / code 1 —
  deliberately not a release version. Everywhere else in this repo an absent
  version is a refusal; here an explicit development pair says what the build
  is instead of borrowing a number that would make it look publishable.
- ~~**DFReroot does not call it.**~~ **It does now** (PR C). `CompanionClient`
  binds the service from a background thread, checks the provider's signing
  certificate before binding, runs `TX_DESCRIBE` as a cheap version handshake
  and then `TX_ATTEST`, and `CompanionProtocol` **re-derives** the attestation
  level from the component signals instead of believing the summary. The app
  declares the companion's signature-level permission, without which the
  framework refuses the bind before any of this runs — a symptom identical to a
  missing install and to a certificate mismatch, which is why all three are
  reported separately.

  Two things PR C deliberately did not do. The early-boot dispatch does **not**
  ask the provider: the round trip costs a bind plus a root shell, its premise
  is a window measured in seconds, and without an attestation the acquisition
  route refuses anyway — so nothing is lost but diagnostic precision, and
  `tools/profile_binding_audit.py` fails if any early-path source reaches
  `CompanionClient`. And DFReroot still executes **no operation** through the
  provider: it reads that state and says so.
