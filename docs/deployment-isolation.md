# Deployment isolation (R-205)

**Goal:** the untrusted planner cannot reach the observer's signing material.
If it could, it could forge attested snapshots and defeat R-203 entirely. This
document is the account topology that keeps them apart, and the mechanisms that
enforce it.

## The two-account topology

| account | runs | holds | trust |
| --- | --- | --- | --- |
| **governance** (e.g. `psoperator`) | the observer, the gatekeeper, **and** the executor | the attestation key (owner-only), the IPC secret (owner-only), the audit log | trusted |
| **planner** (e.g. `psagent`) | the agent / model loop | nothing security-critical | **untrusted** — may be injected or compromised |

The planner reaches the gatekeeper **only** over loopback IPC. What the R-203
gate authenticates is the **observer envelope** the request carries (signature +
epoch + freshness + replay) — not the planner's action or context, which the
gatekeeper still evaluates through policy and freshness. So a planner cannot
forge *evidence* (it never sees the attestation key), but the action it proposes
is admitted on its merits, not trusted because it arrived. The **IPC secret**
authenticates the *gatekeeper → executor* hop, so a planner that bypassed the
gatekeeper still cannot drive input: it lacks the secret the executor requires.

### Why observer and gatekeeper share one account

The observer *signs* snapshots and the gatekeeper *verifies* them with a
**symmetric** HMAC key — the same secret. The key loader refuses to read a file
that is not owner-only **and** owned by the reading process
(`st_uid == geteuid()`). So the same key cannot be read by two different
accounts: symmetric attestation forces observer and gatekeeper into one
governance account. That is fine — both are trusted governance components; the
boundary that matters is planner-vs-governance, and it is fully cut. (Isolating
observer from gatekeeper would require asymmetric keys — see *Future* below.)

## The mechanisms (all fail closed, all tested)

- **Owner-only key material** (`common/attestation.py`). A key file is loaded
  only if it is a real regular file (no symlink), mode `0600` (no group/other
  bits), owned by the reading euid, and unchanged across the open (TOCTOU-safe
  dev/ino re-check). Anything broader — the shape a separate planner account
  would need to read it — is **refused**, so a misconfiguration cannot silently
  expose the key. The key directory must itself be pre-provisioned owner-only.
- **Owner-only IPC secret** (`common/auth.py`). `load_or_create_secret` creates
  the secret `0600` and, on loading a *pre-existing* one, **refuses** it fail-closed
  unless it is owner-only (no group/other bits) and owned by the reading euid — so a
  secret a separate planner account could read is never trusted, not merely
  discouraged. (Windows fails closed, as the key path does.)
- **Loopback-only IPC** (`common/ipc.py`). `IPCServer` refuses to bind anything
  but `127.0.0.1` / `::1` / `localhost`. The gatekeeper and executor services are
  never exposed on a routable interface; a remote party cannot reach them at all.
- **Authenticated hops.** The planner→gatekeeper request is authenticated by the
  R-203 envelope gate (not a secret the planner holds); the gatekeeper→executor
  hop is signed with the owner-only IPC secret, which the planner does not have —
  so it cannot reach the input device directly.

- **Pinned observer epoch (no restart-race).** The R-203 gate can pin the expected
  observer epoch out of band via `observer_epoch` in config. Set it in production:
  otherwise the gate trusts the first envelope after each restart (trust-on-first-use),
  and a compromised planner could race a restart to replay a still-valid envelope from
  an *old* epoch, pinning it and rejecting current frames (CWE-384). Trust-on-first-use
  is acceptable only in dev.

- **Durable frame watermark (the same restart-race, one layer down).** The
  stale-frame check refuses any envelope whose frame id does not advance past the
  last admitted one. That watermark used to live in memory only, so a restart
  disarmed the check entirely and *every* captured envelope still inside its TTL
  replayed cleanly — the epoch got its restart hole closed and the watermark, the
  same class of bug, did not. It is now persisted to `gate_state_path`
  (`.psoperator/gate_state.json` by default) and restored on start. A state file
  that exists but cannot be trusted makes the service **refuse to start**, and a
  gate that cannot write its watermark **refuses to admit** — treating a corrupt
  file as "no state" would turn it back into the silent downgrade this removes.

  The watermark orders envelopes by `(issued_at, frame_id)`. Frame ids restart at
  1 with every observer lifetime, so ordering on the frame id alone locked a
  restarted observer out until it had re-counted past its previous lifetime. The
  observer's clock does not restart, so a new lifetime advances at once, while an
  envelope issued earlier stays a rollback whatever its frame id. If the
  observer's clock steps backwards, admission pauses until the clock passes the
  last admitted issue time again. A missing state file counts as a first start
  only when its directory exists, is owned by the gate's account, and is not
  writable by group or other. If the directory is missing, the nearest existing
  ancestor must be owned by the gate's account or by root and not writable by
  group or other. The gate creates each missing directory with mode `0700`.
  On Windows the directory must be owner-only by its DACL, and the ancestor
  rule is the trusted-parent rule in the platform matrix below.

  The file is load-bearing for replay rejection, so it is held to the same
  ownership standard as the attestation key and the IPC secret: owner-only
  (`0600`), a regular file, owned by the running account, and opened without
  following symlinks — validated by `fstat` on the descriptor actually read, not
  by a `stat` on the path, which is a different file under a race. **A watermark
  another account can rewrite is a watermark it can lower**, which re-admits the
  captured frames this is meant to refuse. Writes are owner-only from creation
  under a random `O_EXCL` temp name, replaced atomically, and the parent
  directory is synced as well as the file — `fsync` on contents alone leaves the
  directory entry undurable, so a crash just after admitting could return to the
  old watermark.

  Worth knowing why this is the fix and nonce-set sizing was not: the nonce set
  is a second line here, because an evicted nonce is by construction an *old*
  frame and the watermark refuses it anyway. The window opens when the watermark
  is absent, which is exactly and only at restart.

These invariants are asserted in `tests/test_deployment_isolation.py` and the
attestation suite.

## Provisioning and running

1. **Create the governance and planner accounts.** The planner account must not
   be a member of any group that can read the governance account's key directory.
2. **Provision the attestation key as the governance account**, into a
   pre-created owner-only directory:
   ```sh
   install -d -m 700 ~/.local/state/psoperator/keys
   psoperator attestation-keygen --key-id observer-v1 \
     --path ~/.local/state/psoperator/keys/observer.json   # owner-only 0600 key
   export PSOPERATOR_OBSERVER_ATTESTATION_KEY_PATH=~/.local/state/psoperator/keys/observer.json
   ```
   On Windows, create the directory owner-only from an unelevated prompt (an
   elevated one can make Administrators the owner, which the loader refuses):
   ```powershell
   New-Item -ItemType Directory "$env:LOCALAPPDATA\psoperator\keys"
   icacls "$env:LOCALAPPDATA\psoperator\keys" /inheritance:r /grant:r "${env:USERNAME}:(F)" "SYSTEM:(F)"
   psoperator attestation-keygen --key-id observer-v1 --path "$env:LOCALAPPDATA\psoperator\keys\observer.json"
   ```
   The gatekeeper service **refuses to start without this key** (fail closed).
3. **Configure the service-manager environment (not just a shell).** The `export`
   above affects only the current shell; each unit gets its own environment, so set
   these in the observer, gatekeeper, and executor **units** (systemd `Environment=`
   / OpenRC conf.d), not interactively:
   - `PSOPERATOR_OBSERVER_ATTESTATION_KEY_PATH` — the key path, in the observer and
     gatekeeper units (both refuse to start without it).
   - `PSOPERATOR_OBSERVER_EPOCH` — the **same** 64-hex value in the observer and
     gatekeeper units (recommended; closes the restart-race — otherwise the gate is
     trust-on-first-use). Optional for startup.
   - `PSOPERATOR_IPC_SECRET_PATH` — a **shared absolute path** in the gatekeeper and
     executor units. Its default (`.psoperator/ipc.secret`) is relative to each
     process's working directory, so separate units would each create a *different*
     secret and every execution would be rejected. Point both at one absolute path
     under the governance account (e.g. `~/.local/state/psoperator/ipc.secret`); the
     loader creates it `0600` and refuses to load it if it is not owner-only.
   - `PSOPERATOR_GATE_STATE_PATH` — an **absolute** path in the gatekeeper unit,
     under an owner-only governance directory (e.g.
     `~/.local/state/psoperator/gate_state.json`). The default
     (`.psoperator/gate_state.json`) is relative to the working directory, so a
     unit started from a different directory finds no file, takes it for a first
     start, and silently resets the frame watermark.
   - `PSOPERATOR_KILL_SWITCH_PATH` — one **shared absolute path** in the gatekeeper
     unit and in the environment you run `psoperator kill`, `resume`, and
     `kill-drill` from (as the governance account), e.g.
     `/var/lib/psoperator/STOP` in a directory the governance account owns. Its
     default (`.psoperator/STOP`) is relative to each process's working directory, so
     `kill` from another directory would engage a stop the service never reads.
     The gatekeeper service and those three commands refuse a relative path, and
     `~` is not expanded. The service prints the path it watches at startup;
     check that it matches what `kill` prints.
4. **Run the services under their accounts.** The observer, gatekeeper, and
   executor services run as `governance` (one service-manager unit each — systemd
   on most Linux; OpenRC on the Gentoo host, where the observer already runs
   supervised); the agent loop runs as `planner`. On OpenRC,
   `scripts/deploy/openrc-setup.sh` writes the three units and one shared
   settings file with absolute paths (run it with `--dry-run` first). It sets up
   a single service account, so the planner split above stays a separate step.
5. **Verify the boundary** (Linux; on macOS use `stat -f '%Lp %Su'` and `lsof -nP -iTCP -sTCP:LISTEN`):
   ```sh
   stat -c '%a %U' "$PSOPERATOR_OBSERVER_ATTESTATION_KEY_PATH"  # expect: 600 governance
   stat -c '%a %U' "$PSOPERATOR_IPC_SECRET_PATH"                # expect: 600 governance
   # Every listener on the service ports must be loopback; any other bind FAILS the check:
   ss -ltnH 'sport = :8764 or sport = :8765 or sport = :8766' \
     | awk '{print $4}' | grep -vE '^(127\.0\.0\.1|\[::1\]):' && echo "EXPOSED — not loopback" || echo "loopback only"
   ```

## Platform support matrix (R-203/R-205)

On POSIX the isolation guarantees rest on ownership and mode bits. NTFS has no
mode bits, so on Windows the same guarantees are checked through each file's
owner and DACL (`psoperator/common/winacl.py`, roadmap D-01). A platform with
neither is not claimed and **fails closed**.

| platform | attestation key, IPC secret and gate state | status |
| --- | --- | --- |
| **Linux** | owner-only mode + owner-uid + TOCTOU-safe; verified in CI | **supported** |
| **macOS** | same POSIX path; verified in CI | **supported** |
| **Windows** | owner-only DACL, read from the opened handle; files created relative to a held, verified directory handle | **supported; verified in CI** (D-01) |

On Windows, "owner-only" means: owned by the running account; a present,
protected DACL with no inherited entry; and every allow entry naming that
account or `SYSTEM`. Administrators are refused on the files themselves. Files
are opened without following a reparse point, and names that would reach an
alternate data stream are refused. Every create, rename and removal is made
relative to a held handle on a verified directory, the counterpart of POSIX
`dir_fd`. The Windows branch never falls back to the POSIX checks; a test
asserts that a simulated Windows on a POSIX host refuses rather than trusting
mode bits.

A missing state directory under a parent is the one place Administrators are
trusted, as root is on POSIX: the parent must be owned by this account,
`SYSTEM` or Administrators, and only those may hold a right that adds, removes
or renames its entries. Profile and project folders pass; a drive root, where
any signed-in user may add a folder, does not.

## Future — asymmetric attestation (option C, out of scope for R-205)

To isolate the observer from the gatekeeper as well (three accounts, not two),
the attestation would move from symmetric HMAC to an asymmetric signature
(Ed25519): the observer signs with a private key it alone holds, the gatekeeper
verifies with the **public** key and holds no secret. Then the gatekeeper's key
being reachable is harmless, and it matches RL-010's asymmetric approval
discipline. This is a crypto re-architecture of the attestation path, deliberately
deferred; R-205's deployment isolation stands on the two-account topology above.
