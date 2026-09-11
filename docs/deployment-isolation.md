# Deployment isolation (R-205)

**Goal:** the untrusted planner cannot reach the observer's signing material.
If it could, it could forge attested snapshots and defeat R-203 entirely. This
document is the account topology that keeps them apart, and the mechanisms that
enforce it.

## The two-account topology

| account | runs | holds | trust |
| --- | --- | --- | --- |
| **governance** (e.g. `psoperator`) | the observer **and** the gatekeeper | the attestation key (owner-only), the IPC secret, the audit log | trusted |
| **planner** (e.g. `psagent`) | the agent / model loop | nothing security-critical | **untrusted** — may be injected or compromised |

The planner reaches the gatekeeper **only** over loopback IPC, authenticating
with the shared IPC secret. It never sees the attestation key.

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
- **Loopback-only IPC** (`common/ipc.py`). `IPCServer` refuses to bind anything
  but `127.0.0.1` / `::1` / `localhost`. The gatekeeper and executor services are
  never exposed on a routable interface; a remote party cannot reach them at all.
- **Authenticated planner IPC.** The planner authenticates to the gatekeeper with
  the IPC secret (loopback + secret), and every observer envelope it forwards is
  independently authenticated by the R-203 gate before anything trusts it.

These invariants are asserted in `tests/test_deployment_isolation.py` and the
attestation suite.

## Provisioning and running

1. **Create the governance and planner accounts.** The planner account must not
   be a member of any group that can read the governance account's key directory.
2. **Provision the attestation key as the governance account**, into a
   pre-created owner-only directory:
   ```sh
   install -d -m 700 ~/.local/state/psoperator/keys
   psoperator provision-attestation-key   # writes an owner-only 0600 key
   ```
   Set `observer_attestation_key_path` to that file. The gatekeeper service
   **refuses to start without it** (fail closed).
3. **Run the services under their accounts** — one service manager unit per
   account (systemd on most Linux; OpenRC on the Gentoo host, where the observer
   already runs as a supervised service). Observer and gatekeeper run as
   `governance`; the agent loop runs as `planner`.
4. **Verify the boundary:**
   ```sh
   stat -c '%a %U' "$observer_attestation_key_path"   # expect: 600 governance
   ss -ltnp | grep -E '127.0.0.1:(8764|8765|8766)'    # loopback only
   ```

## Platform support matrix (R-203/R-205)

The isolation guarantees rest on POSIX ownership and mode semantics. The
supported, verified deployment platforms are POSIX; unclaimed platforms **fail
closed** rather than run with an unverified boundary.

| platform | attestation key provisioning / loading | status |
| --- | --- | --- |
| **Linux** | owner-only mode + owner-uid + TOCTOU-safe; verified in CI | **supported** |
| **macOS** | same POSIX path; verified in CI | **supported** |
| **Windows** | provisioning and loading **refuse to run** — an unverified NTFS ACL is never trusted | **fail closed; not supported** |

Windows support requires implementing and verifying NTFS ACL checks equivalent to
the POSIX owner-only guarantee. It is deliberately deferred and tracked as the
Windows attestation/capture port (roadmap D-01): a platform with no host in the
fleet gets no unverifiable security path — attestation leads, coverage follows.
That Windows attestation-key provisioning and loading fail closed is itself
asserted by a test, so the "POSIX-only" claim cannot silently rot into a
half-implemented Windows path.

## Future — asymmetric attestation (option C, out of scope for R-205)

To isolate the observer from the gatekeeper as well (three accounts, not two),
the attestation would move from symmetric HMAC to an asymmetric signature
(Ed25519): the observer signs with a private key it alone holds, the gatekeeper
verifies with the **public** key and holds no secret. Then the gatekeeper's key
being reachable is harmless, and it matches RL-010's asymmetric approval
discipline. This is a crypto re-architecture of the attestation path, deliberately
deferred; R-205's deployment isolation stands on the two-account topology above.
