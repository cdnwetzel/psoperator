# Snapshot attestation contract

**Status:** R-202 implementation contract

**Last reviewed:** 2026-08-19

## Boundary and non-goals

The observer is the only process that captures pixels, constructs perception
snapshots, and signs them. The untrusted planner receives a strict envelope and
may forward or discard it, but a meaningful deployment runs the observer under
an OS account whose signing-key file is unreadable by the planner account.

R-202 creates the evidence and commits its wire format. It does **not** make the
gatekeeper trust that evidence yet. R-203 must verify the signature, trusted key
identifier, lifetime, observer epoch, monotonic sequence, and nonce before risk
classification, approval, or execution. Until R-203 lands, the separated
gatekeeper parses the envelope but cannot distinguish a valid observer envelope
from one fabricated by a compromised planner.

## Protocol v2 envelope

Successful observer protocol v2 responses contain `attestation` and `health`,
not a second unsigned snapshot. The attestation has this strict shape:

```json
{
  "body": {
    "signature_version": 1,
    "key_id": "observer-2026-08",
    "observer_epoch": "64 lowercase hexadecimal characters",
    "issued_at": 0.0,
    "expires_at": 10.0,
    "nonce": "64 lowercase hexadecimal characters",
    "snapshot": {}
  },
  "signature": "64 lowercase hexadecimal characters"
}
```

The body is serialized as compact JSON with lexicographically sorted object
keys and non-finite numbers forbidden, then authenticated with HMAC-SHA256. The
signature therefore covers every snapshot field, including frame sequence,
capture time, screen dimensions, frame hash, and the complete ordered element
inventory, as well as the envelope metadata.

The lifetime is positive and at most 60 seconds. The default is 10 seconds.
Each observer service lifetime creates a random signed epoch, and every
envelope receives a fresh 256-bit nonce. These values are inputs to the R-203
replay state; their presence alone does not enforce replay protection.

Snapshot frame hashes are exact lowercase SHA-256 digests. Element identifiers
are derived from the frame sequence, frame hash, source, bounded label, and
bounding box, plus their ordered position within the snapshot. The schema also
rejects an element whose `frame_id` differs from its snapshot and rejects
duplicate element IDs.

## Key provisioning

Observer startup never creates or replaces signing material. Provision a key
under the observer service account, in a directory the planner account cannot
traverse:

```bash
sudo install -d -o psoperator-observer -g psoperator-observer -m 700 \
  /var/lib/psoperator-observer/attestation
sudo -u psoperator-observer psoperator attestation-keygen \
  --path /var/lib/psoperator-observer/attestation/observer-2026-08.json \
  --key-id observer-2026-08
```

The containing directory must already exist, be owned by the observer account,
and grant no group/other permissions; key generation never creates or relaxes
it. The key file is created exclusively with mode `0600`. Loading fails closed for
a missing file, symlink, non-regular file, wrong owner, any group/other access,
oversized or malformed JSON, unsupported file version, invalid key ID, or a
secret other than 256 bits. Service startup requires the explicit path:

```bash
PSOPERATOR_OBSERVER_ATTESTATION_KEY_PATH=/var/lib/psoperator-observer/attestation/observer-2026-08.json \
  psoperator observer --backend mss
```

The current owner/mode enforcement is POSIX-only. Windows provisioning and
loading fail closed until PSOperator has an ACL implementation that can prove
the planner account lacks read access; `chmod(0600)` is not treated as an ACL
substitute on Windows.

HMAC verification requires the gatekeeper to receive a separately installed,
owner-only copy of the same key material through an operator-controlled secret
provisioning channel. The copy and its containing directory must be owned by the
gatekeeper service account, and both copies must be unreadable by the planner.
R-203 will configure the gatekeeper's explicit trusted-key paths; repository
config must never contain the secret.

## Rotation and retirement

Key IDs are immutable identities, not aliases for replaceable bytes. Rotation
uses this order:

1. Provision a new file with a new key ID; never overwrite or reuse an old ID.
2. Install the matching owner-only verification copy for the gatekeeper.
3. Explicitly configure the R-203 trusted keyring with both IDs for the bounded
   overlap period.
4. Restart the observer on the new signing key and confirm health reports the
   new key ID and epoch.
5. After the old maximum envelope lifetime and in-flight work have drained,
   remove the old ID from the trusted keyring and remove its files through the
   deployment secret-management procedure.

The keyring loads only explicitly listed files, rejects duplicate IDs, and
raises on an unknown or retired ID. Merely finding another key file on disk
does not make it trusted.

## Failure behavior

- Missing or unsafe key material prevents the observer from opening capture or
  listening on IPC.
- Capture, perception, schema, clock, nonce, or signing failure returns no
  partial or unsigned snapshot and does not consume a frame sequence.
- Protocol v1 requests and responses are rejected after the v2 transition.
- Planner-side validation checks only the strict envelope shape; it deliberately
  has no signing-key import or verification authority.
- Unknown keys, bad signatures, expiry, replay, and sequence rollback remain
  explicit R-203 rejection cases and must be audited before any approval or
  execution path.
