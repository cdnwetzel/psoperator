# PSOperator

PSOperator is a security-oriented, fully local desktop-automation starter for
Python 3.11+. It observes a desktop, asks a locally served model or a recorded
skill for one action, evaluates that action against deterministic policy, and
only then hands it to an explicitly selected executor.

This repository is the synthesis of two prototypes — a broader cross-platform
runtime with hardware-backed execution, and a stricter planner/gatekeeper/
executor trust boundary — combined into one installable `psoperator` package
rather than two competing implementations.

PSOperator is a serious starter, not a claim that general desktop autonomy is
solved. The safety mechanisms described below are implemented and testable;
model accuracy, platform accessibility coverage, and unattended approval are
still prototype-grade.

## What is implemented

| Capability | Status |
| --- | --- |
| Screen capture | `mss` for normal desktops; UVC capture-card backend for crash-cart deployments |
| Change detection | Tile diffing and optional perceptual-hash keyframe filtering |
| Perception | Independent observer service with bounded, signed accessibility/OCR snapshots |
| Planning | Local OpenAI-compatible GUI-model loop, element-only local planner, deterministic test planner |
| Action safety | Strict action parsing, frame freshness checks, current-snapshot target validation |
| Policy | Deterministic T0–T3 classification; T2 approval; T3 hard-block by default |
| Execution | Dry-run default, opt-in `pynput`, and CH9329 serial-to-USB-HID backend |
| Isolation | Optional observer → planner → gatekeeper → authenticated executor topology |
| Operator control | Persistent kill-switch sentinel, never cleared automatically |
| Audit | Append-only SHA-256 hash-chained JSONL decisions with tamper verification |
| Skills | Recorded trajectories, structured skills, layered locator replay |

## Security model

The core invariant is simple: planning proposes; policy decides; only the
executor can actuate.

```text
observer: capture -> perception -> sign
                    |
                    v
          signed snapshot envelope
                    |
                    v
untrusted planner: plan action + forward envelope
                    |
                    v
gatekeeper: R-203 verification pending -> freshness -> target -> risk -> approval -> audit
                    |
                    v
          authenticated executor
```

The gatekeeper does not trust a model's risk estimate or prose explanation.
It classifies structured action data and observed target labels. Element-bound
actions must reference an ID from the exact perception snapshot associated
with the action's frame; invented IDs and mismatched frame hashes fail closed.

In process-separated mode, capture and perception run in the independent
observer service. It assigns the frame sequence and returns capture time,
dimensions, content hash, and a bounded element inventory inside a strict HMAC-
signed JSON envelope. The envelope also binds a signature version, key ID,
observer epoch, issue/expiry times, and nonce. The planner-side client has no
capture, perception-provider, or signing-key import path.

R-202 produces attested snapshots, but R-203 gatekeeper verification is still
required for the stronger compromised-planner boundary. Until then, the
gatekeeper parses and uses the forwarded envelope without authenticating it, so
it cannot distinguish a real observer envelope from a planner fabrication. The
wire contract and key lifecycle are documented in
[`docs/attestation.md`](docs/attestation.md).

Observer sequences are monotonic within one signed service epoch and restart at
1 with a new observer process. The signed epoch, key ID, and nonce give R-203
the material needed to reject rollback and replay, but those checks are not yet
active; observer and gatekeeper restart state must therefore remain coordinated.
Observer IPC is loopback-only but unauthenticated, so any process under the
local host policy can request structured screen text. R-205 will define the OS
account and IPC-access controls required for deployment isolation.

Risk policy defaults are deliberately conservative:

- T0 read-only actions are allowed automatically.
- T1 routine/reversible actions are allowed automatically.
- T2 sensitive actions require approval in the gatekeeper process.
- T3 destructive, credential, or financial actions are hard-blocked by
  default. Setting `PSOPERATOR_HARD_BLOCK_T3=false` is an explicit weakening;
  T3 still requires approval unless that setting is separately changed.

The global kill switch is checked before freshness, policy, or execution. Run
`psoperator kill` to engage it and `psoperator resume` to clear it explicitly.

### Two deployment modes

The in-process examples are convenient for development and retain the same
gatekeeper API, but they do **not** provide OS-process isolation. Treat a model
running in that topology as code in the same trust domain as the orchestrator.

The separated topology runs the observer, planner client, gatekeeper, and
executor as different processes. The gatekeeper-to-executor message is
HMAC-authenticated, short-lived, and nonce-protected. For a meaningful security
boundary, run the executor under a restricted OS account and protect
`.psoperator/ipc.secret` from the planner account. A shared account that can
read the secret weakens the boundary to process separation only.

Neither topology can control a locked session, a secure desktop/UAC prompt, or
firmware. The optional CH9329 + UVC topology moves capture and input out of band
and can reach pre-login screens, but it does not eliminate prompt-injection or
policy-classification risk.

## Quick start

Create an environment and install the core package plus development tools:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest -q
```

The default executor is dry-run. A headless smoke run uses a synthetic frame
and degrades cleanly if no local model endpoint is available:

```bash
python examples/run_agent.py --static
```

For a desktop run, start an OpenAI-compatible local GUI model and point the
configuration at it. For example, with llama.cpp:

```bash
llama-server -m /path/to/gui-model.gguf --port 8000
PSOPERATOR_MODEL_ENDPOINT=http://127.0.0.1:8000/v1 \
  python examples/run_agent.py --task "open the text editor"
```

Real same-machine input is intentionally an explicit flag:

```bash
python examples/run_agent.py --task "open the text editor" --real-input
```

Do not enable real input until you have inspected the active policy, verified
the kill switch, and tested the workflow with the dry-run executor.

## Process-separated mode

Start the services in dependency order. The executor remains dry-run unless
another backend is explicitly selected:

```bash
# once: root creates the directory for the unprivileged observer account
sudo install -d -o psoperator-observer -g psoperator-observer -m 700 \
  /var/lib/psoperator-observer/attestation
sudo -u psoperator-observer psoperator attestation-keygen \
  --path /var/lib/psoperator-observer/attestation/observer-2026-08.json \
  --key-id observer-2026-08

# terminal 1
psoperator executor --backend dryrun

# terminal 2, under the observer service account
PSOPERATOR_OBSERVER_ATTESTATION_KEY_PATH=/var/lib/psoperator-observer/attestation/observer-2026-08.json \
  psoperator observer --backend mss

# optional health check from another shell
psoperator observer-health

# terminal 3
psoperator gatekeeper

# terminal 4
python examples/run_isolated.py Save
```

The observer owns capture, accessibility/OCR perception, and snapshot signing;
the isolated client only requests its strict envelope. It uses the deterministic
element planner by default and submits one action plus the forwarded envelope
to the gatekeeper. Add `--llm` to use the configured local text planner. The
executor and gatekeeper create `.psoperator/ipc.secret` with mode `0600` on
first use. Observer signing material is never auto-created at service startup.

Observer protocol v2 requests are versioned and limited by the shared 4 MiB JSON transport.
The inventory is additionally capped at 512 elements by default, with bounded
labels and roles. Capture or perception failure returns no partial snapshot:
health changes to `degraded`, the sequence does not advance, and the service
retries on the next request. A successful request restores `ready`; process
shutdown closes the capture backend. If observer startup fails, the service
does not listen and planner clients fail closed as unavailable.

To opt into an executor that can move the local mouse and keyboard:

```bash
psoperator executor --backend pynput
```

To use a CH9329 crash-cart cable instead:

```bash
python -m pip install -e '.[ch9329,uvc]'
PSOPERATOR_CH9329_PORT=/dev/ttyUSB0 psoperator executor --backend ch9329
```

The CH9329 factory default is typically 9600 baud. The configured baud rate
must match the chip, and a plain USB-A-to-USB-A cable is not a substitute for a
serial-to-HID bridge.

## Configuration

`PSOperatorConfig` reads `PSOPERATOR_*` environment variables and an optional
`.env` file. Important settings include:

| Variable | Default | Purpose |
| --- | --- | --- |
| `PSOPERATOR_MODEL_ENDPOINT` | `http://localhost:8000/v1` | Local OpenAI-compatible model endpoint |
| `PSOPERATOR_MODEL_NAME` | `ui-tars-1.5-7b` | Model identifier sent to the endpoint |
| `PSOPERATOR_EXECUTOR_BACKEND` | `dryrun` | `dryrun`, `pynput`, or `ch9329` |
| `PSOPERATOR_AUDIT_LOG_PATH` | `psoperator_audit.jsonl` | Hash-chained decision log |
| `PSOPERATOR_KILL_SWITCH_PATH` | `.psoperator/STOP` | Persistent global-stop sentinel |
| `PSOPERATOR_HARD_BLOCK_T3` | `true` | Prevent destructive T3 execution |
| `PSOPERATOR_OBSERVER_PORT` | `8764` | Planner-facing observer service |
| `PSOPERATOR_OBSERVER_TIMEOUT_S` | `5.0` | Observer request timeout |
| `PSOPERATOR_OBSERVER_MAX_ELEMENTS` | `512` | Maximum elements in one snapshot |
| `PSOPERATOR_OBSERVER_ATTESTATION_KEY_PATH` | unset | Required owner-only observer signing-key file |
| `PSOPERATOR_OBSERVER_SNAPSHOT_TTL_S` | `10.0` | Signed-envelope lifetime, at most 60 seconds |
| `PSOPERATOR_GATEKEEPER_PORT` | `8765` | Planner-facing loopback service |
| `PSOPERATOR_EXECUTOR_PORT` | `8766` | Authenticated executor service |

The operator-provided home and work fleet presets ship under
[`psoperator/presets/`](psoperator/presets/).
Their network-address invariants are validated fail-closed. They are examples
of a specific deployment, not portable defaults; most developers should begin
with the localhost configuration.

## Auditing and emergency stop

Every gatekeeper outcome—including stale actions, invalid element targets,
denials, executor errors, and kill-switch rejections—is appended to the audit
chain. Verify it with:

```bash
psoperator audit-verify
psoperator audit-verify /path/to/another-audit.jsonl
```

The chain detects edits, deletion of interior records, reordering, and invalid
JSON. Like any local append-only file, it cannot prove that an attacker with
filesystem control did not truncate the tail or replace the entire file. A
production deployment should periodically anchor the current tail hash in a
separately controlled store.

Emergency stop commands are intentionally boring:

```bash
psoperator kill
psoperator resume
```

The stop is a durable file, so restarting a service does not silently resume
input.

## Project layout

```text
psoperator/
├── common/       validated element schemas, bounded JSON IPC, HMAC signing
├── perception/   capture, UVC, diffing, accessibility, OCR, snapshots
├── planning/     planners with no executor import path
├── runtime/      action schema, freshness, grounding, model loop
├── gatekeeper/   risk, approval, audit, kill switch, executor backends
├── services/     observer/client, gatekeeper, and executor processes
├── skills/       trajectory recording and layered replay
├── harness/      deterministic SoftLoop driver for local-model coding loops
└── remote/       notification/audit helpers
examples/         runnable local, isolated, skill, and crash-cart demos
tests/            unit and boundary tests
```

The formal release roadmap is maintained in
[`docs/roadmap.md`](docs/roadmap.md). The decisions used to combine the original
POCs are recorded separately in [`docs/integration.md`](docs/integration.md).
Multi-agent responsibilities, branch ownership, handoff evidence, and review
authority are defined in [`docs/agent-team.md`](docs/agent-team.md). Automated
contributors must also follow the machine-readable [`WORKFLOW.md`](WORKFLOW.md).

## Relationship to pxx

PSOperator and [pxx](https://github.com/cdnwetzel/pxx) are two independent,
MIT-licensed tools, loosely coupled in one direction. pxx is a general
local-first AI coding-agent runtime (any repo, any model); PSOperator is a
desktop-automation agent with a fail-closed trust boundary. The only coupling
is optional: PSOperator's `harness` package can drive the `pxx` binary as one
pluggable **Coder** backend — via subprocess and a narrow `Coder` protocol, so
it is swappable for any OpenAI-compatible model or another agent. pxx has no
dependency on PSOperator, and PSOperator's core (perception, gatekeeper,
executor) does not require pxx. Neither is a subsystem of the other.

## Multi-agent development

PSOperator separates implementation, adversarial review, deterministic gates,
and release authority. The current team uses Codex as integration lead, PSAIOS
as the architecture and governance peer, an additional Codex agent for core
implementation, Claude Code for adversarial security review, Kimi Code for
perception and platform work, and Antigravity for black-box integration and
release readiness.

PXX 2.5.3 supplies governed execution for compatible tasks: bounded scopes,
budgets, isolated goal nodes, run evidence, and verification. Model review is
not a substitute for deterministic tests, independent security review, or
human release authority.

PXX also provides trusted per-role model lanes. The `plan` lane may decompose a
goal and the `reviewer` lane may produce model-review evidence; other declared
lanes remain incremental integration seams until a runtime consumer adopts
them. Role endpoint routing is operator-controlled through trusted user
configuration, environment variables, or CLI flags and cannot be redirected by
this repository's `pxx.toml`.

The orphan branch `coord/psoperator-psaios` is a serialized two-party message
bus, not a product branch. Only the role holding its recorded baton may write a
turn. Specialist agents work in separate product branches and hand their
evidence to the Codex integration lead; they do not write concurrently to the
coordination branch or directly to `main`.

The minimum contribution contract is:

1. one accountable author and one isolated branch or worktree;
2. a declared base commit, path scope, non-goals, tests, and reviewer;
3. reproducible verification and explicit disposition of review findings;
4. no self-approval or self-merge of security-sensitive work.

See the [multi-agent engineering model](docs/agent-team.md) for the complete
role matrix, PXX operating rules, handoff format, and initial `v0.2` work
allocation.

## Development and verification

Run the full suite before changing trust-boundary code:

```bash
pytest -q
```

For governed PXX work, validate the repository contract first:

```bash
pxx workflow validate
```

The checked-in workflow permission profiles exclude shell access, and
`pxx.toml` does not auto-commit. Run PXX from a clean, agent-specific worktree
with a narrower task scope whenever possible. PXX memory is supporting context
only; tracked documentation remains authoritative and secrets or desktop data
must never be stored there.

Particularly important tests cover:

- action parsing and frame binding;
- snapshot-envelope canonicalization, signing-key safety, and explicit rotation;
- element-ID validation and coordinate resolution;
- deterministic risk classification and T3 hard blocks;
- kill-switch precedence;
- executor IPC authentication and replay rejection;
- audit-chain tamper detection;
- the absence of executor/input-library imports from planning code;
- CH9329 packet construction without touching real hardware.

When adding an action type, update the parser, risk classifier, every enabled
executor, audit serialization, and tests together. Unsupported actions should
raise and be audited; silently approximating an action is unsafe.

## Known limits

- General GUI-model performance is not reliable enough for unattended,
  open-ended desktop work. Recorded skills and deterministic locators should
  be preferred whenever possible.
- Accessibility support is strongest on Windows. Linux AT-SPI traversal and
  macOS Accessibility support are incomplete.
- OCR and image grounding are optional and quality depends on the installed
  backend. Template-image grounding remains a stub.
- The ntfy approval sender exists, but its callback receiver is not complete;
  it therefore denies by default.
- Coordinate actions remain available for canvas applications, but they are
  inherently less robust than frame-bound accessibility/OCR element targets.
- Keyword policy reduces blast radius; it cannot infer every destructive
  semantic phrasing. Default T3 hard blocking and human review remain
  important.
- Local IPC authentication protects the executor hop, not a host already
  compromised at the executor account's privilege level.
- Snapshot envelopes are signed, but the gatekeeper does not authenticate them
  until R-203; R-202 alone does not contain an arbitrary-code planner.
- Attestation-key provisioning currently enforces POSIX ownership and mode;
  Windows fails closed until equivalent ACL verification is implemented.

Those constraints are design inputs, not footnotes. Contributions that narrow
them should include a reproducible test and should preserve fail-closed
behavior when a backend, model, or external service is unavailable.
