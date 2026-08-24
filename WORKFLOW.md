# WORKFLOW.md — PSOperator agent workflow contract

This is the repository-owned, agent-legible workflow contract for PXX and
other automated contributors. The fenced TOML block is validated by `pxx
workflow validate`. Unknown keys, missing sections, and invalid values fail
closed.

The contract does not delegate release authority. Repository documentation,
task-specific scope, independent review, and roadmap exit criteria remain
binding.

```toml
schema_version = 1

hooks = []

[states]
initial = "idle"
names = ["idle", "planning", "executing", "verifying", "reviewing", "completed", "failed"]
terminal = ["completed", "failed"]

[budgets]
max_rounds = 20
max_tokens = 200000
max_cost_usd = 5.0
max_wall_seconds = 1800.0
max_diff_lines = 500

[commands]
test = "python -m pytest -q -p no:cacheprovider"
lint = "python -m ruff check psoperator tests examples"
format = "python -m ruff format --check psoperator tests examples"
build = "uv build"

[permissions]
ask = ["read", "memory"]
plan = ["read", "memory"]
edit = ["read", "write", "memory"]
auto = ["read", "write", "memory"]

[protected_paths]
paths = [
    "WORKFLOW.md",
    "pxx.toml",
    ".github/",
    "pyproject.toml",
    "docs/roadmap.md",
    "docs/agent-team.md",
    "docs/attestation.md",
    "psoperator/cli.py",
    "psoperator/config.py",
    "psoperator/common/auth.py",
    "psoperator/common/attestation.py",
    "psoperator/common/ipc.py",
    "psoperator/common/schema.py",
    "psoperator/gatekeeper/",
    "psoperator/perception/snapshot.py",
    "psoperator/services/",
    "tests/test_gatekeeper.py",
    "tests/test_attestation.py",
    "tests/test_ipc.py",
    "tests/test_isolation.py",
    "tests/test_integration.py",
    "tests/test_observer.py",
]
```

## Required workflow

1. Read `README.md`, `docs/roadmap.md`, and `docs/agent-team.md`.
2. Confirm the task owner, base commit, allowed paths, non-goals, reviewer, and
   acceptance commands before writing.
3. Establish a clean baseline and reproduce the target behavior or failure.
4. Make the smallest change inside the assigned branch and scope.
5. Preserve fail-closed behavior at every trust boundary.
6. Run the task-specific checks plus the declared test, lint, and format
   commands.
7. Produce the handoff evidence required by `docs/agent-team.md`.
8. Stop at ready-for-review. Never self-approve or self-merge a
   security-sensitive change.

The declared protected paths identify the review-sensitive product surface.
PXX 2.5.3 validates and records this contract, but its built-in protected-path
set is maintained by PXX itself. PSOperator-specific protection therefore also
depends on narrow task scopes, isolated branches, independent review, and the
integration gate.

PXX role-model endpoints are intentionally absent from this repository-owned
contract. They are a data-egress surface and must be selected through trusted
operator configuration, environment variables, or CLI flags. At PXX 2.5.3,
`roles.plan` and `roles.reviewer` are the only lanes with runtime consumers;
declaring another lane does not by itself make that lane operational.
