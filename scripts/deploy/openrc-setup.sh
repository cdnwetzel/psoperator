#!/bin/bash
# Set up the observer, executor and gatekeeper as OpenRC services on one host.
#
# All three run as one service account on one host: IPCServer binds loopback
# only, so they cannot be split across machines. Every box-specific value is
# prompted for (defaults are read from an existing observer unit when there is
# one), so nothing host-specific lives in this file.
#
# Update the psoperator checkout or install first: the units run whatever
# version the executable resolves to.
#
# Run as root:  sudo bash scripts/deploy/openrc-setup.sh [--dry-run]
#   --dry-run   print every file and command instead of writing or running it
#
# Writes:
#   /etc/psoperator.env                  shared settings, sourced by each unit
#   /etc/init.d/psoperator-observer      rewritten to source it (old copy backed up)
#   /etc/init.d/psoperator-executor      new
#   /etc/init.d/psoperator-gatekeeper    new
#   <state dir>                          owner-only: IPC secret, gate state, STOP, audit log
#
# Not done here: the planner account split (docs/deployment-isolation.md),
# approvals (the gatekeeper's CLI approval has no console under a service
# manager, so T2/T3 actions fail closed), and the dx fleet binding.
set -eu

DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1
STAMP=$(date +%Y%m%d-%H%M%S)

say() { printf '%s\n' "$*"; }
ask() {  # ask VAR "question" "default"
    local reply
    read -rp "$2 [$3]: " reply
    printf -v "$1" '%s' "${reply:-$3}"
}
yes_no() {  # yes_no "question" -> 0 on y
    local reply
    read -rp "$1 [y/N]: " reply
    [ "$reply" = y ] || [ "$reply" = Y ]
}
run() {
    if [ "$DRY" = 1 ]; then say "DRY: $*"; else "$@"; fi
}
put() {  # put PATH MODE < content
    local content
    content=$(cat)
    if [ "$DRY" = 1 ]; then
        say "DRY: write $1 (mode $2):"
        printf '%s\n' "$content" | sed 's/^/    | /'
    else
        printf '%s\n' "$content" > "$1"
        chmod "$2" "$1"
    fi
}

if [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then
    say "run as root (sudo), or pass --dry-run"; exit 1
fi

# --- defaults from an existing observer unit, if any -------------------------
OBS=/etc/init.d/psoperator-observer
cur() { [ -r "$OBS" ] && sed -n "s/^export $1=\"\{0,1\}\([^\"]*\)\"\{0,1\}$/\1/p" "$OBS" | head -1; }
d_user=$( { [ -r "$OBS" ] && sed -n 's/^command_user="\{0,1\}\([^\"]*\)"\{0,1\}$/\1/p' "$OBS"; } | head -1)
d_bin=$( { [ -r "$OBS" ] && sed -n 's/^command="\{0,1\}\([^\"]*\)"\{0,1\}$/\1/p' "$OBS"; } | head -1)
d_display=$(cur DISPLAY); d_key=$(cur PSOPERATOR_OBSERVER_ATTESTATION_KEY_PATH)
d_ttl=$(cur PSOPERATOR_OBSERVER_SNAPSHOT_TTL_S)

# Every value below is written unquoted-safe into shell files that root and the
# services source, so each is checked against a strict pattern, never escaped.
check() {  # check VALUE REGEX WHAT
    [[ "$1" =~ $2 ]] || { say "invalid $3: $1"; exit 1; }
}
PATH_RE='^/[A-Za-z0-9._/-]+$'

d_user=${d_user%%:*}  # command_user may be "account:group"
ask SVC_USER "service account" "${d_user:-${SUDO_USER:-}}"
check "$SVC_USER" '^[a-z_][a-z0-9_-]*$' "account name"
SVC_HOME=$(getent passwd "$SVC_USER" | cut -d: -f6) || true
[ -n "$SVC_HOME" ] || { say "no such account: $SVC_USER"; exit 1; }
ask BIN "psoperator executable" "${d_bin:-$(command -v psoperator || true)}"
check "$BIN" "$PATH_RE" "executable path"
[ "$DRY" = 1 ] || [ -x "$BIN" ] || { say "not executable: $BIN"; exit 1; }
ask DISPLAY_ "X display the observer captures and the executor drives" "${d_display:-:99}"
check "$DISPLAY_" '^:[0-9]+(\.[0-9]+)?$' "display"
ask KEY "observer attestation key (owner-only file)" "${d_key:-$SVC_HOME/.config/psoperator/observer.key}"
check "$KEY" "$PATH_RE" "key path"
ask STATE "state directory, dedicated to psoperator (created owner-only)" "/var/lib/psoperator"
check "$STATE" "$PATH_RE" "state directory"
STATE=${STATE%/}
# Never take over an existing directory (e.g. /var/lib) that is not already ours.
case "$STATE" in */*/*) ;; *) say "state directory must be at least two levels deep: $STATE"; exit 1 ;; esac
# Every parent must already exist, be a real directory, be owned by root and
# be writable by root only. Then no other account can swap a component for a
# symlink between this check and the privileged install below.
parent=""
IFS=/ read -r -a parts <<< "${STATE#/}"
for part in "${parts[@]:0:${#parts[@]}-1}"; do
    parent="$parent/$part"
    if [ -L "$parent" ] || [ ! -d "$parent" ]; then
        say "parent $parent of the state directory must be an existing real directory"; exit 1
    fi
    meta=$(stat -c '%u %a' "$parent" 2>/dev/null || stat -f '%u %Lp' "$parent")
    if [ "${meta%% *}" != 0 ] || [ $(( 8#${meta##* } & 8#022 )) != 0 ]; then
        say "parent $parent of the state directory must be owned by root and writable only by root"; exit 1
    fi
done
if [ -e "$STATE" ]; then
    owner=$(stat -c '%U' "$STATE" 2>/dev/null || stat -f '%Su' "$STATE")
    if [ ! -d "$STATE" ] || [ -L "$STATE" ] || [ "$owner" != "$SVC_USER" ]; then
        say "$STATE exists and is not a directory owned by $SVC_USER; choose a new path"; exit 1
    fi
fi
ask TTL "snapshot lifetime, seconds" "${d_ttl:-30}"
check "$TTL" '^[0-9]+(\.[0-9]+)?$' "lifetime"
say "executor backends: dryrun (logs only, safe), pynput (drives the display), ch9329 (HID cable)"
ask BACKEND "executor backend" "dryrun"
check "$BACKEND" '^(dryrun|pynput|ch9329)$' "executor backend"
CH_PORT=""
if [ "$BACKEND" = ch9329 ]; then
    ask CH_PORT "HID cable serial port (absolute)" "/dev/ttyACM0"
    check "$CH_PORT" "$PATH_RE" "serial port"
fi

# One epoch shared by the observer and the gatekeeper; kept across re-runs.
EPOCH=""
[ -r /etc/psoperator.env ] && EPOCH=$(sed -n 's/^export PSOPERATOR_OBSERVER_EPOCH="\([0-9a-f]\{64\}\)"$/\1/p' /etc/psoperator.env)
[ -n "$EPOCH" ] || EPOCH=$(openssl rand -hex 32)

# The interpreter that runs psoperator, from the executable's shebang, kept as
# separate words so "#!/usr/bin/env python3" works too.
read -r -a PY < <(head -1 "$BIN" 2>/dev/null | sed -n 's/^#![[:space:]]*//p') || true
[ "${#PY[@]}" -gt 0 ] || PY=(python3)

say ""
say "service account $SVC_USER, executable $BIN, display $DISPLAY_"
say "key $KEY, state $STATE, executor backend $BACKEND"
yes_no "write the services with these settings?" || { say "nothing changed"; exit 0; }

# --- state directory and IPC secret -------------------------------------------
run install -d -m 700 -o "$SVC_USER" -g "$(id -gn "$SVC_USER" 2>/dev/null || echo "$SVC_USER")" "$STATE"
# Created once, before either service starts, so the two never race to make it.
MAKE_SECRET='import sys; from pathlib import Path; from psoperator.common.auth import load_or_create_secret as s; s(Path(sys.argv[1]))'
run su -s /bin/sh "$SVC_USER" -c "$(printf '%q ' "${PY[@]}" -c "$MAKE_SECRET" "$STATE/ipc.secret")"
if [ "$DRY" = 0 ]; then
    [ -r "$KEY" ] || { say "missing key $KEY: provision it with 'psoperator attestation-keygen' as $SVC_USER"; exit 1; }
fi

# --- shared settings ------------------------------------------------------------
CH_LINE=""
[ -n "$CH_PORT" ] && CH_LINE="export PSOPERATOR_CH9329_PORT=\"$CH_PORT\""
[ -e /etc/psoperator.env ] && run cp -p /etc/psoperator.env "/etc/psoperator.env.bak-$STAMP"
put /etc/psoperator.env 644 <<EOF
# psoperator services: shared settings (written by scripts/deploy/openrc-setup.sh).
# The operator's shell needs PSOPERATOR_KILL_SWITCH_PATH too, for kill/resume.
export DISPLAY="$DISPLAY_"
export PSOPERATOR_OBSERVER_ATTESTATION_KEY_PATH="$KEY"
export PSOPERATOR_OBSERVER_EPOCH="$EPOCH"
export PSOPERATOR_OBSERVER_SNAPSHOT_TTL_S="$TTL"
export PSOPERATOR_OBSERVER_HOST="127.0.0.1"
export PSOPERATOR_OBSERVER_PORT="8764"
export PSOPERATOR_GATEKEEPER_HOST="127.0.0.1"
export PSOPERATOR_GATEKEEPER_PORT="8765"
export PSOPERATOR_EXECUTOR_HOST="127.0.0.1"
export PSOPERATOR_EXECUTOR_PORT="8766"
export PSOPERATOR_EXECUTOR_BACKEND="$BACKEND"
export PSOPERATOR_IPC_SECRET_PATH="$STATE/ipc.secret"
export PSOPERATOR_GATE_STATE_PATH="$STATE/gate_state.json"
export PSOPERATOR_KILL_SWITCH_PATH="$STATE/STOP"
export PSOPERATOR_AUDIT_LOG_PATH="$STATE/audit.jsonl"
export PSOPERATOR_RISK_POLICY_PATH="$STATE/policy.json"
$CH_LINE
EOF

unit() {  # unit NAME DESCRIPTION ARGS DEPEND
    put "/etc/init.d/$1" 755 <<EOF
#!/sbin/openrc-run
# Written by psoperator scripts/deploy/openrc-setup.sh; settings in /etc/psoperator.env.
description="$2"
supervisor=supervise-daemon
command="$BIN"
command_args="$3"
command_user="$SVC_USER"
directory="$STATE"
output_log="/var/log/$1.log"
error_log="/var/log/$1.log"
. /etc/psoperator.env

depend() { $4; }
EOF
}

[ -e "$OBS" ] && run cp -p "$OBS" "$OBS.bak-$STAMP"
X_DEP="need xvfb"
[ -e /etc/init.d/xvfb ] || X_DEP="use xvfb"
unit psoperator-observer "psoperator observer: signed screen snapshots" "observer --backend mss" "$X_DEP"
EXEC_DEP="use xvfb"
[ "$BACKEND" = pynput ] && EXEC_DEP="$X_DEP"
unit psoperator-executor "psoperator executor: authenticated input ($BACKEND)" "executor --backend $BACKEND" "$EXEC_DEP"
unit psoperator-gatekeeper "psoperator gatekeeper: verifies snapshots and gates actions" "gatekeeper" \
    "need psoperator-observer psoperator-executor"
for s in observer executor gatekeeper; do run touch "/var/log/psoperator-$s.log"; run chown "$SVC_USER" "/var/log/psoperator-$s.log"; done

# --- operator shell ---------------------------------------------------------------
PROFILE="$SVC_HOME/.profile"
LINE="export PSOPERATOR_KILL_SWITCH_PATH=\"$STATE/STOP\""
if ! grep -qsF "$LINE" "$PROFILE" && yes_no "add the stop path to $PROFILE so 'psoperator kill' works from any folder?"; then
    if [ "$DRY" = 1 ]; then say "DRY: append to $PROFILE: $LINE"
    # Appended as the account itself, never as root: the account controls this path.
    else su -s /bin/sh "$SVC_USER" -c "printf '%s\n' $(printf '%q' "$LINE") >> $(printf '%q' "$PROFILE")"; fi
fi

# --- enable and start ------------------------------------------------------------
for s in observer executor gatekeeper; do run rc-update add "psoperator-$s" default; done
if yes_no "(re)start all three services now, so each runs with these settings?"; then
    # restart, not start: a service already running would keep its old settings.
    for s in observer executor gatekeeper; do run rc-service "psoperator-$s" restart; done
    if [ "$DRY" = 0 ]; then
        # Success means each service is up AND listening, on loopback only.
        ok=0
        for _ in $(seq 1 20); do
            ok=1
            for p in 8764 8765 8766; do
                ss -ltnH "sport = :$p" | grep -qE '(127\.0\.0\.1|\[::1\]):' || ok=0
            done
            [ "$ok" = 1 ] && break
            sleep 0.5
        done
        rc-status | grep psoperator || true
        for s in observer executor gatekeeper; do
            rc-service "psoperator-$s" status >/dev/null 2>&1 || { say "FAILED: psoperator-$s is not running; see /var/log/psoperator-$s.log"; exit 1; }
        done
        [ "$ok" = 1 ] || { say "FAILED: not all of ports 8764/8765/8766 are listening; see /var/log/psoperator-*.log"; exit 1; }
        if ss -ltnH 'sport = :8764 or sport = :8765 or sport = :8766' \
            | awk '{print $4}' | grep -vE '^(127\.0\.0\.1|\[::1\]):'; then
            say "EXPOSED: a service is listening beyond loopback"; exit 1
        fi
        say "all three services running; listeners: loopback only"
        stat -c '%a %U %n' "$KEY" "$STATE/ipc.secret"
        su -s /bin/sh "$SVC_USER" -c ". /etc/psoperator.env; $(printf '%q' "$BIN") observer-health" || true
        tail -n 3 /var/log/psoperator-gatekeeper.log
    fi
else
    say "services enabled but not started; start with: rc-service psoperator-gatekeeper start"
fi
say "done. Undo: rc-update del each service, remove /etc/init.d/psoperator-{executor,gatekeeper},"
say "and restore $OBS from $OBS.bak-$STAMP."
