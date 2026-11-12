# Source from a mythos hook. The lounge is the master.
# No LOUNGE_DIR: the hook stops. A stale active_target (PROGRAM_71, PROGRAM_02, PROGRAM_68)
# must not enter a seat that is waiting for the operator.
# With LOUNGE_DIR: LOUNGE_PROG is the program the operator named.
if [[ -z "${LOUNGE_DIR:-}" || ! -d "${LOUNGE_DIR}" ]]; then
  exit 0
fi
LOUNGE_PROG=$(basename "$(dirname "$LOUNGE_DIR")")
[[ -n "$LOUNGE_PROG" ]] || exit 0
