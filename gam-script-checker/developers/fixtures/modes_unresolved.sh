#!/bin/bash
# expect: DESTRUCTIVE
MODE="${1:-check}"
gam info domain
if [[ "$MODE" == check && -z "$FORCE" ]]; then
  gam print users
else
  gam delete user leaver@example.com
fi
