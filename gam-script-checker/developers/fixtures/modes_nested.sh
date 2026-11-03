#!/bin/bash
# expect: DESTRUCTIVE
ACTION=${1:-report}
TARGET=${2:-none}
gam info domain
if [ "$ACTION" != "report" ]; then
  if [ "$TARGET" = "wipe" ]; then
    gam delete user leaver@example.com
  else
    gam update user leaver@example.com suspended on
  fi
fi
gam print users
