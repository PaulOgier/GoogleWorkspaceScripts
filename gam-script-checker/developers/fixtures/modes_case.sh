#!/bin/bash
# expect: DESTRUCTIVE
gam info domain
case "$1" in
  read|check) gam print users ;;
  remove)
    gam delete user leaver@example.com
    ;;
  *) echo "use read or remove" ;;
esac
