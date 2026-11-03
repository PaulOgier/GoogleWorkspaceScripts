#!/bin/bash
# expect: CHANGES
# Three modes behind a tenant check: only the chosen mode's branch runs.
MODE="${1:-check}"
E="$HOME/evidence"
gam info domain > "$E/domain.txt"
if grep -q "Customer ID: C000000" "$E/domain.txt"; then
  if [ "$MODE" = "check" ]; then
    gam print licenses skus 1010020028
    gam whatis ann@example.com
    gam whatis ben@example.com
  elif [ "$MODE" = "create" ]; then
    gam create user ann@example.com firstname Ann lastname A password random
    gam create user ben@example.com firstname Ben lastname B password random
  elif [ "$MODE" = "finish" ]; then
    gam update group all@example.com add member ann@example.com
    gam update group all@example.com add member ben@example.com
    gam info user ann@example.com
  else
    echo "Unknown mode: $MODE"
  fi
fi
