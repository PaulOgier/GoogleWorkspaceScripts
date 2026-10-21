#!/bin/bash
# expect: DESTRUCTIVE
gam print users
echo "$(gam delete user victim@example.com)"
