#!/bin/sh

psql postgres -U postgres \
    --set=auth_pass="$AUTH_PASS" \
    -f /setup.sql
