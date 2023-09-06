#!/bin/sh

PGPASSWORD=$(cat /run/secrets/postgres_password) \
psql postgres -U postgres \
    --set=auth_pass="$(cat /run/secrets/auth_pass)" \
    -f /setup.sql
