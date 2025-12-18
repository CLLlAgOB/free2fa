#!/usr/bin/env sh
set -e
chown -R apiuser:apiuser /app/certs /opt/db
update-ca-certificates
exec gosu apiuser "$@"
