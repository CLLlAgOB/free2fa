#!/usr/bin/env sh
set -e

# Preparation of rights
chown -R apiuser:apiuser /app/certs /opt/db
chmod 750 /opt/db

# Launching the application from apiuser
exec gosu apiuser python /app/adminapi.py
