#!/bin/sh
set -Eeuo pipefail

# Variables with defaults
: "${SRC_CA:=/usr/local/share/ca-certificates/ca.crt}"
: "${NGINX_CERT_DIR:=/usr/share/nginx/html/certs}"

# Create a directory for certificates if it does not exist
mkdir -p "${NGINX_CERT_DIR}"

# Copy CA if the file exists and is not empty
if [ -s "${SRC_CA}" ]; then
  # install -D carefully creates directories and sets permissions
  install -m 0644 -D "${SRC_CA}" "${NGINX_CERT_DIR}/ca.crt"
  echo "CA copied to ${NGINX_CERT_DIR}/ca.crt"
else
  echo "WARN: CA not found or empty at ${SRC_CA}" >&2
fi

# Checking the Nginx configuration before startup
nginx -t

# Start Nginx in the foreground (exec — so that signals are sent to nginx)
exec nginx -g 'daemon off;'
