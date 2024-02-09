#!/bin/bash

# Create a directory to store certificates for Nginx
mkdir -p /usr/share/nginx/html/certs

# Copy the CA certificate to the Nginx certs directory
cp -f /usr/local/share/ca-certificates/ca.crt /usr/share/nginx/html/certs/ca.crt

# Start Nginx in the foreground
nginx -g 'daemon off;'
