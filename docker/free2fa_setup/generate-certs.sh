#!/bin/bash

# generate-certs.sh
# Copyright (C) 2024 Voloskov Aleksandr Nikolaevich

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Create directories for CA root certificate
mkdir -p /certs/rootca
mkdir -p /certs/rootpca

# CA root certificate parameters
CA_KEY="/certs/rootpca/ca.key" # Path for the private key
CA_CERT="/certs/rootca/ca.crt" # Path for the public key (certificate)
CA_SUBJECT="/CN=free2fa"
CA_EXPIRY_DAYS=${CA_EXPIRY_DAYS:-5475} # Default to 15 years if not set

# Function for logging
log() {
    # Date and time format: YYYYY-MM-DD HH:MM:SS
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "$timestamp - free2fa_setup - $1 - $2"
}

# Check certificate expiry (returns 0 if the certificate is valid for more than 30 days)
check_cert_expiry() {
    CERT=$1
    log "INFO" "Checking expiry for certificate: $CERT"

    if [ -f "$CERT" ]; then
        EXPIRY_DATE=$(openssl x509 -enddate -noout -in "$CERT" | cut -d= -f2)
        # Convert the expiry date to a format acceptable by the date command
        FORMATTED_EXPIRY_DATE=$(date -d "${EXPIRY_DATE// GMT/}" +%s 2>/dev/null)

        if [ $? -ne 0 ]; then
            log "INFO" "Error processing expiry date: $EXPIRY_DATE"
            return 1
        fi

        CURRENT_SECONDS=$(date +%s)
        DIFF_SECONDS=$((FORMATTED_EXPIRY_DATE - CURRENT_SECONDS))
        DAYS_LEFT=$((DIFF_SECONDS / 86400))
        log "INFO" "Days until expiry: $DAYS_LEFT"

        if [ $DAYS_LEFT -gt 30 ]; then
            log "INFO" "Certificate is valid for more than 30 days."
            return 0
        else
            log "INFO" "Certificate is valid for less than 30 days."
            return 1
        fi
    else
        log "INFO" "Certificate not found: $CERT"
        return 1
    fi
}

# Function to generate certificates for microservices
generate_service_cert() {
    SERVICE=$1
    SERVICE_EXPIRY_DAYS=${2:-365} # Default to 1 year if not set
    SERVICE_DIR="/certs/${SERVICE}"
    mkdir -p "$SERVICE_DIR"
    SERVICE_KEY="${SERVICE_DIR}/${SERVICE}.key"
    SERVICE_CSR="${SERVICE_DIR}/${SERVICE}.csr"
    SERVICE_CERT="${SERVICE_DIR}/${SERVICE}.crt"
    SERVICE_CONFIG="${SERVICE_DIR}/${SERVICE}.cnf"

    # Create a config for the certificate with SAN (Subject Alternative Name)
    echo "[req]" >"$SERVICE_CONFIG"
    echo "distinguished_name = req_distinguished_name" >>"$SERVICE_CONFIG"
    echo "req_extensions = v3_req" >>"$SERVICE_CONFIG"
    echo "prompt = no" >>"$SERVICE_CONFIG"
    echo "" >>"$SERVICE_CONFIG"
    echo "[req_distinguished_name]" >>"$SERVICE_CONFIG"
    echo "CN = $SERVICE" >>"$SERVICE_CONFIG"
    echo "" >>"$SERVICE_CONFIG"
    echo "[v3_req]" >>"$SERVICE_CONFIG"
    echo "keyUsage = digitalSignature, keyEncipherment, keyAgreement" >>"$SERVICE_CONFIG"
    echo "extendedKeyUsage = serverAuth, clientAuth" >>"$SERVICE_CONFIG"
    echo "subjectAltName = @alt_names" >>"$SERVICE_CONFIG"
    echo "" >>"$SERVICE_CONFIG"
    echo "[alt_names]" >>"$SERVICE_CONFIG"
    echo "DNS.1 = $SERVICE" >>"$SERVICE_CONFIG"
    if [ ! -z "$ADDITIONAL_DNS_NAME_FOR_ADMIN_HTML" ]; then
        echo "DNS.2 = $ADDITIONAL_DNS_NAME_FOR_ADMIN_HTML" >>"$SERVICE_CONFIG"
    fi

    if check_cert_expiry "$SERVICE_CERT"; then
        log "INFO" "Certificate for $SERVICE is valid for more than 30 days and does not require renewal."
    else
        log "INFO" "Generating/updating certificate for $SERVICE."
        # Generate a key
        openssl genrsa -out "$SERVICE_KEY" 2048
        # Generate a CSR using the configuration
        openssl req -new -key "$SERVICE_KEY" -out "$SERVICE_CSR" -config "$SERVICE_CONFIG"
        # Sign the certificate using the CA root
        openssl x509 -req -in "$SERVICE_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$SERVICE_CERT" -days "$SERVICE_EXPIRY_DAYS" -sha256 -extfile "$SERVICE_CONFIG" -extensions v3_req
    fi
}

# Generate/update the CA root certificate if it does not exist or is expired
if ! check_cert_expiry $CA_CERT; then
    log "INFO" "Generating/updating the CA root certificate."
    openssl genrsa -out "$CA_KEY" 4096
    openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days "$CA_EXPIRY_DAYS" -out "$CA_CERT" -subj "$CA_SUBJECT"
    # Convert the CA root public certificate to DER format for Windows
    openssl x509 -inform PEM -in $CA_CERT -outform DER -out /certs/rootca/ca.der
fi

# Generate/update certificates for each microservice
generate_service_cert "free2fa_admin_html" "$CA_EXPIRY_DAYS" "$ADDITIONAL_DNS_NAME_FOR_ADMIN_HTML"
ADDITIONAL_DNS_NAME_FOR_ADMIN_HTML="localhost"
generate_service_cert "free2fa_api" "$CA_EXPIRY_DAYS" "$ADDITIONAL_DNS_NAME_FOR_ADMIN_HTML"
generate_service_cert "free2fa_admin_api" "$CA_EXPIRY_DAYS"

log "INFO" "Waiting for admin api availability"
until curl -s --cacert /certs/rootca/ca.crt -o /dev/null -w '%{http_code}' https://free2fa_admin_api:8000/health | grep -q "200"; do
    sleep 5
done

log "INFO" "All done! Quit."
