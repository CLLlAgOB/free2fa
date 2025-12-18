FROM nginx:1-alpine

RUN set -eux; \
    apk add --no-cache apache2-utils ca-certificates; \
    update-ca-certificates

COPY ./nginx/nginx.conf /etc/nginx/nginx.conf
COPY ./files/ /usr/share/nginx/html/

COPY --chmod=0755 entrypoint.sh /usr/local/bin/custom-entrypoint.sh

ENV SRC_CA=/usr/local/share/ca-certificates/ca.crt \
    NGINX_CERT_DIR=/usr/share/nginx/html/certs

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- http://localhost/ >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/custom-entrypoint.sh"]
