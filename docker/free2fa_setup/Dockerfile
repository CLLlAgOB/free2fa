FROM alpine:latest

RUN apk --no-cache add bash curl openssl

WORKDIR /certs

COPY --chmod=0755 generate-certs.sh ./generate-certs.sh

ENTRYPOINT ["./generate-certs.sh"]
