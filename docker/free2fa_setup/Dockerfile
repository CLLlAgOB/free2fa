FROM alpine:3.19.1

RUN apk --no-cache add openssl=3.1.4-r5 curl=8.5.0-r0 bash=5.2.21-r0

WORKDIR /certs

COPY generate-certs.sh ./generate-certs.sh
RUN chmod +x ./generate-certs.sh


ENTRYPOINT ["./generate-certs.sh"]
