FROM alpine

RUN apk --no-cache add openssl curl bash

WORKDIR /certs

COPY generate-certs.sh ./generate-certs.sh
RUN chmod +x ./generate-certs.sh


ENTRYPOINT ["./generate-certs.sh"]
