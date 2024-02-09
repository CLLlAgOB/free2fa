FROM nginx:1.24

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends apache2-utils=2.4.56-1~deb11u2 \
    && apt-get clean \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/* 
    
COPY entrypoint.sh ./

RUN chmod +x ./entrypoint.sh

COPY ./files/ /usr/share/nginx/html/

COPY ./nginx/nginx.conf /etc/nginx/nginx.conf

EXPOSE 443

RUN chmod +x ./entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
