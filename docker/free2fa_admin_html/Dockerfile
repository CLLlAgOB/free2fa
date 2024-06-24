FROM nginx

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends apache2-utils \
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
