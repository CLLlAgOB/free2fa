#!/bin/sh
# change permission
chown -R apiuser:apiuser /app/certs /opt/db;
update-ca-certificates;


# Starting the container's main command
exec su -s /bin/sh apiuser -c "$*"