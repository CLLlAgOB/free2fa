#!/bin/sh
# change permission
chown -R apiuser:apiuser /app/certs/ /opt/db/
chmod 770 -R /opt/db/

# Starting the container's main command
su -s /bin/bash apiuser -c "python adminapi.py"
