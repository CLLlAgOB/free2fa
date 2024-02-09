#!/bin/bash

# build.sh
# Copyright (C) 2024 Voloskov Aleksandr Nikolaevich

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Define component versions
api_version="latest"
admin_html_version="latest"
admin_api_version="latest"
setup_version="latest"

# Assemble and upload API
docker build -t clllagob/free2fa:api_$api_version ./free2fa_api
docker push clllagob/free2fa:api_$api_version

# Assemble and upload Admin HTML
docker build -t clllagob/free2fa:admin_html_$admin_html_version ./free2fa_admin_html
docker push clllagob/free2fa:admin_html_$admin_html_version

# Assemble and upload Admin API
docker build -t clllagob/free2fa:admin_api_$admin_api_version ./free2fa_admin_api
docker push clllagob/free2fa:admin_api_$admin_api_version

# Assemble and upload Setup
docker build -t clllagob/free2fa:setup_$setup_version ./free2fa_setup
docker push clllagob/free2fa:setup_$setup_version
