#!/bin/bash

# install.ssh
# Copyright (C) 2024 Voloskov Aleksandr Nikolaevich

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version..

# Checking to run as root user
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as the root user."
    exit 1
fi

# Function for checking and setting the whiptail
check_and_install_whiptail() {
    if ! command -v whiptail &>/dev/null; then
        echo "whiptail not found. Attempting to install..."
        apt-get update && apt-get install -y whiptail
        if [ $? -ne 0 ]; then
            echo "Failed to install whiptail. Please install manually and run the script again."
            exit 1
        fi
    else
        echo "whiptail is already installed."
    fi
}

# Checking and installing whiptail
check_and_install_whiptail

# Checking the Ubuntu version
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    if [[ "$ID" == "ubuntu" && "$(echo $VERSION_ID | cut -d. -f1)" -ge 22 ]]; then
        echo "You are using Ubuntu $VERSION_ID. Continue executing the script."
    else
        echo "Warning: Your Linux version ($PRETTY_NAME) is different from the one on which the script was tested."
        echo "Some settings may not work as expected."
        if ! whiptail --yesno "Would you like to continue?" 8 78 --title "Version warning"; then
            echo "Script execution is canceled by the user."
            exit 1
        fi
    fi
else
    echo "The operating system version could not be determined."
    exit 1
fi

check_if_cancel() {
    # Check if the user clicked Cancel
    if [ $? -ne 0 ]; then
        echo "The user canceled the input."
        exit 1
    fi
}

# Requesting a domain name
DOMAIN=$(whiptail --inputbox "Enter the domain name (for example, domain.local). Enter in lower case:" 8 78 --title "Domain Name" 3>&1 1>&2 2>&3)

check_if_cancel

# Convert the domain name to uppercase for use in configurations where you want to
DOMAIN_UPPERCASE=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')

# Function to check and install Docker
check_and_install_docker() {
    if ! command -v docker &>/dev/null; then
        echo "Docker not found."
        if whiptail --yesno "Do you want to install Docker?" 8 78 --title "Installing Docker"; then
            echo "Installing Docker..."
            curl -fsSL https://get.docker.com -o get-docker.sh
            sh get-docker.sh
            systemctl enable docker
            systemctl start docker
            echo "Docker has been installed and started."
        else
            echo "Docker installation is skipped."
        fi
    else
        echo "Docker is already installed, skip the installation."
    fi
}

# Function to check and install Docker Compose
check_and_install_docker_compose() {
    if ! command -v docker-compose &>/dev/null; then
        echo "Docker Compose was not found."
        if whiptail --yesno "Do you want to install Docker Compose?" 8 78 --title "Installing Docker Compose"; then
            echo "Installing Docker Compose..."
            if [[ ":$PATH:" != *":/usr/local/bin:"* ]]; then
                echo "Adding /usr/local/bin to your PATH"
                export PATH=$PATH:/usr/local/bin
                echo "export PATH=$PATH:/usr/local/bin" >>~/.bashrc
            fi
            curl -L "https://github.com/docker/compose/releases/download/v2.5.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
            chmod +x /usr/local/bin/docker-compose
            echo "Docker Compose has been installed."
        else
            echo "The installation of Docker Compose is skipped."
        fi
    else
        echo "Docker Compose is already installed, skip the installation."
    fi
}

# Check and install Docker without asking first
check_and_install_docker

# Check and install Docker Compose without asking first
check_and_install_docker_compose

# Creating a temporary file
TEMP_FILE=$(mktemp)

# Request data from the user
DOMAIN_LOCAL=$DOMAIN_UPPERCASE
KERBEROS_SERVER=$(whiptail --inputbox "Enter the Kerberos server(domain controller server of more  
than one domain controller then with a space (dc01 dc02 dc03 ...))." 8 78 --title "Configuring Kerberos" 3>&1 1>&2 2>&3)
check_if_cancel

ADMIN_SERVER=$(whiptail --inputbox "Enter the Kerberos administrative server(Often, this is also your
Active Directory domain controller (dc01))" 8 78 --title "Configuring Kerberos" 3>&1 1>&2 2>&3)

check_if_cancel

# Writing Kerberos settings to a temporary file
cat <<EOF >$TEMP_FILE
krb5-config krb5-config/default_realm string $DOMAIN_LOCAL
krb5-config krb5-config/kerberos_servers string $KERBEROS_SERVER
krb5-config krb5-config/admin_server string $ADMIN_SERVER
krb5-config krb5-config/dns_for_default boolean true
krb5-config krb5-config/add_servers boolean false
EOF

# Applying the settings from the temporary file
debconf-set-selections $TEMP_FILE

# Deleting the temporary file
rm $TEMP_FILE

# installation of required packages.
apt-get update
NEEDRESTART_MODE=a apt-get install -y --no-install-recommends ca-certificates curl sssd sssd-tools libnss-sss libpam-sss adcli realmd krb5-user freeradius freeradius-rest freeradius-utils

# Requesting a username
USER=$(whiptail --inputbox "Enter a user name to enter the server into the domain" 8 78 --title "User Name" 3>&1 1>&2 2>&3)

check_if_cancel

# Logging in to the domain
echo "Logging into the $DOMAIN domain using the $USER user..."
realm join $DOMAIN --user=$USER

echo "The operation is done."

# Ask the user whether to allow login by short names
if whiptail --yesno "Allow login by short names without specifying a domain?" 20 60 --defaultno; then
    USE_FULLY_QUALIFIED_NAMES="False"
else
    USE_FULLY_QUALIFIED_NAMES="True"
fi

# Asking which groups are allowed to log in
ALLOW_GROUPS=$(whiptail --inputbox "Enter the groups allowed to authorize, separated by commas (e.g., vpn@domain.local, vpn2@domain.local)" 20 60 3>&1 1>&2 2>&3)

check_if_cancel

# Ask the user whether to ignore unavailable GPOs
if whiptail --yesno "Ignore unavailable GPOs (default yes)?" 20 60; then
    IGNORE_UNREADABLE="True"
else
    IGNORE_UNREADABLE="False"
fi

# Preparing to modify a file /etc/sssd/sssd.conf
SSSD_CONF="/etc/sssd/sssd.conf"

# Create a backup sssd.conf
cp "$SSSD_CONF" "${SSSD_CONF}.bak"

# Changing the use_fully_qualified_names settings
sed -i "s/^use_fully_qualified_names = .*/use_fully_qualified_names = $USE_FULLY_QUALIFIED_NAMES/" "$SSSD_CONF"

sed -i "s/^access_provider = .*/access_provider = simple/" "$SSSD_CONF"

# Add or update the simple_allow_groups setting
if grep -q "^simple_allow_groups" "$SSSD_CONF"; then
    sed -i "s/^simple_allow_groups = .*/simple_allow_groups = $ALLOW_GROUPS/" "$SSSD_CONF"
else
    echo "simple_allow_groups = $ALLOW_GROUPS" | tee -a "$SSSD_CONF"
fi

# Add or update the ad_gpo_ignore_unreadable setting
if grep -q "^ad_gpo_ignore_unreadable" "$SSSD_CONF"; then
    sed -i "s/^ad_gpo_ignore_unreadable = .*/ad_gpo_ignore_unreadable = $IGNORE_UNREADABLE/" "$SSSD_CONF"
else
    echo "ad_gpo_ignore_unreadable = $IGNORE_UNREADABLE" | tee -a "$SSSD_CONF"
fi

echo "The SSSD settings have been updated."

sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config
systemctl restart sshd
systemctl restart sssd

CONFIG_FILE_RADIUS="/etc/freeradius/3.0/radiusd.conf"
CONFIG_FILE_CLIENT="/etc/freeradius/3.0/clients.conf"
START_SERVICE="$PWD/start_service.sh"
STOP_SERVICE="$PWD/stop_service.sh"
FREE2FA_SERVICE="/etc/systemd/system/free2fa.service"
CONFIG_FILE_KRB5="/etc/krb5.conf"
CONFIG_FILE_REST="/etc/freeradius/3.0/mods-enabled/rest"
CONFIG_FILE_PAM="/etc/freeradius/3.0/mods-enabled/pam"
CONFIG_FILE_SITE="/etc/freeradius/3.0/sites-enabled/default"

# Creating a temporary file
TEMP_FILE=$(mktemp)

# Writing Kerberos settings to a temporary file
cat <<EOF >$TEMP_FILE
[libdefaults]
default_realm = $DOMAIN_UPPERCASE
dns_lookup_realm = false
dns_lookup_kdc = true

# The following krb5.conf variables are only for MIT Kerberos.
kdc_timesync = 1
ccache_type = 4
forwardable = true
proxiable = true

[realms]
        $DOMAIN_UPPERCASE = {
EOF

# Adding KDC servers
for server in $KERBEROS_SERVER; do
    echo "                kdc = $server" >> $TEMP_FILE
done

cat <<EOF >>$TEMP_FILE
                admin_server = $ADMIN_SERVER
                default_domain = $DOMAIN
        }

[domain_realm]
        .$DOMAIN = $DOMAIN_UPPERCASE
        $DOMAIN = $DOMAIN_UPPERCASE
EOF


cp $TEMP_FILE $CONFIG_FILE_KRB5

# Deleting the temporary file
rm $TEMP_FILE

# Function to generate a random key
generate_random_key() {
    tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w 32 | head -n 1
}

# Function to create a .env file using parameters collected via whiptail dialogs
create_env_file() {
    cat >.env <<EOF
CA_EXPIRY_DAYS=${CA_EXPIRY_DAYS}
FREE2FA_TELEGRAM_BOT_TOKEN=${FREE2FA_TELEGRAM_BOT_TOKEN}
FREE2FA_TELEGRAM_BOT_LANGUAGE=${FREE2FA_TELEGRAM_BOT_LANGUAGE}
FREE2FA_AUTO_REG_ENABLED=${FREE2FA_AUTO_REG_ENABLED}
FREE2FA_BYPASS_ENABLED=${FREE2FA_BYPASS_ENABLED}
RADIUS_CLIENT_SECRET=${RADIUS_CLIENT_SECRET}
FREE2FA_TIMEOUT=${FREE2FA_TIMEOUT}
RADIUS_START_SERVERS=${RADIUS_START_SERVERS}
RADIUS_MAX_SERVERS=${RADIUS_MAX_SERVERS}
RADIUS_MAX_SPARE_SERVERS=${RADIUS_MAX_SPARE_SERVERS}
RADIUS_MIN_SPARE_SERVERS=${RADIUS_MIN_SPARE_SERVERS}
ADMIN_SECRET_KEY=${ADMIN_SECRET_KEY:-$(generate_random_key)}
RESET_PASSWORD=${RESET_PASSWORD}
ALLOW_API_FAILURE_PASS=${ALLOW_API_FAILURE_PASS}
ADDITIONAL_DNS_NAME_FOR_ADMIN_HTML=${ADDITIONAL_DNS_NAME_FOR_ADMIN_HTML}
EOF
}

# Function to prompt for .env configuration using whiptail
prompt_env_configuration() {
    CA_EXPIRY_DAYS=$(whiptail --inputbox "Enter CA_EXPIRY_DAYS (default 365):" 8 78 365 --title "CA_EXPIRY_DAYS" 3>&1 1>&2 2>&3)
    check_if_cancel
    FREE2FA_TELEGRAM_BOT_TOKEN=$(whiptail --inputbox "Enter TELEGRAM_BOT_TOKEN (default your-key):" 8 78 your-key --title "FREE2FA_TELEGRAM_BOT_TOKEN" 3>&1 1>&2 2>&3)
    check_if_cancel
    FREE2FA_TELEGRAM_BOT_LANGUAGE=$(whiptail --inputbox "Enter TELEGRAM_BOT_LANGUAGE (default ru):" 8 78 ru --title "FREE2FA_TELEGRAM_BOT_LANGUAGE" 3>&1 1>&2 2>&3)
    check_if_cancel
    FREE2FA_AUTO_REG_ENABLED=$(whiptail --inputbox "Enter AUTO_REG_ENABLED (default true):" 8 78 true --title "FREE2FA_AUTO_REG_ENABLED" 3>&1 1>&2 2>&3)
    check_if_cancel
    FREE2FA_BYPASS_ENABLED=$(whiptail --inputbox "Enter BYPASS_ENABLED (default true):" 8 78 true --title "FREE2FA_BYPASS_ENABLED" 3>&1 1>&2 2>&3)
    check_if_cancel
    RADIUS_CLIENT_SECRET=$(whiptail --inputbox "Enter RADIUS_CLIENT_SECRET (default secret123):" 8 78 secret123 --title "RADIUS_CLIENT_SECRET" 3>&1 1>&2 2>&3)
    check_if_cancel
    RADIUS_CLIENT_IP=$(whiptail --inputbox "Enter RADIUS_CLIENT_IP (default 0.0.0.0):" 8 78 "0.0.0.0" --title "RADIUS_CLIENT_IP" 3>&1 1>&2 2>&3)
    check_if_cancel
    FREE2FA_TIMEOUT=$(whiptail --inputbox "Enter TIMEOUT FOR CONFURMATION (default 20):" 8 78 20 --title "FREE2FA_TIMEOUT" 3>&1 1>&2 2>&3)
    check_if_cancel
    RADIUS_START_SERVERS=$(whiptail --inputbox "Enter RADIUS_START_SERVERS (default 5):" 8 78 5 --title "RADIUS_START_SERVERS" 3>&1 1>&2 2>&3)
    check_if_cancel
    RADIUS_MAX_SERVERS=$(whiptail --inputbox "Enter RADIUS_MAX_SERVERS (default 20):" 8 78 20 --title "RADIUS_MAX_SERVERS" 3>&1 1>&2 2>&3)
    check_if_cancel
    RADIUS_MAX_SPARE_SERVERS=$(whiptail --inputbox "Enter RADIUS_MAX_SPARE_SERVERS (default 10):" 8 78 10 --title "RADIUS_MAX_SPARE_SERVERS" 3>&1 1>&2 2>&3)
    check_if_cancel
    RADIUS_MIN_SPARE_SERVERS=$(whiptail --inputbox "Enter RADIUS_MIN_SPARE_SERVERS (default 5):" 8 78 5 --title "RADIUS_MIN_SPARE_SERVERS" 3>&1 1>&2 2>&3)
    check_if_cancel
    ADMIN_SECRET_KEY=$(whiptail --inputbox "Enter ADMIN_SECRET_KEY (auto-generated if empty):" 8 78 "" --title "ADMIN_SECRET_KEY" 3>&1 1>&2 2>&3)
    check_if_cancel
    RESET_PASSWORD=$(whiptail --inputbox "Enter RESET_PASSWORD (default false):" 8 78 false --title "RESET_PASSWORD" 3>&1 1>&2 2>&3)
    check_if_cancel
    ALLOW_API_FAILURE_PASS=$(whiptail --inputbox "Enter ALLOW_API_FAILURE_PASS (default false):" 8 78 false --title "ALLOW_API_FAILURE_PASS" 3>&1 1>&2 2>&3)
    check_if_cancel
    ADDITIONAL_DNS_NAME_FOR_ADMIN_HTML=$(whiptail --inputbox "Enter ADDITIONAL_DNS_NAME_FOR_ADMIN_HTML (default free2fa):" 8 78 free2fa --title "ADDITIONAL_DNS_NAME_FOR_ADMIN_HTML" 3>&1 1>&2 2>&3)
    check_if_cancel
    create_env_file
}

# Download docker-compose.yml
download_docker_compose_yml() {
    curl -L "https://raw.githubusercontent.com/CLLlAgOB/free2fa/main/docker-compouse/docker-compose.yml" -o docker-compose.yml
    echo "docker-compose.yml downloaded."
}

prompt_env_configuration
download_docker_compose_yml

# Default values
CLIENT_SECRET=${RADIUS_CLIENT_SECRET:-"test123"}
RADIUS_CLIENT_TIMEOUT=${RADIUS_CLIENT_TIMEOUT:-10}
RADIUS_CLIENT_IP=${RADIUS_CLIENT_IP:-"0.0.0.0"}
RADIUS_START_SERVERS=${RADIUS_START_SERVERS:-5}
RADIUS_MAX_SERVERS=${RADIUS_MAX_SERVERS:-32}
RADIUS_MAX_SPARE_SERVERS=${RADIUS_MAX_SPARE_SERVERS:-10}
RADIUS_MIN_SPARE_SERVERS=${RADIUS_MIN_SPARE_SERVERS:-3}

key_file="/etc/freeradius/3.0/key"

# Check if the file exists
if [ ! -f "$key_file" ]; then
    # Generate 32 random characters
    random_key=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32)

    # Write the key to a file
    echo "$random_key" | tee "$key_file" >/dev/null

    # Set read-only permissions for the root owner and the freerad group
    chown root:freerad "$key_file"
    chmod 440 "$key_file"
else
    # Read value from file
    random_key=$(cat "$key_file")
fi

# Creating a temporary file
TEMP_FILE=$(mktemp)

# Записываем настройки Kerberos во временный файл
cat <<'EOF' >$TEMP_FILE
server default {
    listen {
        type = auth
        ipaddr = *
        port = 1812
        limit {
            max_connections = 100
            lifetime = 0
            idle_timeout = 60
        }
    }

    authorize {
        if (&User-Name =~ /(.+)@([^\.]+)\./) {
             update request {
                Tmp-String-0 := "%{tolower:%{1}}"
                Tmp-String-1 := "%{tolower:%{2}}"
                User-Name := "%{Tmp-String-1}\\\\%{Tmp-String-0}"
           }
        }
        if (!&User-Password) {
            update control {
                Auth-Type := Reject
            }
        }
        else {
            update control {
                Auth-Type := PAM
            }
        }
    }

    authenticate {
        Auth-Type PAM {
            pam
            if (!ok) {
                reject
            }
            if (ok) {
                rest
                update control {
                    Auth-Type := REST
                }
            }
        }
        Auth-Type REST {
            rest {
                updated = 1
            }
            if (updated) {
                ok
            }
        }
    }
}
EOF

cp $TEMP_FILE $CONFIG_FILE_SITE

# Deleting the temporary file
rm $TEMP_FILE

# Creating a temporary file
TEMP_FILE=$(mktemp)

# Writing Kerberos settings to a temporary file
cat <<'EOF' >$TEMP_FILE
rest {
    tls {
        check_cert = yes
        check_cert_cn = yes
    }

    connect_uri = "https://localhost:5000"
    connect_timeout = $((RADIUS_CLIENT_TIMEOUT + 3))

    authenticate {
        uri = "${..connect_uri}/authenticate"
        method = 'post'
        body = 'json'
        data = '{ "user_name": "%{User-Name}", "client_key": "FREE2FA_API_KEY" }'
        tls = ${..tls}
        timeout = 3
    }

    pool {
        start = ${thread[pool].start_servers}
        min = ${thread[pool].min_spare_servers}
        max = ${thread[pool].max_servers}
        spare = ${thread[pool].max_spare_servers}
        uses = 0
        lifetime = 0
        idle_timeout = 120
    }
}
EOF

cp $TEMP_FILE $CONFIG_FILE_REST

# Deleting the temporary file
rm $TEMP_FILE

# Creating a temporary file
TEMP_FILE=$(mktemp)

# Writing Kerberos settings to a temporary file
cat <<EOF >$TEMP_FILE
pam {
        pam_auth = passwd
}
EOF

cp $TEMP_FILE $CONFIG_FILE_PAM

# Deleting the temporary file
rm $TEMP_FILE

# Creating a temporary file
TEMP_FILE=$(mktemp)

# Write the settings to a temporary file
cat <<EOF >$TEMP_FILE
client rdg {
  ipaddr = $RADIUS_CLIENT_IP
  secret = $CLIENT_SECRET
}
EOF

cp $TEMP_FILE $CONFIG_FILE_CLIENT

# Deleting the temporary file
rm $TEMP_FILE

# Creating a temporary file
TEMP_FILE=$(mktemp)

CURRENT_DIR=$PWD
CURRENT_FOLDER=$(basename "$PWD")
PATH_TO_CA_CERT="/var/lib/docker/volumes/${CURRENT_FOLDER}_free2fa_ca_certs/_data/ca.crt"


# start service script
cat <<EOF >$TEMP_FILE
#!/bin/bash

#  Go to the directory with docker-compose.yml
cd "$CURRENT_DIR"

# Starting Docker Compose
docker-compose up -d

# Checking service availability
while true; do
    if [ -f "$PATH_TO_CA_CERT" ]; then
        echo "The $PATH_TO_CA_CERT certificate has been created."
        break
    else
        echo "Waiting for $PATH_TO_CA_CERT certificate to be created..."
    fi
    sleep 2
done
cp $PATH_TO_CA_CERT /usr/local/share/ca-certificates/
if update-ca-certificates; then
    echo "The certificate has been added to trusted."
else
    echo "An error occurred while adding a certificate."
    exit 1
fi

until curl -s --cacert $PATH_TO_CA_CERT -o /dev/null -w '%{http_code}' https://localhost:5000/health | grep -q "200"; do
    echo "Waiting for the launch of Docker service..."
    sleep 5
done



echo "Docker Compose has been successfully started."

# Starting FreeRADIUS
service freeradius start
echo "FreeRADIUS has been successfully started."
EOF

cp $TEMP_FILE $START_SERVICE

chmod +x $START_SERVICE
# Deleting the temporary file
rm $TEMP_FILE

# Creating a temporary file
TEMP_FILE=$(mktemp)

# Write the stop services script to a temporary file.
cat <<EOF >$TEMP_FILE
#!/bin/bash

# Go to the directory with docker-compose.yml
cd "$CURRENT_DIR"

# Stopping Docker Compose
docker-compose stop

# Stopping FreeRADIUS
service freeradius stop

echo "The services have been successfully stopped."
EOF

cp $TEMP_FILE $STOP_SERVICE

chmod +x $STOP_SERVICE
# Deleting the temporary file
rm $TEMP_FILE

# Creating a temporary file
TEMP_FILE=$(mktemp)

# Write the start services script to a temporary file.
cat <<EOF >$TEMP_FILE
[Unit]
Description=Free2fa and FreeRADIUS
After=network.target docker.service
Wants=docker.service


[Service]
Type=oneshot
ExecStart=$CURRENT_DIR/start_service.sh
ExecStop=$CURRENT_DIR/stop_service.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

cp $TEMP_FILE $FREE2FA_SERVICE

# Deleting the temporary file
rm $TEMP_FILE
systemctl stop freeradius
systemctl disable freeradius
systemctl enable free2fa.service

# Updating configuration files
sed -i "/^rest {/,/^}/ s/connect_timeout = .*/connect_timeout = $((RADIUS_CLIENT_TIMEOUT + 3))/" "$CONFIG_FILE_REST"
sed -i "/^rest {/,/^}/ { /    authenticate {/,/    }/ s/timeout = .*/timeout = $((RADIUS_CLIENT_TIMEOUT + 3))/ }" "$CONFIG_FILE_REST"
sed -i "s/\"client_key\": \".*\"/\"client_key\": \"$random_key\"/" "$CONFIG_FILE_REST"
sed -i "s/start_servers = .*/start_servers = $RADIUS_START_SERVERS/" "$CONFIG_FILE_RADIUS"
sed -i "s/max_servers = .*/max_servers = $RADIUS_MAX_SERVERS/" "$CONFIG_FILE_RADIUS"
sed -i "s/max_spare_servers = .*/max_spare_servers = $RADIUS_MAX_SPARE_SERVERS/" "$CONFIG_FILE_RADIUS"
sed -i "s/min_spare_servers = .*/min_spare_servers = $RADIUS_MIN_SPARE_SERVERS/" "$CONFIG_FILE_RADIUS"
sed -i "s/destination = .*/destination = stdout/" "$CONFIG_FILE_RADIUS"

echo "Configuration updated."

# Setting access rights to configuration files
chmod 440 /etc/freeradius/3.0/mods-enabled/rest /etc/freeradius/3.0/mods-enabled/pam /etc/freeradius/3.0/sites-enabled/default
chown root:freerad /etc/freeradius/3.0/mods-enabled/rest /etc/freeradius/3.0/mods-enabled/pam /etc/freeradius/3.0/sites-enabled/default
if whiptail --yesno "Output the resulting configs to the console?" 10 60; then
    # If the user selected "Yes", output the contents of the configuration files
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    echo -e "\033[34mContent /etc/sssd/sssd.conf:\033[0m \n"
    cat /etc/sssd/sssd.conf
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    echo -e "\033[34mContent /etc/krb5.conf:\033[0m \n"
    cat /etc/krb5.conf
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    echo -e "\033[34mContent /etc/freeradius/3.0/radiusd.conf,\033[0m"
    echo -e "\033[34mOutput only the modified lines because the file is very large:\033[0m \n"
    grep -E "start_servers =|max_servers =|max_spare_servers =|min_spare_servers =" /etc/freeradius/3.0/radiusd.conf
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    echo -e "\033[34mContent /etc/freeradius/3.0/clients.conf:\033[0m \n"
    cat /etc/freeradius/3.0/clients.conf
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    echo -e "\033[34mContent /etc/freeradius/3.0/mods-enabled/rest:\033[0m \n"
    cat /etc/freeradius/3.0/mods-enabled/rest
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    echo -e "\033[34mContent /etc/freeradius/3.0/mods-enabled/pam:\033[0m\n"
    cat /etc/freeradius/3.0/mods-enabled/pam
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    echo -e "\033[34mContent /etc/freeradius/3.0/sites-enabled/default:\033[0m \n"
    cat /etc/freeradius/3.0/sites-enabled/default
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    read -n 1 -s -r -p "Press any key to continue..."
    echo "" # Для перевода строки после продолжения
else
    # If the user selects "No", simply terminate the script
    echo "The output of the configuration files is omitted."
fi

# Run Docker Compose and FreeRADIUS?
if whiptail --yesno "Do you want to run Docker Compose and the FreeRADIUS service?" 10 60 --title "Starting Docker Compose and FreeRADIUS"; then
    # Running Docker Compose
    echo "Running Docker Compose..."
    if docker-compose pull; then
        echo "The images have been downloaded"
    else
        echo "Failed to download the Docker images. Please check the configuration."
        exit 1
    fi
    # Starting the FreeRADIUS service
    echo "Starting the Free2fa service..."
    if service free2fa start; then
        echo "The Free2fa service starts up."
    else
        echo "Failed to start the FreeRADIUS service."
        exit 1
    fi
else
    echo "The launch of Docker Compose and the FreeRADIUS service has been canceled."
fi


# Prompt to start the build
# Display helpful information for managing free2fa and FreeRADIUS
echo -e "\033[34mTo manage the free2fa service, you can use the following commands:\033[0m\n\
- To stop the free2fa service, enter: \033[32mservice free2fa stop\033[0m\n\
- To start the free2fa service, enter: \033[32mservice free2fa start\033[0m\n\n\
To view the Docker logs follow to the installation directory, please use the command:\n\
\033[32mdocker-compose logs -f\033[0m\n\n\
For accessing the FreeRADIUS logs, execute the following command:\n\
\033[32mcat /var/log/freeradius/radius.log\033[0m\n\n\
or you can see all logs in one window use the command:\n\
\033[32mtail -f /var/log/freeradius/radius.log & docker-compose logs -f\n\n
\033[34mTo initiate FreeRADIUS in debug mode, ensure to stop the FreeRADIUS service first by executing:\n\
\033[32mservice freeradius stop\033[0m\n\
Then, to start FreeRADIUS in debug mode, enter:\n\
\033[32mfreeradius -Xx\033[0m\n"

