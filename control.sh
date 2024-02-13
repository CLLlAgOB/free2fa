#!/bin/bash

ROOT_DIR="/etc/freeradius/3.0/"
CONFIG_FILE_CLIENT="${ROOT_DIR}clients.conf"
CONFIG_FILE_SITE="${ROOT_DIR}sites-available/"
CONFIG_FILE_SITE_ENABLE="${ROOT_DIR}sites-enabled/"
CONFIG_FILE_EXEC="${ROOT_DIR}mods-available/exec"
# Function for displaying a list of configurations and selecting an action for a specific configuration
select_config() {
    configs=($(ls ${CONFIG_FILE_SITE}2fa_*))
    echo "List of available 2FA configurations:"
    for i in "${!configs[@]}"; do
        config_name=$(basename "${configs[$i]}")
        if [ -L "${CONFIG_FILE_SITE_ENABLE}${config_name}" ]; then
            echo "$((i+1)). $config_name - on"
        else
            echo "$((i+1)). $config_name - off"
        fi
    done

    read -p "Enter the configuration number to control or 'q' to exit: " choice
    if [[ $choice =~ ^[Qq]$ ]]; then
        return
    elif [[ $choice =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#configs[@]}" ]; then
        config_action "${configs[$((choice-1))]}"
    else
        echo "Incorrect selection. Please enter the correct number."
    fi
}

# Function to perform an action on the selected configuration
config_action() {
    confign=$1
    config_name=$(basename "$confign")
    echo "Configuration selected: $config_name"
    echo "Available actions:"
    echo "1. Enable configuration"
    echo "2. Turn off configuration"
    echo "3. Delete configuration"
    echo "4. Back to list of configurations"
    echo "5. Show configuration"
    
    read -p "Select an action: " action
    case $action in
        1)
            if [ ! -L "${CONFIG_FILE_SITE_ENABLE}${config_name}" ]; then
                ln -s "${CONFIG_FILE_SITE}${config_name}" "${CONFIG_FILE_SITE_ENABLE}" && echo "Configuration ${config_name} on."
            else
                echo "Configuration is already enabled."
            fi
            ;;
        2)
            if [ -L "${CONFIG_FILE_SITE_ENABLE}${config_name}" ]; then
                rm "${CONFIG_FILE_SITE_ENABLE}${config_name}" && echo "Configuration ${config_name} off."
            else
                echo "Configuration is not enabled."
            fi
            ;;
        3)
            if [ -L "${CONFIG_FILE_SITE_ENABLE}${config_name}" ]; then
                rm "${CONFIG_FILE_SITE_ENABLE}${config_name}"
            fi
            rm "${CONFIG_FILE_SITE}${config_name}" && echo "Configuration ${config_name} deleted."
            # Prepare a temporary file for the modified configuration
            temp_file=$(mktemp)
            
            # Delete the client section, saving the changes to a temporary file
            awk -v client="$config_name" '
                BEGIN {print_client=1}
                $0 ~ "client " client " {" {print_client=0}
                print_client {print}
                $0 ~ "}" {print_client=1}
            ' "$CONFIG_FILE_CLIENT" > "$temp_file"

            # Move the modified configuration back to the main file
            mv "$temp_file" "$CONFIG_FILE_CLIENT"
            echo "Client Configuration $config_name removed from $CONFIG_FILE_CLIENT"
                        # Prepare a temporary file for the modified configuration
            temp_file=$(mktemp)
            
            # Delete the exec section, saving the changes to a temporary file
            awk -v config="exec_$config_name" '
            BEGIN { print_config = 1; }
            $0 ~ config " {" { print_config = 0; }
            $0 ~ "^}[[:space:]]*$" && !print_config {
                print_config = 1;
                next;
            }
            print_config { print; } 
            ' "$CONFIG_FILE_EXEC" > "$temp_file"

            # Move the modified configuration back to the main file
            mv "$temp_file" "$CONFIG_FILE_EXEC"
            chmod -R 640 "$CONFIG_FILE_EXEC" "$CONFIG_FILE_CLIENT"
            chown -R freerad:freerad "$CONFIG_FILE_EXEC" "$CONFIG_FILE_CLIENT"
            echo "Exec Configuration $config_name removed from $CONFIG_FILE_CLIENT"
            ;;
        4) ;;
        5)
            echo "Showing the configuration for $config_name:"
            echo "Site Configuration:"
            cat "${CONFIG_FILE_SITE}${config_name}"
            echo "Client configuration (if applicable):"
            grep -A 20 "client ${config_name} {" "$CONFIG_FILE_CLIENT" | grep -m 1 -B 20 '}'
            echo "Exec configuration (if applicable):"
            grep -A 20 "exec_${config_name} {" "$CONFIG_FILE_EXEC" | grep -m 1 -B 20 '}'
            ;;
        *)
            echo "Incorrect selection. Please select the correct action."
            ;;
    esac
}

# Function for adding a new configuration
add_config() {
    read -p "Enter a base name for the new configuration: " config_name
    full_config_name="2fa_$config_name"
    config_file="/etc/sssd/sssd.conf"
    krb5_realm_cleaned=$(awk -F' = ' '/^krb5_realm/ {split($2,a,"."); print tolower(a[1])}' $config_file)
    use_fully_qualified_names=$(awk -F' = ' '/^use_fully_qualified_names/ {print $2}' $config_file)
    read -p "Enter the base port for the new configuration: " config_port
    read -p "Enter the IP address of the client: " ip
    read -p "Enter the secret for the client: " secret
    if [[ $use_fully_qualified_names == "True" ]]; then
        read -p "Enter the groups that are allowed access in the format groupname@domain.local,group2@domain.local: " groups
    else
        read -p "Enter the groups that are allowed access in the format groupname,group: " groups
    fi
    # Find and output the value for the use_fully_qualified_names key
    
    
    # Creating a temporary file
    TEMP_FILE=$(mktemp)

    # Write the SITE config settings to a temporary file
    cat <<'EOF' >"$TEMP_FILE"
server __default__ {
    listen {
        type = auth
        ipaddr = *
        port = __port__
        limit {
            max_connections = 100
            lifetime = 0
            idle_timeout = 60
        }
    }
    authorize {
        if (&User-Name =~ /(.+)@([^\.]+)/) {
            update request {
                Tmp-String-0 := "%{tolower:%{1}}"
                Tmp-String-1 := "%{tolower:%{2}}"
                User-Name := "%{Tmp-String-1}\\\\%{Tmp-String-0}"
           }
        }
        elsif (&User-Name =~ /^([^.]+)\.([^\\]+)\\(.+)$/) {
            update request {
                Tmp-String-0 := "%{tolower:%{1}}"
                Tmp-String-1 := "%{tolower:%{3}}"
                User-Name := "%{Tmp-String-0}\\\\%{Tmp-String-1}"
            }
        }
        elsif (&User-Name =~ /^[A-Za-z0-9\.\-_]+$/) {
            if ("__use_fully_qualified_names__" == "False") {
                update request {
                    User-Name := "__domain__\\\\%{tolower:%{User-Name}}"
                }
            }
        }
        elsif (&User-Name =~ /^[A-Za-z\.]+\\\\[A-Za-z]+$/) {
            update request {
                User-Name := "%{tolower:%{User-Name}}"
            }
        }
        if (!&User-Password) {
            update control {
                Auth-Type := Reject
            }
        }
        else {
            __check_membership__
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


    sed "s/__default__/$full_config_name/g" "$TEMP_FILE" > "${CONFIG_FILE_SITE}${full_config_name}"
    sed -i "s/__port__/$config_port/g" "${CONFIG_FILE_SITE}${full_config_name}"
    sed -i "s/__check_membership__/exec_$full_config_name/g" "${CONFIG_FILE_SITE}${full_config_name}"
    sed -i "s/__use_fully_qualified_names__/$use_fully_qualified_names/g" "${CONFIG_FILE_SITE}${full_config_name}"
    sed -i "s/__domain__/$krb5_realm_cleaned/g" "${CONFIG_FILE_SITE}${full_config_name}"

        # Client Configuration Template
    template="client __name__ {
    ipaddr = __ip__
    secret = __secret__
}"

    # Replacing placeholders in a template
    config="${template/__name__/$full_config_name}"
    config="${config/__ip__/$ip}"
    config="${config/__secret__/$secret}"

    # Adding a new configuration to the end of the file
    {
        echo "$config"
    } >> "$CONFIG_FILE_CLIENT"

    config=""

            # Client Configuration Template
    template='exec __name__ {
    wait = yes
    program = "/etc/freeradius/3.0/scripts/check_group_membership.sh %{User-Name} __groups__"
    input_pairs = request
    output_pairs = reply
    shell_escape = yes
}'

    # Replacing placeholders in a template
    config="${template/__name__/exec_$full_config_name}"
    config="${config/__groups__/$groups}"

    # Adding a new configuration to the end of the file
    {
        echo "$config"
    } >> "$CONFIG_FILE_EXEC"


    chmod -R 640 "$CONFIG_FILE_EXEC" "$CONFIG_FILE_CLIENT"
    chown -R freerad:freerad "$CONFIG_FILE_EXEC" "$CONFIG_FILE_CLIENT"
    ln -s "${CONFIG_FILE_SITE}${full_config_name}" "${CONFIG_FILE_SITE_ENABLE}" && echo "Configuration ${3} enabled."
    echo "The new client configuration has been added to $CONFIG_FILE to apply the config, restart freeradius"
}

# Main menu
while true; do
    echo "Select an action:"
    echo "1. Configuration management"
    echo "2. Add a new configuration"
    echo "3. Exit"
    read -p "Your choice: " choice

    case $choice in
        1) select_config ;;
        2) add_config ;;
        3) break ;;
        *) echo "Wrong choice. Please enter a number between 1 and 3." ;;
    esac
done
