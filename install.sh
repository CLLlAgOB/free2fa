#!/bin/bash

# install.ssh
# Copyright (C) 2025 Voloskov Aleksandr Nikolaevich

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


# -----------------------------------------------------------------------------
# Logging helpers (keep whiptail stdout capturing safe: log to STDERR + file)
# -----------------------------------------------------------------------------
LOG_FILE=""

log() {
    local msg="$*"
    if [ -n "${LOG_FILE:-}" ]; then
        printf '%s %s
' "$(date '+%Y-%m-%d %H:%M:%S')" "$msg" | tee -a "$LOG_FILE" >&2
    else
        printf '%s %s
' "$(date '+%Y-%m-%d %H:%M:%S')" "$msg" >&2
    fi
}

warn() { log "WARN: $*"; }
die()  { log "ERROR: $*"; exit 1; }

init_run_log() {
    local install_dir="$1"
    local tag="$2"
    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    local bk_dir="${install_dir%/}/backups"
    mkdir -p "$bk_dir"
    LOG_FILE="${bk_dir}/free2fa_${tag}_${ts}.log"
    log "Log file: ${LOG_FILE}"
}

# -----------------------------------------------------------------------------
# PAM helpers (rlm_pam uses /etc/pam.d/<pam_auth>, default is radiusd)
#   Source: FreeRADIUS rlm_pam docs (pam_auth directive)
# -----------------------------------------------------------------------------
get_freeradius_pam_auth_name() {
    local f="/etc/freeradius/3.0/mods-available/pam"
    if [ ! -f "$f" ]; then
        echo "radiusd"
        return 0
    fi
    local v
    v="$(grep -E '^[[:space:]]*pam_auth[[:space:]]*=' "$f" | head -n 1 | sed -E 's/.*=[[:space:]]*"?([^"[:space:]]+)"?.*/check_if_cancel() {
    # Check if the user clicked Cancel
    if [ $? -ne 0 ]; then
        echo "The user canceled the input."
        exit 1
    fi
}

/' || true)"
    if [ -n "$v" ]; then
        echo "$v"
    else
        echo "radiusd"
    fi
}

set_freeradius_pam_auth_name() {
    local name="$1"
    local f="/etc/freeradius/3.0/mods-available/pam"
    [ -f "$f" ] || return 0

    if grep -qE '^[[:space:]]*pam_auth[[:space:]]*=' "$f"; then
        sed -i -E "s@^[[:space:]]*pam_auth[[:space:]]*=.*@    pam_auth = ${name}@g" "$f"
    else
        # Insert into pam { } block if possible, else append
        if grep -qE '^[[:space:]]*pam[[:space:]]*\{' "$f"; then
            sed -i -E "/^[[:space:]]*pam[[:space:]]*\{/a\    pam_auth = ${name}" "$f"
        else
            echo "pam_auth = ${name}" >> "$f"
        fi
    fi
}

ensure_pam_d_radiusd_prefer_sss() {
    local target="/etc/pam.d/radiusd"
    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    if [ -f "$target" ]; then
        cp -a "$target" "${target}.bak_${ts}"
        log "Backup PAM file: ${target}.bak_${ts}"
    fi

    # Goal: Try pam_sss first, then pam_unix as fallback (helps avoid pam_unix failure logs for domain users).
    # NOTE: PAM is security-sensitive; apply only if you really want AD/SSSD-first behaviour.
    cat > "$target" <<'EOF'
#%PAM-1.0
# Free2FA / FreeRADIUS PAM stack (SSSD first, then local UNIX)
# - Domain users authenticate via pam_sss
# - Local users can still authenticate via pam_unix if pam_sss returns "user unknown"

auth    sufficient  pam_sss.so forward_pass
auth    sufficient  pam_unix.so try_first_pass nullok
auth    required    pam_deny.so

account sufficient  pam_sss.so
account required    pam_unix.so
account required    pam_permit.so

session required    pam_permit.so
EOF

    chmod 644 "$target" || true
    log "Wrote PAM service file: $target"
}

# -----------------------------------------------------------------------------
# Restore helper
# -----------------------------------------------------------------------------
restore_free2fa_backup() {
    local install_dir="$1"
    local bk_dir="${install_dir%/}/backups"
    [ -d "$bk_dir" ] || die "Backups dir not found: $bk_dir"

    local archives
    archives="$(ls -1t "$bk_dir"/free2fa_backup_*.tar.gz 2>/dev/null || true)"
    if [ -z "$archives" ]; then
        die "No backup archives found in: $bk_dir"
    fi

    local menu=()
    local i=0
    while IFS= read -r f; do
        i=$((i+1))
        menu+=("$f" "$(basename "$f")")
        [ "$i" -ge 30 ] && break
    done <<< "$archives"

    local chosen
    chosen=$(whiptail --title "Free2FA Restore" --menu "Select backup archive to restore (will overwrite files):" 20 90 10 \
        "${menu[@]}" \
        3>&1 1>&2 2>&3)
    check_if_cancel

    if ! whiptail --yesno "Restore archive?

$chosen

This will overwrite system files under /etc, /opt, etc.
Continue?" 16 90 --title "Confirm restore"; then
        die "Restore canceled by user."
    fi

    init_run_log "$install_dir" "restore"
    log "Restoring archive: $chosen"

    # Extract relative paths to root
    tar -xzf "$chosen" -C /
    log "Restore complete."

    if whiptail --yesno "Restart free2fa / freeradius services now?" 10 78 --title "Restart after restore"; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload || true
            systemctl restart free2fa.service 2>/dev/null || service freeradius restart || true
        else
            service free2fa restart || service freeradius restart || true
        fi
        log "Restart complete."
    else
        warn "Restart skipped."
    fi

    whiptail --msgbox "Restore completed.
Log: ${LOG_FILE}
Archive: $chosen" 12 90 --title "Free2FA Restore"
}


# -----------------------------------------------------------------------------
# INSTALL / UPDATE MODE
#   If Free2FA looks already installed, the script can run in "update" mode.
#   Update mode:
#     - makes backup of Free2FA-related files
#     - ensures required packages are installed
#     - ensures FreeRADIUS cache modules (anti-bruteforce) exist + enabled
#     - updates site config to include cache logic if missing
#     - optionally updates docker-compose.yml and restarts services
# -----------------------------------------------------------------------------

detect_existing_free2fa_install() {
    # Heuristics:
    #  1) free2fa systemd unit exists
    #  2) current dir looks like install dir (docker-compose.yml + .env)
    #  3) FreeRADIUS has a non-default site enabled
    if [ -f "/etc/systemd/system/free2fa.service" ]; then
        return 0
    fi
    if [ -f "$PWD/docker-compose.yml" ] && [ -f "$PWD/.env" ]; then
        return 0
    fi
    if [ -d "/etc/freeradius/3.0/sites-enabled" ]; then
        if ls -1 /etc/freeradius/3.0/sites-enabled 2>/dev/null | grep -Ev '^(default|inner-tunnel)$' | head -n 1 | grep -q .; then
            return 0
        fi
    fi
    return 1
}

# Minimal, safe-ish .env loader (only KEY=VALUE, ignores comments)
load_dotenv_file() {
    local f="$1"
    [ -f "$f" ] || return 1
    while IFS= read -r line; do
        line="${line%$'\r'}"
        [ -z "$line" ] && continue
        case "$line" in
            \#*) continue ;;
        esac
        if echo "$line" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*='; then
            export "$line"
        fi
    done < "$f"
    return 0
}

is_pkg_installed() {
    local pkg="$1"
    dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"
}

ensure_packages_installed() {
    local pkgs=("$@")
    local missing=()
    for p in "${pkgs[@]}"; do
        if ! is_pkg_installed "$p"; then
            missing+=("$p")
        fi
    done

    if [ "${#missing[@]}" -eq 0 ]; then
        echo "All required packages are already installed."
        return 0
    fi

    local msg="Missing packages:\n\n$(printf '%s\n' "${missing[@]}")\n\nInstall them now?"
    if whiptail --yesno "$msg" 20 78 --title "Install packages"; then
        apt-get update
        NEEDRESTART_MODE=a apt-get install -y --no-install-recommends "${missing[@]}"
        return $?
    fi

    echo "Package installation skipped by user."
    return 0
}

ensure_blastradius_security_update() {
  local f="$1"

  # If security block does not exist - append
  if ! grep -qE '^[[:space:]]*security[[:space:]]*\{' "$f"; then
    cat >>"$f" <<'EOT'

security {
    require_message_authenticator = auto
    limit_proxy_state = auto
}
EOT
    return
  fi

  if grep -qE '^[[:space:]]*#?[[:space:]]*require_message_authenticator[[:space:]]*=' "$f"; then
    sed -i -E 's/^[[:space:]]*#?[[:space:]]*require_message_authenticator[[:space:]]*=.*/    require_message_authenticator = auto/' "$f"
  else
    sed -i -E '/^[[:space:]]*security[[:space:]]*\{/a\    require_message_authenticator = auto' "$f"
  fi

  if grep -qE '^[[:space:]]*#?[[:space:]]*limit_proxy_state[[:space:]]*=' "$f"; then
    sed -i -E 's/^[[:space:]]*#?[[:space:]]*limit_proxy_state[[:space:]]*=.*/    limit_proxy_state = auto/' "$f"
  else
    sed -i -E '/^[[:space:]]*security[[:space:]]*\{/a\    limit_proxy_state = auto' "$f"
  fi
}

detect_radius_site_name() {
    local dir="/etc/freeradius/3.0/sites-enabled"
    if [ -d "$dir" ]; then
        ls -1 "$dir" 2>/dev/null | grep -Ev '^(default|inner-tunnel)$' | head -n 1 || true
    fi
}

extract_site_value() {
    local site_file="$1"
    local what="$2"
    case "$what" in
        port)
            grep -E '^[[:space:]]*port[[:space:]]*=' "$site_file" | head -n 1 | sed -E 's/.*=[[:space:]]*([0-9]+).*/\1/' || true
            ;;
        shortdomain)
            # &User-Name := "SHORT\\%{tolower:%{User-Name}}"
            grep -E 'User-Name[[:space:]]*:=[[:space:]]*"[A-Za-z0-9_-]+\\\\%\\{tolower:%\\{User-Name\\}\\}"' "$site_file" \
              | head -n 1 \
              | sed -E 's/.*:=[[:space:]]*"([A-Za-z0-9_-]+)\\\\.*/\1/' || true
            ;;
        shortname_flag)
            # if ("True" == "True") or if ("False" == "True")
            grep -E 'if[[:space:]]*\("((True|False|true|false))"[[:space:]]*==[[:space:]]*"True"\)' "$site_file" \
              | head -n 1 \
              | sed -E 's/.*\("((True|False|true|false))".*/\1/' || true
            ;;
        *)
            echo ""
            ;;
    esac
}

backup_free2fa_files() {
    local install_dir="$1"
    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    local bk_dir="${install_dir%/}/backups"
    mkdir -p "$bk_dir"

    local out="${bk_dir}/free2fa_backup_${ts}.tar.gz"
    local manifest="${bk_dir}/free2fa_backup_${ts}.manifest.txt"

    # Collect files that exist (absolute paths)
    local files=()

    # installation dir files
    [ -f "${install_dir%/}/.env" ] && files+=("${install_dir%/}/.env")
    [ -f "${install_dir%/}/docker-compose.yml" ] && files+=("${install_dir%/}/docker-compose.yml")
    [ -f "${install_dir%/}/start_service.sh" ] && files+=("${install_dir%/}/start_service.sh")
    [ -f "${install_dir%/}/stop_service.sh" ] && files+=("${install_dir%/}/stop_service.sh")
    [ -f "${install_dir%/}/key" ] && files+=("${install_dir%/}/key")

    # systemd unit
    [ -f "/etc/systemd/system/free2fa.service" ] && files+=("/etc/systemd/system/free2fa.service")

    # FreeRADIUS related
    local r="/etc/freeradius/3.0"
    [ -f "${r}/radiusd.conf" ] && files+=("${r}/radiusd.conf")
    [ -f "${r}/clients.conf" ] && files+=("${r}/clients.conf")
    [ -f "${r}/mods-available/rest" ] && files+=("${r}/mods-available/rest")
    [ -f "${r}/mods-available/pam" ] && files+=("${r}/mods-available/pam")
    [ -f "${r}/mods-available/cache_free2fa_fail" ] && files+=("${r}/mods-available/cache_free2fa_fail")
    [ -f "${r}/mods-available/cache_free2fa_ban" ] && files+=("${r}/mods-available/cache_free2fa_ban")
    [ -f "${r}/mods-available/linelog_free2fa_guard" ] && files+=("${r}/mods-available/linelog_free2fa_guard")
    [ -d "${r}/scripts" ] && files+=("${r}/scripts")
    [ -d "${r}/sites-available" ] && files+=("${r}/sites-available")
    [ -d "${r}/sites-enabled" ] && files+=("${r}/sites-enabled")
    [ -d "${r}/mods-enabled" ] && files+=("${r}/mods-enabled")

    # PAM service file used by rlm_pam is /etc/pam.d/<pam_auth> (default radiusd)
    # We'll include both if present.
    [ -f "/etc/pam.d/radiusd" ] && files+=("/etc/pam.d/radiusd")
    [ -f "/etc/pam.d/passwd" ] && files+=("/etc/pam.d/passwd")

    # kerberos/sssd (often touched during install)
    [ -f "/etc/krb5.conf" ] && files+=("/etc/krb5.conf")
    [ -f "/etc/sssd/sssd.conf" ] && files+=("/etc/sssd/sssd.conf")

    if [ "${#files[@]}" -eq 0 ]; then
        echo "No files found for backup."
        return 0
    fi

    # Write manifest
    {
        echo "Free2FA backup created at: $(date -Is)"
        echo "Install dir: ${install_dir}"
        echo
        echo "Included paths:"
        for f in "${files[@]}"; do
            echo " - $f"
        done
    } > "$manifest"

    # Store paths relative to / (avoid tar leading-slash stripping ambiguity)
    local rel=()
    for f in "${files[@]}"; do
        # Normalize double slashes and remove leading /
        rel+=("${f#/}")
    done

    # Create archive: payload from / + manifest as additional file
    tar -czf "$out" -C / "${rel[@]}" -C "$bk_dir" "$(basename "$manifest")"
    echo "Backup created: $out"
    echo "Manifest: $manifest"
}


write_cache_modules_update() {
    local root="/etc/freeradius/3.0"
    local cooldown="$1"

    local f_fail="${root}/mods-available/cache_free2fa_fail"
    local f_ban="${root}/mods-available/cache_free2fa_ban"
    local f_log="${root}/mods-available/linelog_free2fa_guard"

    cat >"$f_fail" <<EOF
cache cache_free2fa_fail {
    key = "fail:%{User-Name}"
    ttl = ${cooldown}
    add_stats = yes

    update {
        &control:Tmp-String-2 := "1"
    }
}
EOF

    cat >"$f_ban" <<EOF
cache cache_free2fa_ban {
    key = "ban:%{User-Name}"
    ttl = ${cooldown}

    update {
        &control:Tmp-String-3 := "1"
    }
}
EOF

    cat >"$f_log" <<EOF
linelog free2fa_guard_log {
    filename        = syslog
    syslog_facility = daemon
    format          = "BRUTE FORCE PROTECTION: user '%{User-Name}' blocked for ${cooldown}s (pam_fail_hits=%{%{request:Cache-Entry-Hits}:-n/a})"
}
EOF

    ln -sf "$f_fail" "${root}/mods-enabled/cache_free2fa_fail"
    ln -sf "$f_ban"  "${root}/mods-enabled/cache_free2fa_ban"
    ln -sf "$f_log"  "${root}/mods-enabled/linelog_free2fa_guard"

    chmod 440 "$f_fail" "$f_ban" "$f_log" || true
    chown freerad:freerad "$f_fail" "$f_ban" "$f_log" 2>/dev/null || true
}

rewrite_site_with_cache_update() {
    local site_name="$1"
    local port="$2"
    local shortdomain="$3"
    local shortname_flag="$4"
    local attempts="$5"
    local cooldown="$6"

    local root="/etc/freeradius/3.0"
    local site_file="${root}/sites-available/${site_name}"

    # Use the same template as current install script (cache-aware)
    local tmp
    tmp="$(mktemp)"

    cat <<'EOF' >"$tmp"
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
        # --- Normalize User-Name first (important for cache key stability) ---
        if (&User-Name =~ /(.+)@([^\.]+)/) {
            update request {
                &Tmp-String-0 := "%{tolower:%{1}}"
                &Tmp-String-1 := "%{tolower:%{2}}"
                &User-Name := "%{Tmp-String-1}\\\\%{Tmp-String-0}"
            }
        }
        elsif (&User-Name =~ /^([^.]+)\.([^\\]+)\\(.+)$/) {
            update request {
                &Tmp-String-0 := "%{tolower:%{1}}"
                &Tmp-String-1 := "%{tolower:%{3}}"
                &User-Name := "%{Tmp-String-0}\\\\%{Tmp-String-1}"
            }
        }
        elsif (&User-Name =~ /^[A-Za-z0-9\.\-_]+$/) {
            if ("__shortname__" == "True") {
                update request {
                    &User-Name := "__domain__\\\\%{tolower:%{User-Name}}"
                }
            }
        }
        elsif (&User-Name =~ /^[A-Za-z\.]+\\\\[A-Za-z]+$/) {
            update request {
                &User-Name := "%{tolower:%{User-Name}}"
            }
        }

        #
        # 0) BAN check: if ban:<user> exists -> reject BEFORE PAM
        #
        update control {
            &Cache-Status-Only := yes
        }
        cache_free2fa_ban
        if (ok) {
            reject
        }

        #
        # 1) Normal logic
        #
        if (!&User-Password) {
            update control {
                &Auth-Type := Reject
            }
        }
        else {
            check_membership
            update control {
                &Auth-Type := PAM
            }
        }
    }

    authenticate {
        Auth-Type PAM {
            # Allow unlang after PAM reject: default authenticate behaviour is to return on reject,
            # so we rewrite reject to a low priority instead of immediate return.
            pam {
                reject = 1
            }

            # PAM wrong password -> mark pam_fail and reject
            if (reject) {
                update control {
                    &Tmp-Integer-0 := 1
                }
                reject
            }

            # PAM ok -> mark pam_ok (so OTP/REST failure can clear fail counter)
            if (ok) {
                update control {
                    &Tmp-Integer-1 := 1
                }
            }

            # Second factor
            rest

            # If REST didn't succeed -> reject
            if (!ok && !updated) {
                reject
            }

            ok
        }
    }

    post-auth {
        Post-Auth-Type REJECT {
            #
            # A) Increase counter ONLY for PAM bad password
            #
            if (&control:Tmp-Integer-0 && (&control:Tmp-Integer-0 == 1)) {

                # 1) merge/insert fail counter (creates entry on first fail)
                update control {
                    &Cache-Status-Only := no
                    &Cache-TTL := __cooldown__
                }
                cache_free2fa_fail

                # 2) If entry just created (updated), do a status-only find so hits becomes 1 immediately
                if (updated) {
                    update control {
                        &Cache-Status-Only := yes
                    }
                    cache_free2fa_fail
                }

                # 3) If hits reached threshold -> set ban marker and log
                if (&request:Cache-Entry-Hits && (&request:Cache-Entry-Hits >= __attempts__)) {
                    update control {
                        &Cache-Status-Only := no
                        &Cache-TTL := __cooldown__
                    }
                    cache_free2fa_ban

                    # Optional syslog log entry
                    free2fa_guard_log
                }
            }

            #
            # B) Password was OK (pam_ok) but failed later (e.g. OTP) -> clear fail counter
            #
            elsif (&control:Tmp-Integer-1 && (&control:Tmp-Integer-1 == 1)) {
                update control {
                    &Cache-Status-Only := no
                    &Cache-TTL := 0
                }
                cache_free2fa_fail
            }
        }

        Post-Auth-Type ACCEPT {
            # Success -> clear both fail counter and ban marker
            update control {
                &Cache-Status-Only := no
                &Cache-TTL := 0
            }
            cache_free2fa_fail
            cache_free2fa_ban
        }
    }
}
EOF

    sed "s/__default__/${site_name}/g" "$tmp" > "$site_file"
    sed -i "s/__port__/${port}/g" "$site_file"
    sed -i "s/__domain__/${shortdomain}/g" "$site_file"
    sed -i "s/__shortname__/${shortname_flag}/g" "$site_file"
    sed -i "s/__attempts__/${attempts}/g" "$site_file"
    sed -i "s/__cooldown__/${cooldown}/g" "$site_file"

    rm -f "$tmp"

    chmod 440 "$site_file" || true
    chown freerad:freerad "$site_file" 2>/dev/null || true

    ln -sf "$site_file" "${root}/sites-enabled/${site_name}"
}

update_flow() {
    local install_dir="$PWD"

    # Ask install dir if docker-compose not in current dir
    if [ ! -f "${install_dir}/docker-compose.yml" ]; then
        install_dir=$(whiptail --inputbox "Enter Free2FA install directory (where docker-compose.yml is located):" 10 90 "$install_dir" --title "Update: install dir" 3>&1 1>&2 2>&3)
        check_if_cancel
    fi

    [ -d "$install_dir" ] || die "Install dir not found: $install_dir"
    cd "$install_dir"

    init_run_log "$install_dir" "update"
    log "Update started in install dir: $install_dir"

    # Try to load existing .env
    if [ -f ".env" ]; then
        load_dotenv_file ".env" || true
        log "Loaded .env from install dir."
    else
        warn ".env not found in install dir."
    fi

    # Throttle defaults (same defaults as dialogs in this script)
    local THROTTLE_ATTEMPTS_LOCAL="${THROTTLE_ATTEMPTS:-4}"
    local THROTTLE_COOLDOWN_LOCAL="${THROTTLE_COOLDOWN_SECONDS:-300}"

    # Ask user - allow change
    THROTTLE_ATTEMPTS_LOCAL=$(whiptail --inputbox "Max failed attempts per user before cooldown:" 10 90 "$THROTTLE_ATTEMPTS_LOCAL" --title "Update: THROTTLE_ATTEMPTS" 3>&1 1>&2 2>&3)
    check_if_cancel
    THROTTLE_COOLDOWN_LOCAL=$(whiptail --inputbox "Cooldown duration in seconds after reaching the limit:" 10 90 "$THROTTLE_COOLDOWN_LOCAL" --title "Update: THROTTLE_COOLDOWN_SECONDS" 3>&1 1>&2 2>&3)
    check_if_cancel

    # Validate
    while ! [[ "$THROTTLE_ATTEMPTS_LOCAL" =~ ^[0-9]+$ ]] || [ "$THROTTLE_ATTEMPTS_LOCAL" -lt 1 ]; do
        THROTTLE_ATTEMPTS_LOCAL=$(whiptail --inputbox "Invalid. Enter positive integer:" 10 90 "4" --title "Update: THROTTLE_ATTEMPTS" 3>&1 1>&2 2>&3)
        check_if_cancel
    done
    while ! [[ "$THROTTLE_COOLDOWN_LOCAL" =~ ^[0-9]+$ ]] || [ "$THROTTLE_COOLDOWN_LOCAL" -lt 1 ]; do
        THROTTLE_COOLDOWN_LOCAL=$(whiptail --inputbox "Invalid. Enter positive integer:" 10 90 "300" --title "Update: THROTTLE_COOLDOWN_SECONDS" 3>&1 1>&2 2>&3)
        check_if_cancel
    done

    # Domain join status (informational)
    local domain_join="no"
    if realm list 2>/dev/null | grep -q "domain-name"; then
        domain_join="yes"
    fi

    # Detect site
    local site_name="${RADIUS_SITE_NAME:-}"
    if [ -z "$site_name" ]; then
        site_name="$(detect_radius_site_name)"
    fi
    if [ -z "$site_name" ]; then
        site_name=$(whiptail --inputbox "Enter RADIUS SITE NAME:" 10 90 "2fa_default" --title "Update: RADIUS_SITE_NAME" 3>&1 1>&2 2>&3)
        check_if_cancel
    fi

    local site_file="/etc/freeradius/3.0/sites-available/${site_name}"
    [ -f "$site_file" ] || die "Site file not found: $site_file"

    # PAM service name used by rlm_pam (important for the pam_unix/pam_sss log lines you saw)
    local current_pam_auth
    current_pam_auth="$(get_freeradius_pam_auth_name)"

    # Pre-summary to user
    whiptail --msgbox "Detected:\n\n- Domain joined: ${domain_join}\n- Site: ${site_name}\n- rlm_pam PAM service: ${current_pam_auth} (uses /etc/pam.d/${current_pam_auth})\n\nA log will be saved to:\n${LOG_FILE}" 16 90 --title "Update summary"

    # Decide actions (interactive)
    # Default: do backup + cache update + security block + restart.
    local fix_pam_default="OFF"
    if [ "$current_pam_auth" != "radiusd" ]; then
        fix_pam_default="ON"
    fi

    local choices
    choices=$(whiptail --title "Update actions" --checklist "Select what to do:" 22 90 10 \
        "backup"      "Create backup archive before changes" ON \
        "packages"    "Ensure required packages are installed" ON \
        "cache_mods"  "Create/Update cache modules (cache_free2fa_* + linelog)" ON \
        "radius_sec"  "Ensure radiusd.conf security{} block" ON \
        "site_cache"  "Update site config to cache-aware version (if missing)" ON \
        "pam_fix"     "Fix PAM for rlm_pam: set pam_auth=radiusd + /etc/pam.d/radiusd (SSSD first)" "$fix_pam_default" \
        "compose"     "Update docker-compose.yml from GitHub" OFF \
        "restart"     "Restart services" ON \
        3>&1 1>&2 2>&3)
    check_if_cancel

    log "Selected actions: $choices"
    local do_backup=0 do_packages=0 do_cache_mods=0 do_radius_sec=0 do_site_cache=0 do_pam_fix=0 do_compose=0 do_restart=0
    echo "$choices" | grep -q "backup" && do_backup=1
    echo "$choices" | grep -q "packages" && do_packages=1
    echo "$choices" | grep -q "cache_mods" && do_cache_mods=1
    echo "$choices" | grep -q "radius_sec" && do_radius_sec=1
    echo "$choices" | grep -q "site_cache" && do_site_cache=1
    echo "$choices" | grep -q "pam_fix" && do_pam_fix=1
    echo "$choices" | grep -q "compose" && do_compose=1
    echo "$choices" | grep -q "restart" && do_restart=1

    # 1) Backup
    if [ $do_backup -eq 1 ]; then
        log "Creating backup..."
        backup_free2fa_files "$install_dir"
    else
        warn "Backup skipped by user."
    fi

    # 2) Packages
    if [ $do_packages -eq 1 ]; then
        log "Ensuring required packages are installed..."
        ensure_packages_installed ca-certificates curl sssd sssd-tools libnss-sss libpam-sss adcli realmd krb5-user freeradius freeradius-rest freeradius-utils
    else
        warn "Package check skipped."
    fi

    # 3) .env throttle keys (best-effort)
    if [ -f ".env" ]; then
        if ! grep -qE '^THROTTLE_ATTEMPTS=' ".env"; then
            echo "THROTTLE_ATTEMPTS=${THROTTLE_ATTEMPTS_LOCAL}" >> ".env"
            log "Appended THROTTLE_ATTEMPTS to .env"
        fi
        if ! grep -qE '^THROTTLE_COOLDOWN_SECONDS=' ".env"; then
            echo "THROTTLE_COOLDOWN_SECONDS=${THROTTLE_COOLDOWN_LOCAL}" >> ".env"
            log "Appended THROTTLE_COOLDOWN_SECONDS to .env"
        fi
    fi

    # 4) Cache modules
    if [ $do_cache_mods -eq 1 ]; then
        log "Writing cache modules (cooldown=${THROTTLE_COOLDOWN_LOCAL})..."
        write_cache_modules_update "$THROTTLE_COOLDOWN_LOCAL"
    else
        warn "Cache modules update skipped."
    fi

    # 5) radiusd.conf security block
    if [ $do_radius_sec -eq 1 ]; then
        if [ -f "/etc/freeradius/3.0/radiusd.conf" ]; then
            log "Ensuring radiusd.conf security{} block..."
            ensure_blastradius_security_update "/etc/freeradius/3.0/radiusd.conf"
        else
            warn "radiusd.conf not found, security block skipped."
        fi
    fi

    # 6) Site config update (only if missing cache logic)
    if [ $do_site_cache -eq 1 ]; then
        if grep -q "cache_free2fa_ban" "$site_file"; then
            log "Site already contains cache logic: $site_file"
        else
            log "Updating site config to cache-aware template: $site_file"
            local port shortdomain shortflag
            port="$(extract_site_value "$site_file" port)"
            shortdomain="$(extract_site_value "$site_file" shortdomain)"
            shortflag="$(extract_site_value "$site_file" shortname_flag)"

            if [ -z "$port" ]; then
                port=$(whiptail --inputbox "Enter RADIUS port number:" 10 90 "1812" --title "Update: RADIUS_PORT_NUMBER" 3>&1 1>&2 2>&3)
                check_if_cancel
            fi
            if [ -z "$shortdomain" ]; then
                shortdomain=$(whiptail --inputbox "Enter short domain (NETBIOS / short name, e.g. DOMAIN):" 10 90 "" --title "Update: short domain" 3>&1 1>&2 2>&3)
                check_if_cancel
            fi
            if [ -z "$shortflag" ]; then
                shortflag=$(whiptail --inputbox "Enter shortname flag (True/False) from existing config:" 10 90 "True" --title "Update: shortname flag" 3>&1 1>&2 2>&3)
                check_if_cancel
            fi

            cp -a "$site_file" "${site_file}.bak_$(date +%Y%m%d_%H%M%S)"
            rewrite_site_with_cache_update "$site_name" "$port" "$shortdomain" "$shortflag" "$THROTTLE_ATTEMPTS_LOCAL" "$THROTTLE_COOLDOWN_LOCAL"
            log "Site updated with cache logic: $site_file"
        fi
    fi

    # 7) PAM fix
    if [ $do_pam_fix -eq 1 ]; then
        # Your log line contained "pam_unix(passwd:auth)" + "pam_sss(passwd:auth)".
        # That means rlm_pam is using PAM service name "passwd" (or request overrides), i.e. /etc/pam.d/passwd.
        # Fix strategy: switch to pam_auth=radiusd and provide /etc/pam.d/radiusd where pam_sss is tried first.
        log "Applying PAM fix: set pam_auth=radiusd and ensure /etc/pam.d/radiusd (SSSD first)..."
        local pam_mod="/etc/freeradius/3.0/mods-available/pam"
        if [ -f "$pam_mod" ]; then
            cp -a "$pam_mod" "${pam_mod}.bak_$(date +%Y%m%d_%H%M%S)"
            log "Backup rlm_pam config: ${pam_mod}.bak_*"
        fi
        set_freeradius_pam_auth_name "radiusd"
        ensure_pam_d_radiusd_prefer_sss
        log "PAM fix applied. Previous rlm_pam PAM service was: ${current_pam_auth}"
    else
        log "PAM fix not selected."
    fi

    # 8) docker-compose update
    if [ $do_compose -eq 1 ]; then
        log "Downloading docker-compose.yml from GitHub..."
        curl -L "https://raw.githubusercontent.com/CLLlAgOB/free2fa/main/docker-compose/docker-compose.yml" -o docker-compose.yml
        log "docker-compose.yml downloaded."
    fi

    # 9) Restart
    if [ $do_restart -eq 1 ]; then
        log "Restarting services..."
        if command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload || true
            if systemctl list-unit-files --type=service 2>/dev/null | grep -q '^free2fa\.service'; then
                systemctl restart free2fa.service || true
            else
                service freeradius restart || true
            fi
        else
            service free2fa restart || service freeradius restart || true
        fi
        log "Restart complete."
    else
        warn "Restart skipped."
    fi

    whiptail --msgbox "Update completed.\n\nLog:\n${LOG_FILE}\n\nBackups dir:\n${install_dir%/}/backups" 14 90 --title "Free2FA Update"
}


# Choose mode if installation detected
if detect_existing_free2fa_install; then
    MODE=$(whiptail --title "Free2FA" --menu "Select mode:" 14 80 3 \
        "install"  "New installation (full)" \
        "update"   "Update existing installation (backup + configs)" \
        "restore"  "Restore from backup archive (overwrites files)" \
        3>&1 1>&2 2>&3)
    check_if_cancel

    if [ "$MODE" = "update" ]; then
        update_flow
        exit 0
    elif [ "$MODE" = "restore" ]; then
        # Restore needs install dir to locate backups/ (where archives are stored)
        local_dir="$PWD"
        if [ ! -d "${local_dir%/}/backups" ]; then
            local_dir=$(whiptail --inputbox "Enter Free2FA install directory (where backups/ is located):" 10 90 "$local_dir" --title "Restore: install dir" 3>&1 1>&2 2>&3)
            check_if_cancel
        fi
        restore_free2fa_backup "$local_dir"
        exit 0
    fi
fi

# Requesting a domain name
DOMAIN=$(whiptail --inputbox "Enter the domain name (for example, domain.local). Enter in lower case:" 8 78 --title "Domain Name" 3>&1 1>&2 2>&3)
DOMAIN=${DOMAIN,,} 
check_if_cancel

# Проверяем, резолвится ли домен
if nslookup "$DOMAIN" > /dev/null; then
    echo "Domain $DOMAIN is resolved successfully."
else
    echo "Error: Domain $DOMAIN cannot be resolved. Check your domain name or DNS settings."
    exit 1
fi


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

# Check and install Docker without asking first
check_and_install_docker


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
cat <<EOF >"$TEMP_FILE"
krb5-config krb5-config/default_realm string $DOMAIN_LOCAL
krb5-config krb5-config/kerberos_servers string $KERBEROS_SERVER
krb5-config krb5-config/admin_server string $ADMIN_SERVER
krb5-config krb5-config/dns_for_default boolean true
krb5-config krb5-config/add_servers boolean false
EOF

# Applying the settings from the temporary file
debconf-set-selections "$TEMP_FILE"

# Deleting the temporary file
rm "$TEMP_FILE"

# installation of required packages.
apt-get update
NEEDRESTART_MODE=a apt-get install -y --no-install-recommends ca-certificates curl sssd sssd-tools libnss-sss libpam-sss adcli realmd krb5-user freeradius freeradius-rest freeradius-utils

if realm list | grep -q "domain-name"; then
    echo "Server is already joined to a domain."
else
    # Requesting a username
    USER=$(whiptail --inputbox "Enter a user name to enter the server into the domain" 8 78 --title "User Name" 3>&1 1>&2 2>&3)

    check_if_cancel

    # Logging in to the domain
    echo "Logging into the $DOMAIN domain using the $USER user..."
    if realm join "$DOMAIN" --user="$USER"; then
        echo "Successfully joined the domain $DOMAIN."
    else
        echo "Error: Failed to join the domain $DOMAIN."
        exit 1
    fi
fi

# Ask the user whether to allow login by short names
if whiptail --yesno "Allow login by short names without specifying a domain?" 20 60 --defaultno; then
    USE_FULLY_QUALIFIED_NAMES="False"
else
    USE_FULLY_QUALIFIED_NAMES="True"
fi

# Asking which groups are allowed to log in
ALLOW_GROUPS=$(whiptail --inputbox "Enter the groups that are allowed to authorize, separated by commas (for example, vpn@domain.local,vpn2@domain.local). \n
Attention if you use short names, you should specify groups without domain. ( e.g. vpn,vpn2 ) " 20 60 3>&1 1>&2 2>&3)

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

sed -i "s/^access_provider = .*/access_provider = permit/" "$SSSD_CONF"

# # Add or update the simple_allow_groups setting
# if grep -q "^simple_allow_groups" "$SSSD_CONF"; then
#     sed -i "s/^simple_allow_groups = .*/simple_allow_groups = $ALLOW_GROUPS/" "$SSSD_CONF"
# else
#     echo "simple_allow_groups = $ALLOW_GROUPS" | tee -a "$SSSD_CONF"
# fi

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

ROOT_DIR="/etc/freeradius/3.0/"
CONFIG_FILE_RADIUS="${ROOT_DIR}radiusd.conf"
CONFIG_FILE_CLIENT="${ROOT_DIR}clients.conf"
START_SERVICE="$PWD/start_service.sh"
STOP_SERVICE="$PWD/stop_service.sh"
FREE2FA_SERVICE="/etc/systemd/system/free2fa.service"

# --- PAM lockout settings (wrong password via rlm_pam) ---
PAM_LOCKOUT_MAX_FAILS=5        # lock after 5 bad passwords
PAM_LOCKOUT_BAN_SECONDS=300    # ban duration (5 minutes)

CONFIG_FILE_KRB5="/etc/krb5.conf"
CONFIG_FILE_REST="${ROOT_DIR}mods-available/rest"
CONFIG_FILE_PAM="${ROOT_DIR}mods-available/pam"
CONFIG_FILE_CACHE_FREE2FA_FAIL="${ROOT_DIR}mods-available/cache_free2fa_fail"
CONFIG_FILE_CACHE_FREE2FA_BAN="${ROOT_DIR}mods-available/cache_free2fa_ban"
CONFIG_FILE_LINELOG_GUARD="${ROOT_DIR}mods-available/linelog_free2fa_guard"
CONFIG_FILE_SITE="${ROOT_DIR}sites-available/"
EXEC_MOD="${ROOT_DIR}mods-available/exec"
SCRIPT_DIR="${ROOT_DIR}scripts/"
CHECK_GROUP_SCRIPT="${SCRIPT_DIR}check_group_membership.sh"

mkdir -p $SCRIPT_DIR
# Creating a temporary file
TEMP_FILE=$(mktemp)

# Writing Kerberos settings to a temporary file
cat <<EOF >"$TEMP_FILE"
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
    echo "                kdc = $server" >> "$TEMP_FILE"
done

cat <<EOF >>"$TEMP_FILE"
                admin_server = $ADMIN_SERVER
                default_domain = $DOMAIN
        }

[domain_realm]
        .$DOMAIN = $DOMAIN_UPPERCASE
        $DOMAIN = $DOMAIN_UPPERCASE
EOF

ensure_blastradius_security() {
  local f="$1"

  # Если security-блока нет — добавим в конец файла
  if ! grep -qE '^[[:space:]]*security[[:space:]]*\{' "$f"; then
    cat >>"$f" <<'EOT'

security {
    require_message_authenticator = auto
    limit_proxy_state = auto
}
EOT
    return
  fi

  if grep -qE '^[[:space:]]*#?[[:space:]]*require_message_authenticator[[:space:]]*=' "$f"; then
    sed -i -E 's/^[[:space:]]*#?[[:space:]]*require_message_authenticator[[:space:]]*=.*/    require_message_authenticator = auto/' "$f"
  else
    sed -i -E '/^[[:space:]]*security[[:space:]]*\{/a\    require_message_authenticator = auto' "$f"
  fi

  if grep -qE '^[[:space:]]*#?[[:space:]]*limit_proxy_state[[:space:]]*=' "$f"; then
    sed -i -E 's/^[[:space:]]*#?[[:space:]]*limit_proxy_state[[:space:]]*=.*/    limit_proxy_state = auto/' "$f"
  else
    sed -i -E '/^[[:space:]]*security[[:space:]]*\{/a\    limit_proxy_state = auto' "$f"
  fi
}

cp "$TEMP_FILE" "$CONFIG_FILE_KRB5"

# Deleting the temporary file
rm "$TEMP_FILE"

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
FREE2FA_TELEGRAM_BOT_PROXY=${FREE2FA_TELEGRAM_BOT_PROXY}
FREE2FA_AUTO_REG_ENABLED=${FREE2FA_AUTO_REG_ENABLED}
FREE2FA_BYPASS_ENABLED=${FREE2FA_BYPASS_ENABLED}
RADIUS_CLIENT_SECRET=${RADIUS_CLIENT_SECRET}
REQUIRE_MESSAGE_AUTHENTICATOR=${REQUIRE_MESSAGE_AUTHENTICATOR}
FREE2FA_TIMEOUT=${FREE2FA_TIMEOUT}
RADIUS_START_SERVERS=${RADIUS_START_SERVERS}
RADIUS_MAX_SERVERS=${RADIUS_MAX_SERVERS}
RADIUS_MAX_SPARE_SERVERS=${RADIUS_MAX_SPARE_SERVERS}
RADIUS_MIN_SPARE_SERVERS=${RADIUS_MIN_SPARE_SERVERS}
ADMIN_SECRET_KEY=${ADMIN_SECRET_KEY:-$(generate_random_key)}
RESET_PASSWORD=${RESET_PASSWORD}
ALLOW_API_FAILURE_PASS=${ALLOW_API_FAILURE_PASS}
ADDITIONAL_DNS_NAME_FOR_ADMIN_HTML=${ADDITIONAL_DNS_NAME_FOR_ADMIN_HTML}
THROTTLE_ATTEMPTS=${THROTTLE_ATTEMPTS}
THROTTLE_COOLDOWN_SECONDS=${THROTTLE_COOLDOWN_SECONDS}
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
    FREE2FA_TELEGRAM_BOT_PROXY=$(whiptail --inputbox "Enter TELEGRAM_BOT_PROXY (leave empty to disable, example socks5://127.0.0.1:1080):" 10 78 "" --title "FREE2FA_TELEGRAM_BOT_PROXY" 3>&1 1>&2 2>&3)
    check_if_cancel
    FREE2FA_AUTO_REG_ENABLED=$(whiptail --inputbox "Enter AUTO_REG_ENABLED (default true):" 8 78 true --title "FREE2FA_AUTO_REG_ENABLED" 3>&1 1>&2 2>&3)
    check_if_cancel
    FREE2FA_BYPASS_ENABLED=$(whiptail --inputbox "Enter BYPASS_ENABLED (default true):" 8 78 true --title "FREE2FA_BYPASS_ENABLED" 3>&1 1>&2 2>&3)
    check_if_cancel
    RADIUS_CLIENT_SECRET=$(whiptail --inputbox "Enter RADIUS_CLIENT_SECRET (default secret123):" 8 78 secret123 --title "RADIUS_CLIENT_SECRET" 3>&1 1>&2 2>&3)
    check_if_cancel
    REQUIRE_MESSAGE_AUTHENTICATOR=$(whiptail --inputbox "Require mandatory Message-Authenticator attribute in RADIUS messages (default false):" 8 78 false --title "REQUIRE_MESSAGE_AUTHENTICATOR" 3>&1 1>&2 2>&3)
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
    RADIUS_SITE_NAME=$(whiptail --inputbox "Enter RADIUS SITE NAME (default 2fa_default):" 8 78 "2fa_default" --title "RADIUS_SITE_NAME" 3>&1 1>&2 2>&3)
    check_if_cancel
    RADIUS_PORT_NUMBER=$(whiptail --inputbox "Enter RADIUS port number (default 1812):" 8 78 "1812" --title "RADIUS_PORT_NUMBER" 3>&1 1>&2 2>&3)
    check_if_cancel
    # ---- Throttle (anti-bruteforce) settings ----
    THROTTLE_ATTEMPTS=$(
    whiptail --inputbox "Max failed attempts per user before cooldown (default 5):" \
        8 78 "5" --title "THROTTLE_ATTEMPTS" 3>&1 1>&2 2>&3
    )
    check_if_cancel

    # validate THROTTLE_ATTEMPTS
    while ! [[ "$THROTTLE_ATTEMPTS" =~ ^[0-9]+$ ]] || [ "$THROTTLE_ATTEMPTS" -lt 1 ]; do
    THROTTLE_ATTEMPTS=$(
        whiptail --inputbox "Invalid value. Enter a positive integer (default 5):" \
        8 78 "5" --title "THROTTLE_ATTEMPTS" 3>&1 1>&2 2>&3
    )
    check_if_cancel
    done

    THROTTLE_COOLDOWN_SECONDS=$(
    whiptail --inputbox "Cooldown duration in seconds after reaching the limit (default 300):" \
        8 78 "300" --title "THROTTLE_COOLDOWN_SECONDS" 3>&1 1>&2 2>&3
    )
    check_if_cancel

    # validate THROTTLE_COOLDOWN_SECONDS
    while ! [[ "$THROTTLE_COOLDOWN_SECONDS" =~ ^[0-9]+$ ]] || [ "$THROTTLE_COOLDOWN_SECONDS" -lt 1 ]; do
    THROTTLE_COOLDOWN_SECONDS=$(
        whiptail --inputbox "Invalid value. Enter a positive integer (default 300):" \
        8 78 "300" --title "THROTTLE_COOLDOWN_SECONDS" 3>&1 1>&2 2>&3
    )
    check_if_cancel
    done
    create_env_file
}

# Download docker-compose.yml
download_docker_compose_yml() {
    curl -L "https://raw.githubusercontent.com/CLLlAgOB/free2fa/main/docker-compose/docker-compose.yml" -o docker-compose.yml
    echo "docker-compose.yml downloaded."
}

prompt_env_configuration
download_docker_compose_yml

CONFIG_FILE_SITE="$CONFIG_FILE_SITE$RADIUS_SITE_NAME"

key_file="${ROOT_DIR}key"

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

# Записываем настройки SITE config во временный файл
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
        # --- Normalize User-Name first (important for cache key stability) ---
        if (&User-Name =~ /(.+)@([^\.]+)/) {
            update request {
                &Tmp-String-0 := "%{tolower:%{1}}"
                &Tmp-String-1 := "%{tolower:%{2}}"
                &User-Name := "%{Tmp-String-1}\\\\%{Tmp-String-0}"
            }
        }
        elsif (&User-Name =~ /^([^.]+)\.([^\\]+)\\(.+)$/) {
            update request {
                &Tmp-String-0 := "%{tolower:%{1}}"
                &Tmp-String-1 := "%{tolower:%{3}}"
                &User-Name := "%{Tmp-String-0}\\\\%{Tmp-String-1}"
            }
        }
        elsif (&User-Name =~ /^[A-Za-z0-9\.\-_]+$/) {
            if ("__shortname__" == "True") {
                update request {
                    &User-Name := "__domain__\\\\%{tolower:%{User-Name}}"
                }
            }
        }
        elsif (&User-Name =~ /^[A-Za-z\.]+\\\\[A-Za-z]+$/) {
            update request {
                &User-Name := "%{tolower:%{User-Name}}"
            }
        }

        #
        # 0) BAN check: if ban:<user> exists -> reject BEFORE PAM
        #
        update control {
            &Cache-Status-Only := yes
        }
        cache_free2fa_ban
        if (ok) {
            reject
        }

        #
        # 1) Normal logic
        #
        if (!&User-Password) {
            update control {
                &Auth-Type := Reject
            }
        }
        else {
            check_membership
            update control {
                &Auth-Type := PAM
            }
        }
    }

    authenticate {
        Auth-Type PAM {
            # Allow unlang after PAM reject: default authenticate behaviour is to return on reject,
            # so we rewrite reject to a low priority instead of immediate return.
            pam {
                reject = 1
            }

            # PAM wrong password -> mark pam_fail and reject
            if (reject) {
                update control {
                    &Tmp-Integer-0 := 1
                }
                reject
            }

            # PAM ok -> mark pam_ok (so OTP/REST failure can clear fail counter)
            if (ok) {
                update control {
                    &Tmp-Integer-1 := 1
                }
            }

            # Second factor
            rest

            # If REST didn't succeed -> reject
            if (!ok && !updated) {
                reject
            }

            ok
        }
    }

    post-auth {
        Post-Auth-Type REJECT {
            #
            # A) Increase counter ONLY for PAM bad password
            #
            if (&control:Tmp-Integer-0 && (&control:Tmp-Integer-0 == 1)) {

                # 1) merge/insert fail counter (creates entry on first fail)
                update control {
                    &Cache-Status-Only := no
                    &Cache-TTL := __cooldown__
                }
                cache_free2fa_fail

                # 2) If entry just created (updated), do a status-only find so hits becomes 1 immediately
                if (updated) {
                    update control {
                        &Cache-Status-Only := yes
                    }
                    cache_free2fa_fail
                }

                # 3) If hits reached threshold -> set ban marker and log
                if (&request:Cache-Entry-Hits && (&request:Cache-Entry-Hits >= __attempts__)) {
                    update control {
                        &Cache-Status-Only := no
                        &Cache-TTL := __cooldown__
                    }
                    cache_free2fa_ban

                    # Optional syslog log entry
                    free2fa_guard_log
                }
            }

            #
            # B) Password was OK (pam_ok) but failed later (e.g. OTP) -> clear fail counter
            #
            elsif (&control:Tmp-Integer-1 && (&control:Tmp-Integer-1 == 1)) {
                update control {
                    &Cache-Status-Only := no
                    &Cache-TTL := 0
                }
                cache_free2fa_fail
            }
        }

        Post-Auth-Type ACCEPT {
            # Success -> clear both fail counter and ban marker
            update control {
                &Cache-Status-Only := no
                &Cache-TTL := 0
            }
            cache_free2fa_fail
            cache_free2fa_ban
        }
    }
}
EOF

shortdomain="${DOMAIN%%.*}"

sed "s/__default__/$RADIUS_SITE_NAME/g" "$TEMP_FILE" > "$CONFIG_FILE_SITE"
sed -i "s/__port__/$RADIUS_PORT_NUMBER/g" "$CONFIG_FILE_SITE"
sed -i "s/__domain__/$shortdomain/g" "$CONFIG_FILE_SITE"
sed -i "s/__shortname__/$USE_FULLY_QUALIFIED_NAMES/g" "$CONFIG_FILE_SITE"
sed -i "s/__attempts__/$THROTTLE_ATTEMPTS/g" "$CONFIG_FILE_SITE"
sed -i "s/__cooldown__/$THROTTLE_COOLDOWN_SECONDS/g" "$CONFIG_FILE_SITE"

# Deleting the temporary file
rm "$TEMP_FILE"
TEMP_FILE=$(mktemp)

# Writing check group membership settings to a temporary file
cat <<'EOF' >"$TEMP_FILE"
exec check_membership {
    wait = yes
    program = "__script__ %{User-Name} __groups__"
    input_pairs = request
    output_pairs = reply
    shell_escape = yes
}
EOF

sed "s|__script__|$CHECK_GROUP_SCRIPT|g" "$TEMP_FILE" > "$EXEC_MOD"
sed -i "s/__groups__/$ALLOW_GROUPS/g" "$EXEC_MOD"


# Creating a temporary file
TEMP_FILE=$(mktemp)

# Writing check group membership settings to a temporary file
cat <<'EOF' >"$TEMP_FILE"
#!/bin/bash

# Get username and group string from command line arguments
USERNAME="$1"
GROUPS_STRING="$2"

# Path to the log file for debugging
LOG_FILE="/var/log/freeradius/group_check.log"

# Write the obtained parameters to a log file for debugging
echo "Received parameters: USERNAME=$USERNAME, GROUPS_STRING=$GROUPS_STRING" >> "$LOG_FILE"

# Convert the username to work correctly with the id command
username_sanitized=$(echo "$USERNAME" | sed 's|\\\\|\\|g')

# Function for checking whether the user belongs to a group
check_group_membership() {
    local username="$1"

    # Get the list of user groups
    user_groups=$(id -nG "$username" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "User $username does not exist" >> "$LOG_FILE"
        # Return attribute for FreeRADIUS
        #echo "Reply-Message = \"User $username does not exist\""
        exit 1
    fi

    # Convert the string of groups into an array
    IFS=',' read -r -a REQUIRED_GROUPS <<< "$GROUPS_STRING"

    for group in "${REQUIRED_GROUPS[@]}"; do
        if [[ " $user_groups " =~ " $group " ]]; then
            echo "User $username is a member of group $group" >> "$LOG_FILE"
            # Return attribute for FreeRADIUS
            #echo "Reply-Message = \"User $username is a member of group $group\""
            exit 0
        fi
    done

    # If the user does not belong to any of the required groups
    echo "User $username does not belong to any required group" >> "$LOG_FILE"
    # Return attribute for FreeRADIUS
    echo "Reply-Message = \"User $username does not belong to any required group\""
    exit 1
}

check_group_membership "$username_sanitized" "$GROUPS_STRING"
EOF

cp "$TEMP_FILE" "$CHECK_GROUP_SCRIPT"

# Deleting the temporary file
rm "$TEMP_FILE"

# Creating a temporary file
TEMP_FILE=$(mktemp)

# Writing REST settings to a temporary file
cat <<'EOF' >"$TEMP_FILE"
rest {
    tls {
        check_cert = yes
        check_cert_cn = yes
    }

    connect_uri = "https://localhost:5000"
    connect_timeout = __timeout3__

    authenticate {
        uri = "${..connect_uri}/authenticate"
        method = 'post'
        body = 'json'
        data = '{ "user_name": "%{User-Name}", "client_key": "FREE2FA_API_KEY" }'
        tls = ${..tls}
        timeout = __timeout2__
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

sed "s/__timeout3__/$((FREE2FA_TIMEOUT + 3))/g" "$TEMP_FILE" > "$CONFIG_FILE_REST"
sed -i "s/__timeout2__/$((FREE2FA_TIMEOUT + 2))/g" "$CONFIG_FILE_REST"

# Deleting the temporary file
rm "$TEMP_FILE"

# Creating a temporary file
TEMP_FILE=$(mktemp)

# Create dedicated PAM service for FreeRADIUS (SSSD only, no local pam_unix)
PAM_SERVICE_NAME="radiusd"
PAM_SERVICE_FILE="/etc/pam.d/${PAM_SERVICE_NAME}"

# Creating a temporary file
TEMP_FILE=$(mktemp)

# Writing PAM service (SSSD only) to a temporary file
cat <<'EOF' >"$TEMP_FILE"
#%PAM-1.0

auth    required    pam_env.so
auth    sufficient  pam_sss.so forward_pass
auth    required    pam_deny.so

account sufficient  pam_sss.so
account required    pam_deny.so
EOF

cp "$TEMP_FILE" "$PAM_SERVICE_FILE"
chmod 0644 "$PAM_SERVICE_FILE"

# Deleting the temporary file
rm "$TEMP_FILE"

# Creating a temporary file
TEMP_FILE=$(mktemp)

# Writing pam settings to a temporary file
cat <<EOF >"$TEMP_FILE"
pam {
        pam_auth = radiusd
}
EOF

cp "$TEMP_FILE" "$CONFIG_FILE_PAM"

# Deleting the temporary file
rm "$TEMP_FILE"

# Creating a temporary file

TEMP_FILE=$(mktemp)

# ---------------------------------------------------------------------------
# Free2FA brute-force protection (PAM bad password ONLY)
#   - cache_free2fa_fail : counts bad PAM passwords per User-Name (hits via add_stats)
#   - cache_free2fa_ban  : bans User-Name for THROTTLE_COOLDOWN_SECONDS
#   - linelog_free2fa_guard : logs ban event to syslog (facility daemon)
# ---------------------------------------------------------------------------

# cache_free2fa_fail
cat <<EOF >"$TEMP_FILE"
cache cache_free2fa_fail {
    key = "fail:%{User-Name}"
    ttl = __cooldown__
    add_stats = yes

    update {
        &control:Tmp-String-2 := "1"
    }
}
EOF

cp "$TEMP_FILE" "$CONFIG_FILE_CACHE_FREE2FA_FAIL"
rm "$TEMP_FILE"

sed -i "s/__cooldown__/$THROTTLE_COOLDOWN_SECONDS/g" "$CONFIG_FILE_CACHE_FREE2FA_FAIL"
ln -sf "$CONFIG_FILE_CACHE_FREE2FA_FAIL" "${ROOT_DIR}mods-enabled/cache_free2fa_fail"

# cache_free2fa_ban
TEMP_FILE=$(mktemp)
cat <<EOF >"$TEMP_FILE"
cache cache_free2fa_ban {
    key = "ban:%{User-Name}"
    ttl = __cooldown__

    update {
        &control:Tmp-String-3 := "1"
    }
}
EOF

cp "$TEMP_FILE" "$CONFIG_FILE_CACHE_FREE2FA_BAN"
rm "$TEMP_FILE"

sed -i "s/__cooldown__/$THROTTLE_COOLDOWN_SECONDS/g" "$CONFIG_FILE_CACHE_FREE2FA_BAN"
ln -sf "$CONFIG_FILE_CACHE_FREE2FA_BAN" "${ROOT_DIR}mods-enabled/cache_free2fa_ban"

# linelog (syslog) for ban event
TEMP_FILE=$(mktemp)
cat <<EOF >"$TEMP_FILE"
linelog free2fa_guard_log {
    filename        = syslog
    syslog_facility = daemon
    format          = "BRUTE FORCE PROTECTION: user '%{User-Name}' blocked for __cooldown__s (pam_fail_hits=%{%{request:Cache-Entry-Hits}:-n/a})"
}
EOF

cp "$TEMP_FILE" "$CONFIG_FILE_LINELOG_GUARD"
rm "$TEMP_FILE"

sed -i "s/__cooldown__/$THROTTLE_COOLDOWN_SECONDS/g" "$CONFIG_FILE_LINELOG_GUARD"
ln -sf "$CONFIG_FILE_LINELOG_GUARD" "${ROOT_DIR}mods-enabled/linelog_free2fa_guard"

# Write the settings to a temporary file
cat <<EOF >"$TEMP_FILE"
client $RADIUS_SITE_NAME {
  ipaddr = $RADIUS_CLIENT_IP
  secret = $RADIUS_CLIENT_SECRET
  require_message_authenticator = $REQUIRE_MESSAGE_AUTHENTICATOR
  limit_proxy_state = auto
}
EOF

cp "$TEMP_FILE" "$CONFIG_FILE_CLIENT"

# Deleting the temporary file
rm "$TEMP_FILE"

# Creating a temporary file
TEMP_FILE=$(mktemp)

CURRENT_DIR=$PWD
CURRENT_FOLDER=$(basename "$PWD")
PATH_TO_CA_CERT="/var/lib/docker/volumes/${CURRENT_FOLDER}_free2fa_ca_certs/_data/ca.crt"


# start service script
cat <<EOF >"$TEMP_FILE"
#!/bin/bash

#  Go to the directory with docker-compose.yml
cd "$CURRENT_DIR"
PATH_TO_CA_CERT=$PATH_TO_CA_CERT
# Starting Docker Compose
docker compose up -d

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
key_file_path=$key_file
EOF
cat <<'EOF' >>"$TEMP_FILE"
key=$(cat $key_file_path) # Reading a key from a file
data="{\"user_name\": \"key\", \"client_key\": \"$key\"}"
curl -s --cacert $PATH_TO_CA_CERT -X POST -H "Content-Type: application/json" -d "$data" https://localhost:5000/authenticate

echo "Docker Compose has been successfully started."

# Starting FreeRADIUS
service freeradius start
echo "FreeRADIUS has been successfully started."
EOF

cp "$TEMP_FILE" "$START_SERVICE"

chmod +x "$START_SERVICE"
# Deleting the temporary file
rm "$TEMP_FILE"

# Creating a temporary file
TEMP_FILE=$(mktemp)

# Write the stop services script to a temporary file.
cat <<EOF >"$TEMP_FILE"
#!/bin/bash

# Go to the directory with docker-compose.yml
cd "$CURRENT_DIR"

# Stopping Docker Compose
docker compose stop

# Stopping FreeRADIUS
service freeradius stop

echo "The services have been successfully stopped."
EOF

cp "$TEMP_FILE" "$STOP_SERVICE"

chmod +x "$STOP_SERVICE"
# Deleting the temporary file
rm "$TEMP_FILE"

# Creating a temporary file
TEMP_FILE=$(mktemp)

# Write the start services script to a temporary file.
cat <<EOF >"$TEMP_FILE"
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

cp "$TEMP_FILE" "$FREE2FA_SERVICE"

# Deleting the temporary file
rm "$TEMP_FILE"
systemctl stop freeradius
systemctl disable freeradius
systemctl enable free2fa.service

rm /etc/freeradius/3.0/sites-enabled/default

# Updating configuration files
sed -i "s/\"client_key\": \".*\"/\"client_key\": \"$random_key\"/" "$CONFIG_FILE_REST"
sed -i "s/start_servers = .*/start_servers = $RADIUS_START_SERVERS/" "$CONFIG_FILE_RADIUS"
sed -i "s/max_servers = .*/max_servers = $RADIUS_MAX_SERVERS/" "$CONFIG_FILE_RADIUS"
sed -i "s/max_spare_servers = .*/max_spare_servers = $RADIUS_MAX_SPARE_SERVERS/" "$CONFIG_FILE_RADIUS"
sed -i "s/min_spare_servers = .*/min_spare_servers = $RADIUS_MIN_SPARE_SERVERS/" "$CONFIG_FILE_RADIUS"
sed -i "s/destination = .*/destination = stdout/" "$CONFIG_FILE_RADIUS"
ensure_blastradius_security "$CONFIG_FILE_RADIUS"

echo "Configuration updated."

# Setting access rights to configuration files

chmod 440 "$CONFIG_FILE_REST" "$CONFIG_FILE_PAM" "$CONFIG_FILE_CACHE_FREE2FA_FAIL" "$CONFIG_FILE_CACHE_FREE2FA_BAN" "$CONFIG_FILE_LINELOG_GUARD" "$CONFIG_FILE_SITE" "$CHECK_GROUP_SCRIPT"
chown freerad:freerad "$CONFIG_FILE_REST" "$CONFIG_FILE_PAM" "$CONFIG_FILE_CACHE_FREE2FA_FAIL" "$CONFIG_FILE_CACHE_FREE2FA_BAN" "$CONFIG_FILE_LINELOG_GUARD" "$CONFIG_FILE_SITE" "$CHECK_GROUP_SCRIPT"

chmod +x "$CHECK_GROUP_SCRIPT"
ln -sf "$CONFIG_FILE_REST" "${ROOT_DIR}mods-enabled/rest"
ln -sf "$CONFIG_FILE_PAM" "${ROOT_DIR}mods-enabled/pam"
ln -sf "$CONFIG_FILE_SITE" "${ROOT_DIR}sites-enabled/$RADIUS_SITE_NAME"

if whiptail --yesno "Output the resulting configs to the console?" 10 60; then
    # If the user selected "Yes", output the contents of the configuration files
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    echo -e "\033[34mContent $SSSD_CONF:\033[0m \n"
    cat "$SSSD_CONF"
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    echo -e "\033[34mContent $CONFIG_FILE_KRB5:\033[0m \n"
    cat $CONFIG_FILE_KRB5
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    echo -e "\033[34mContent $CONFIG_FILE_RADIUS,\033[0m"
    echo -e "\033[34mOutput only the modified lines because the file is very large:\033[0m \n"
    grep -E "start_servers =|max_servers =|max_spare_servers =|min_spare_servers =" "$CONFIG_FILE_RADIUS"
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    echo -e "\033[34mContent $CONFIG_FILE_CLIENT:\033[0m \n"
    cat "$CONFIG_FILE_CLIENT"
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    echo -e "\033[34mContent $CONFIG_FILE_REST:\033[0m \n"
    cat "$CONFIG_FILE_REST"
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    echo -e "\033[34mContent $CONFIG_FILE_PAM:\033[0m\n"
    cat "$CONFIG_FILE_PAM"
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    echo -e "\033[34mContent ${ROOT_DIR}sites-available/$RADIUS_SITE_NAME:\033[0m \n"
    cat "${ROOT_DIR}sites-available/$RADIUS_SITE_NAME"
    printf '%*s\n' "${COLUMNS:-$(tput cols)}" '' | tr ' ' -
    read -n 1 -s -r -p "Press any key to continue..."
    echo ""
else
    # If the user selects "No", simply terminate the script
    echo "The output of the configuration files is omitted."
fi

# Run Docker Compose and FreeRADIUS?
if whiptail --yesno "Do you want to run Docker Compose and the FreeRADIUS service?" 10 60 --title "Starting Docker Compose and FreeRADIUS"; then
    # Running Docker Compose
    echo "Running Docker Compose..."
    if docker compose pull; then
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
\033[32mdocker compose logs -f\033[0m\n\n\
For accessing the FreeRADIUS logs, execute the following command:\n\
\033[32mcat /var/log/freeradius/radius.log\033[0m\n\n\
or you can see all logs in one window use the command:\n\
\033[32mtail -f /var/log/freeradius/radius.log & docker compose logs -f\n\n
\033[34mTo initiate FreeRADIUS in debug mode, ensure to stop the FreeRADIUS service first by executing:\n\
\033[32mservice freeradius stop\033[0m\n\
Then, to start FreeRADIUS in debug mode, enter:\n\
\033[32mfreeradius -Xx\033[0m\n"

