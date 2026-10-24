#!/usr/bin/env bash
set -u
set -o pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
umask 077
shopt -s nullglob

ask() {
    local answer
    read -r -p "$* [y/N]: " answer || exit 0
    [[ ${answer,,} == y || ${answer,,} == yes ]]
}

# Every backup keeps its original path underneath the private backup folder.
backup() {
    local file=$1
    SAVED="$BACKUP_DIR${file}.$(date +%H%M%S%N)"
    mkdir -p -- "$(dirname -- "$SAVED")" || return 1
    cp -a -- "$file" "$SAVED" || return 1
    printf '[+] Backup: %s\n' "$SAVED"
}

# Replace an active setting, or append it if missing. Comments stay comments.
set_value() {
    local file=$1 key=$2 value=$3 separator=${4:-' '} pattern
    pattern=${key//./\\.}
    if grep -Eiq "^[[:blank:]]*$pattern([[:blank:]]|=)" "$file"; then
        sed -i -E "s|^[[:blank:]]*$pattern([[:blank:]]*=[[:blank:]]*|[[:blank:]]+).*|$key$separator$value|I" "$file"
    else
        printf '\n%s%s%s\n' "$key" "$separator" "$value" >> "$file"
    fi
}

human_users() {
    # Includes low-UID accounts with a login shell, such as the hidden training user.
    awk -F: '$3 > 0 && $3 < 65534 && ($3 >= 1000 || $7 ~ /\/(bash|sh|dash|zsh|ksh|fish)$/) {print $1}' /etc/passwd
}

audit_users() {
    local user group file
    echo 'Use the README to decide who belongs here. Deleted accounts keep their home files.'
    echo 'UID 0 accounts (normally only root):'
    awk -F: '$3 == 0 {print "  " $1}' /etc/passwd
    for file in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do backup "$file" || return; done
    while IFS= read -r user; do
        [[ $user =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$ ]] || { echo "Review unusual account name: $user"; continue; }
        if [[ $user == "$MAIN_USER" ]]; then echo "[*] Keeping your current account: $user"; continue; fi
        printf '\nUser: %s | UID: %s | Groups: %s\n' "$user" "$(id -u "$user")" "$(id -nG "$user")"
        if ask "Would you like to delete user '$user'?"; then
            deluser "$user"
            continue
        fi
        if ask "Should '$user' be a sudo/administrator user?"; then
            usermod -aG sudo "$user"
        else
            for group in sudo admin; do
                if id -nG "$user" | tr ' ' '\n' | grep -Fxq "$group"; then gpasswd -d "$user" "$group"; fi
            done
        fi
    done < <(human_users)
    echo '[*] Custom sudoers grants are separate from sudo/admin group membership.'
}

audit_services() {
    local service
    local services=(nginx squid apache2 vsftpd ssh smbd nmbd samba-ad-dc
        postfix exim4 dovecot cups avahi-daemon bluetooth rsync rpcbind
        nfs-server nfs-kernel-server isc-dhcp-server isc-dhcp-server6
        bind9 dnsmasq snmpd slapd xinetd openbsd-inetd tftpd-hpa)
    echo 'Only disable services that the README does not require. SSH, Apache and FTP may be required.'
    systemctl list-unit-files --type=service > "$BACKUP_DIR/service-states-$(date +%H%M%S%N).txt"
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" || systemctl is-enabled --quiet "$service"; then
            if ask "Would you like to stop and disable '$service'?"; then systemctl disable --now "$service"; fi
        fi
    done
}

audit_packages() {
    local package
    local packages=(doona xprobe hydra hydra-gtk john hashcat ophcrack ophcrack-cli
        aircrack-ng nmap ncat netcat-traditional wireshark tshark sqlmap nikto
        gobuster dirb dirbuster hping3 medusa ettercap-text-only ettercap-graphical
        tcpdump dsniff netdiscover kismet wifite reaver crunch fcrackzip chntpw
        metasploit-framework beef-xss responder impacket-scripts x11vnc tightvncserver
        gnome-mahjongg gnome-sudoku gnome-mines aisleriot freeciv-server minetest
        endless-sky wesnoth hedgewars xbill bsdgames)
    echo 'These are review candidates. Keep tools needed by the README or unfinished forensics.'
    echo 'APT will show the proposed removals before asking you to confirm them.'
    dpkg-query -W > "$BACKUP_DIR/packages-before-$(date +%H%M%S%N).txt"
    for package in "${packages[@]}"; do
        if [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null) == 'install ok installed' ]]; then
            if ask "Would you like to remove package '$package'?"; then apt-get purge "$package"; fi
        fi
    done
}

ssh_ports() {
    local ports
    ports=$({ /usr/sbin/sshd -T 2>/dev/null | awk '$1 == "port" {print $2}'
              ss -ltnp 2>/dev/null | awk '/"sshd"/ {n=split($4,a,":"); print a[n]}'
              if [[ -n ${SSH_CONNECTION:-} ]]; then awk '{print $4}' <<< "$SSH_CONNECTION"; fi
            } | grep -E '^[0-9]+$' | sort -nu)
    printf '%s\n' "${ports:-22}"
}

configure_ufw() {
    local port extra range min max ftp_file=/etc/vsftpd.conf
    local -a ports=()
    if ! command -v ufw >/dev/null; then
        ask 'UFW is missing. Install it?' || return
        apt-get install ufw || return
    fi
    ufw status verbose
    ask 'Configure UFW: deny incoming, allow outgoing, and add required service rules?' || return
    backup /etc/ufw || return
    backup /etc/default/ufw || return
    # Allow SSH before changing defaults or enabling the firewall.
    if [[ -x /usr/sbin/sshd ]]; then
        while IFS= read -r port; do ufw allow "$port/tcp" || return; done < <(ssh_ports)
    fi
    if ask 'Does the README require a web server on ports 80 and 443?'; then
        ufw allow 80/tcp && ufw allow 443/tcp || return
    fi
    if ask 'Does the README require FTP?'; then
        port=21; range=''
        if [[ -f $ftp_file ]]; then
            extra=$(awk -F= '$1 == "listen_port" {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$ftp_file")
            [[ -z $extra ]] || port=$extra
            min=$(awk -F= '$1 == "pasv_min_port" {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$ftp_file")
            max=$(awk -F= '$1 == "pasv_max_port" {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$ftp_file")
            [[ ! $min =~ ^[0-9]+$ || ! $max =~ ^[0-9]+$ ]] || range="$min:$max"
        fi
        ufw allow "$port/tcp" || return
        read -r -p "FTP passive data range [$range] (example 40000:41000): " extra || return
        range=${extra:-$range}
        if [[ $range =~ ^[0-9]+:[0-9]+$ ]]; then
            ufw allow "$range/tcp" || return
        else
            echo '[!] A required FTP server needs working data-connection rules. Firewall defaults were not changed.'
            return
        fi
    fi
    read -r -p 'Other required ports (example 53/udp 8080/tcp), or Enter to skip: ' extra || return
    read -r -a ports <<< "$extra"
    for port in "${ports[@]}"; do
        [[ $port =~ ^[0-9]+(:[0-9]+)?/(tcp|udp)$ ]] || { echo "Invalid port: $port"; return; }
        ufw allow "$port" || return
    done
    ufw default deny incoming && ufw default allow outgoing && ufw logging low || return
    ufw show added
    if ask 'Enable UFW with these rules?'; then ufw --force enable; fi
    ufw status verbose
}

configure_ssh() {
    local file pair key value save i failed=no
    local main=/etc/ssh/sshd_config
    local -a files=("$main" /etc/ssh/sshd_config.d/*.conf) copies=()
    local -a settings=('PermitRootLogin no' 'PermitEmptyPasswords no' 'UsePAM yes'
        'StrictModes yes' 'IgnoreRhosts yes' 'HostbasedAuthentication no'
        'PermitUserEnvironment no' 'MaxAuthTries 3' 'LoginGraceTime 60' 'LogLevel VERBOSE')
    [[ -x /usr/sbin/sshd && -f $main ]] || { echo 'OpenSSH server is missing.'; return; }
    echo 'SSH preset: block direct root/empty-password logins, require PAM, and limit authentication attempts.'
    echo 'Current ports, password/key choices and SFTP configuration are kept.'
    ask 'Apply the basic SSH settings?' || return
    /usr/sbin/sshd -t || { echo 'Fix the existing SSH configuration first.'; return; }
    # This small module handles the main file and the usual Mint .conf snippets.
    for file in "${files[@]}"; do backup "$file" || return; copies+=("$SAVED"); done
    save="$BACKUP_DIR/ssh-main-new-$(date +%H%M%S%N)"
    { echo '# BEGIN ROUND1 SSH'
      printf '%s\n' "${settings[@]}"
      echo '# END ROUND1 SSH'
      sed '/^# BEGIN ROUND1 SSH$/,/^# END ROUND1 SSH$/d' "$main"
    } > "$save" || return
    cat "$save" > "$main" || failed=yes
    for file in "${files[@]}"; do
        for pair in "${settings[@]}"; do
            read -r key value <<< "$pair"
            # Replace existing overrides, including those within Match blocks.
            sed -i -E "s|^([[:blank:]]*)$key([[:blank:]]*=[[:blank:]]*|[[:blank:]]+).*|\1$key $value|I" "$file" || failed=yes
        done
        chown root:root "$file" && chmod 600 "$file" || failed=yes
    done
    if [[ $failed == no ]] && /usr/sbin/sshd -t; then
        if systemctl is-active --quiet ssh; then
            systemctl reload ssh || failed=yes
        elif ask 'SSH is stopped. Start it as required by the README?'; then
            systemctl start ssh || failed=yes
        fi
    else
        failed=yes
    fi
    if [[ $failed == yes ]]; then
        for i in "${!files[@]}"; do cp -a -- "${copies[i]}" "${files[i]}"; done
        systemctl is-active --quiet ssh && systemctl reload ssh
        echo '[!] SSH change failed; original configuration files were copied back. Check SSH status.'
    else
        echo '[+] SSH configuration accepted. Check a NEW authorized SSH login before closing this window.'
        /usr/sbin/sshd -T | grep -E '^(permitrootlogin|permitemptypasswords|passwordauthentication|usepam|maxauthtries) '
    fi
}

configure_apache() {
    local file=/etc/apache2/conf-available/security.conf old enabled=no failed=no
    [[ -f $file ]] && command -v apache2ctl >/dev/null || { echo 'Apache2 security.conf is missing.'; return; }
    ask 'Set Apache FileETag None, ServerTokens Prod and ServerSignature Off?' || return
    backup "$file" || return
    old=$SAVED
    [[ ! -e /etc/apache2/conf-enabled/security.conf ]] || enabled=yes
    set_value "$file" FileETag None && set_value "$file" ServerTokens Prod &&
        set_value "$file" ServerSignature Off && a2enconf security && apache2ctl configtest || failed=yes
    if [[ $failed == no ]] && systemctl is-active --quiet apache2; then systemctl reload apache2 || failed=yes; fi
    if [[ $failed == yes ]]; then
        cp -a -- "$old" "$file"
        [[ $enabled == yes ]] || a2disconf security
        if systemctl is-active --quiet apache2; then apache2ctl configtest && systemctl reload apache2; fi
        echo '[!] Apache rejected the change; its previous security.conf was copied back.'
    else
        echo '[+] Apache security.conf updated. If Apache is stopped, this did not start it.'
    fi
}

password_ages() {
    local user expiry normalized
    echo 'Password age and account expiration are separate. Account expiration disables the whole account.'
    echo 'A 90-day password age is measured from the last password change; old passwords may expire immediately.'
    backup /etc/shadow || return
    while IFS= read -r user; do
        [[ $user =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$ ]] || continue
        ask "Review password ages and account expiration for '$user'?" || continue
        chage -l "$user"
        if ask 'Set minimum 1 day, maximum 90 days and warning 7 days?'; then chage -m 1 -M 90 -W 7 "$user"; fi
        read -r -p 'Account expires on YYYY-MM-DD, "never", or Enter to keep its current date: ' expiry || return
        case $expiry in
            '') ;;
            never) chage -E -1 "$user" ;;
            *) normalized=$(date -d "$expiry" +%F 2>/dev/null)
               if [[ $expiry =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ && $normalized == "$expiry" ]]; then
                   chage -E "$expiry" "$user"
               else echo '[!] Invalid date; account expiration was kept.'; fi ;;
        esac
    done < <(human_users)
}

configure_login_defs() {
    local file=/etc/login.defs
    echo 'New-account password defaults: age 1/90 days, warning 7 days. Login UMASK: 027.'
    echo 'Use menu option 7 to change existing users.'
    ask 'Apply these login.defs defaults?' || return
    backup "$file" || return
    set_value "$file" PASS_MIN_DAYS 1 && set_value "$file" PASS_MAX_DAYS 90 &&
        set_value "$file" PASS_WARN_AGE 7 && set_value "$file" UMASK 027 && echo '[+] login.defs updated.'
}

remove_nullok() {
    local file=/etc/pam.d/common-auth
    ask 'Remove nullok / nullok_secure from active pam_unix authentication lines?' || return
    backup "$file" || return
    sed -i -E '/^[[:blank:]]*auth[[:blank:]].*pam_unix\.so/ {
        :again
        s/[[:blank:]]+nullok(_secure)?([[:blank:]]|$)/\2/
        t again
    }' "$file" && echo '[+] Blank-password PAM options removed.'
}

enable_syn_cookies() {
    ask 'Enable IPv4 TCP SYN cookies now and in /etc/sysctl.conf?' || return
    backup /etc/sysctl.conf || return
    set_value /etc/sysctl.conf net.ipv4.tcp_syncookies 1 ' = ' &&
        sysctl -w net.ipv4.tcp_syncookies=1
}

find_media() {
    local file
    echo 'Searching /home for OGG, MP4 and MP3 files. Check forensics before deleting evidence.'
    while IFS= read -r -d '' file; do
        printf '\nFound: %q\n' "$file"
        if ask 'Would you like to back up and delete this file?'; then
            backup "$file" && rm -- "$file"
        fi
    done < <(find /home -type f \( -iname '*.ogg' -o -iname '*.mp4' -o -iname '*.mp3' \) -print0)
}

update_packages() {
    ask 'Run apt-get update, then apt-get upgrade?' || return
    echo 'Review the APT prompts. For config-file replacements, N normally keeps your current configuration.'
    apt-get update && apt-get upgrade
}

if (( EUID != 0 )); then echo 'Run: sudo bash ~/Downloads/round1.sh'; exit 1; fi
MAIN_USER=${SUDO_USER:-$(logname 2>/dev/null || echo root)}
BACKUP_DIR=$(mktemp -d /var/backups/round1-XXXXXXXX) || exit 1
SAVED=''
echo 'SIMPLE ROUND ONE HELPER'
echo 'Run from the VM desktop. Read the current README and finish relevant forensics first.'
echo "Backups: $BACKUP_DIR"
while :; do
    cat <<'MENU'

 1) Audit users and sudo/admin membership
 2) Audit services
 3) Review unwanted packages
 4) Configure UFW
 5) Configure SSH
 6) Configure Apache2 (three settings)
 7) Password ages and account expiration dates
 8) Configure /etc/login.defs
 9) Remove nullok from /etc/pam.d/common-auth
10) Enable IPv4 TCP SYN cookies
11) Find and review OGG / MP4 / MP3 files in /home
12) APT update and upgrade
 0) Exit
MENU
    read -r -p 'Choose a number: ' choice || break
    case $choice in
        1) audit_users ;; 2) audit_services ;; 3) audit_packages ;; 4) configure_ufw ;;
        5) configure_ssh ;; 6) configure_apache ;; 7) password_ages ;; 8) configure_login_defs ;;
        9) remove_nullok ;; 10) enable_syn_cookies ;; 11) find_media ;; 12) update_packages ;;
        0) break ;; *) echo 'Choose a number from the menu.' ;;
    esac
done
