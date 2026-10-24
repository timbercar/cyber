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

strip_nullok() {
    local file=/etc/pam.d/common-auth
    sed -i -E '/^[[:blank:]]*auth[[:blank:]].*pam_unix\.so/ {
        :again
        s/[[:blank:]]+nullok(_secure)?([[:blank:]]|$)/\2/
        t again
    }' "$file"
}

remove_nullok() {
    ask 'Remove nullok / nullok_secure from active pam_unix authentication lines?' || return
    backup /etc/pam.d/common-auth || return
    strip_nullok && echo '[+] Blank-password PAM options removed.'
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

# PAM manages login/password rules. Keep its files and bookkeeping together.
snapshot_pam() {
    backup /etc/pam.d || return
    PAM_SAVE=$SAVED
    PAM_STATE=''
    if [[ -d /var/lib/pam ]]; then backup /var/lib/pam || return; PAM_STATE=$SAVED; fi
}

restore_pam() {
    cp -a -- "$PAM_SAVE/." /etc/pam.d/ || return
    if [[ -n $PAM_STATE ]]; then cp -a -- "$PAM_STATE/." /var/lib/pam/ || return; fi
    echo '[!] Previous PAM files were copied back. Keep this terminal open and check a new login.'
}

password_strength() {
    local file=/etc/pam.d/common-password config=/etc/security/pwquality.conf pair key value old_config=''
    echo 'Require 12+ characters when setting a NEW password, including when an administrator sets it.'
    echo 'Keep this terminal open until you have checked another login.'
    ask 'Configure password strength? (Installs libpam-pwquality if needed.)' || return
    snapshot_pam || return
    if [[ $(dpkg-query -W -f='${Status}' libpam-pwquality 2>/dev/null) != 'install ok installed' ]]; then
        apt-get install libpam-pwquality || { restore_pam; return; }
    fi
    if [[ ! -f /usr/share/pam-configs/pwquality ]]; then echo '[!] Password quality profile is missing.'; return; fi
    # Let the PAM tool calculate module ordering; never force over custom stacks.
    if ! DEBIAN_FRONTEND=noninteractive pam-auth-update --enable pwquality; then restore_pam; return; fi
    if ! awk '
        /^[ \t]*password[ \t]/ && /pam_pwquality\.so/ {count++; quality=NR; ok=($2=="requisite" || $2=="required")}
        /^[ \t]*password[ \t]/ && /pam_unix\.so/ {unix=NR; token=($0 ~ /[ \t]use_authtok([ \t]|$)/)}
        END {exit !(count==1 && ok && quality<unix && token)}' "$file"; then
        echo '[!] A custom password stack needs your captain. Password policy activation was not confirmed.'
        restore_pam
        return
    fi
    if [[ -f $config ]]; then backup "$config" || return; old_config=$SAVED; else touch "$config" || return; fi
    # Preserve a stricter existing minimum and negative credit requirements.
    local minimum=12 current
    current=$(awk -F= '/^[ \t]*minlen[ \t]*=/ {gsub(/[ \t]/,"",$2); sub(/#.*/,"",$2); print $2; exit}' "$config")
    if [[ $current =~ ^[0-9]{1,3}$ ]] && (( 10#$current > minimum )); then minimum=$((10#$current)); fi
    while IFS= read -r current; do
        if [[ $current =~ ^[0-9]{1,3}$ ]] && (( 10#$current > minimum )); then minimum=$((10#$current)); fi
    done < <(awk '/^[ \t]*password[ \t]/ && /pam_pwquality\.so/ {for(i=1;i<=NF;i++) if($i ~ /^minlen=/) {split($i,a,"=");print a[2]}}' "$file")
    set_value "$config" minlen "$minimum" ' = ' && set_value "$config" enforcing 1 ' = ' || return
    for key in dcredit ucredit lcredit ocredit; do
        current=$(awk -F= -v key="$key" '$1 ~ "^[[:blank:]]*"key"[[:blank:]]*$" {gsub(/[ \t]/,"",$2);sub(/#.*/,"",$2);print $2;exit}' "$config")
        if [[ $current =~ ^\+?[0-9]+$ ]]; then set_value "$config" "$key" 0 ' = ' || return; fi
    done
    if awk -v minimum="$minimum" '
        /^[ \t]*password[ \t]/ && /pam_pwquality\.so/ {
            line=""
            for(i=1;i<=NF;i++) {
                if($i ~ /^(minlen|retry|enforcing)=/ || $i=="enforce_for_root") continue
                option=$i
                if(option ~ /^[dulo]credit=\+?[0-9]+$/) {split(option,a,"=");option=a[1]"=0"}
                line=line (line=="" ? "" : " ") option
            }
            print line " retry=3 minlen="minimum" enforcing=1 enforce_for_root";next
        }
        {print}' "$file" > "$BACKUP_DIR/password-new" && cat "$BACKUP_DIR/password-new" > "$file" && strip_nullok; then
        echo "[+] Minimum $minimum characters configured for new passwords; existing passwords were not reset."
    else
        restore_pam
        [[ -z $old_config ]] || cp -a -- "$old_config" "$config"
    fi
}

account_lockout() {
    local file=/etc/pam.d/common-auth config=/etc/security/faillock.conf old_config='' profile
    local -a profiles=(round1-lockout-before round1-lockout-fail round1-lockout-success)
    echo 'Five failed logins within 15 minutes will temporarily block an account for 15 minutes.'
    echo 'Keep this administrator terminal open until you have checked another login.'
    ask 'Configure temporary account lockout?' || return
    if [[ -z $(find /usr/lib /lib -name pam_faillock.so -type f -print -quit 2>/dev/null) ]]; then
        echo '[!] pam_faillock is missing. Ask your captain to check libpam-modules.'; return
    fi
    snapshot_pam || return
    if grep -Eq '^[[:blank:]]*auth[[:blank:]].*pam_faillock\.so' "$file"; then
        if ! grep -Eq '^[[:blank:]]*auth[[:blank:]].*pam_faillock\.so.*authfail' "$file" ||
           ! grep -Eq '^[[:blank:]]*auth[[:blank:]].*pam_faillock\.so.*preauth' "$file" ||
           ! { grep -Eq '^[[:blank:]]*auth[[:blank:]].*pam_faillock\.so.*authsucc' "$file" ||
               grep -Eq '^[[:blank:]]*account[[:blank:]].*pam_faillock\.so' /etc/pam.d/common-account; }; then
            echo '[!] An incomplete/custom lockout stack needs your captain. Nothing was changed.'; return
        fi
    fi
    if grep -Eq '^[[:blank:]]*(auth|account)[[:blank:]].*pam_faillock\.so.*[[:blank:]]conf=' "$file" /etc/pam.d/common-account; then
        echo '[!] A separate lockout configuration is in use. Ask your captain to review it.'; return
    fi
    if [[ -f $config ]]; then backup "$config" || return; old_config=$SAVED; else touch "$config" || return; fi
    set_value "$config" deny 5 ' = ' && set_value "$config" fail_interval 900 ' = ' &&
        set_value "$config" unlock_time 900 ' = ' || return
    if ! grep -Eq '^[[:blank:]]*auth[[:blank:]].*pam_faillock\.so' "$file"; then
        for profile in "${profiles[@]}"; do
            if [[ -f /usr/share/pam-configs/$profile ]]; then backup "/usr/share/pam-configs/$profile" || return; fi
        done
        cat > /usr/share/pam-configs/round1-lockout-before <<'PAM'
Name: Round1 temporary lockout check
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
        requisite pam_faillock.so preauth silent
PAM
        cat > /usr/share/pam-configs/round1-lockout-fail <<'PAM'
Name: Round1 count failed logins
Default: no
Priority: 0
Auth-Type: Primary
Auth:
        [default=die] pam_faillock.so authfail
PAM
        cat > /usr/share/pam-configs/round1-lockout-success <<'PAM'
Name: Round1 clear failures after login
Default: no
Priority: 0
Auth-Type: Additional
Auth:
        required pam_faillock.so authsucc
PAM
        if ! DEBIAN_FRONTEND=noninteractive pam-auth-update --enable "${profiles[@]}"; then
            restore_pam; [[ -z $old_config ]] || cp -a -- "$old_config" "$config"; return
        fi
    fi
    if ! grep -Eq '^[[:blank:]]*auth[[:blank:]].*pam_faillock\.so.*authfail' "$file" ||
       ! grep -Eq '^[[:blank:]]*auth[[:blank:]].*pam_faillock\.so.*preauth' "$file" ||
       ! { grep -Eq '^[[:blank:]]*auth[[:blank:]].*pam_faillock\.so.*authsucc' "$file" ||
           grep -Eq '^[[:blank:]]*account[[:blank:]].*pam_faillock\.so' /etc/pam.d/common-account; }; then
        echo '[!] Lockout activation was not confirmed. A custom PAM stack needs review.'
        restore_pam; [[ -z $old_config ]] || cp -a -- "$old_config" "$config"; return
    fi
    # Existing inline options override faillock.conf, so align those limits too.
    for file in /etc/pam.d/common-auth /etc/pam.d/common-account; do
        sed -i -E '/^[[:blank:]]*(auth|account)[[:blank:]].*pam_faillock\.so/ {
            s/(^|[[:blank:]])deny=[0-9]+/\1deny=5/g
            s/(^|[[:blank:]])fail_interval=[0-9]+/\1fail_interval=900/g
            s/(^|[[:blank:]])unlock_time=[0-9]+/\1unlock_time=900/g
        }' "$file" || { restore_pam; return; }
    done
    strip_nullok || { restore_pam; return; }
    echo '[+] Temporary lockout configured. Check a fresh successful login before closing this terminal.'
}

blank_passwords() {
    local user found=no
    backup /etc/shadow || return
    while IFS= read -r user; do
        found=yes
        [[ $user =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$ ]] || continue
        printf '\n[!] Empty password: %s\n' "$user"
        if [[ $user == root ]]; then
            if ask 'Lock the root PASSWORD and continue administering through your normal sudo account?'; then passwd -l root; fi
        elif ask "Set a password for '$user'?"; then
            passwd "$user"
        fi
    done < <(awk -F: '$2=="" {print $1}' /etc/shadow)
    [[ $found == yes ]] || echo '[+] No empty local password fields were found.'
}

manage_groups() {
    local group names user
    local -a members=()
    read -r -p 'Group name from the README (Enter to cancel): ' group || return
    [[ -n $group ]] || return
    [[ $group =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$ ]] || { echo 'Invalid group name.'; return; }
    case $group in root|sudo|admin) echo 'Use user auditing (option 1) to review administrators.'; return ;; esac
    backup /etc/group && backup /etc/gshadow || return
    if ! getent group "$group" >/dev/null; then
        ask "Create group '$group'?" || return
        groupadd "$group" || return
    fi
    getent group "$group"
    read -r -p 'Usernames to ADD, separated by spaces (Enter to skip): ' names || return
    read -r -a members <<< "$names"
    for user in "${members[@]}"; do
        if [[ $user =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$ ]] && getent passwd "$user" >/dev/null; then
            gpasswd -a "$user" "$group"
        else echo "Unknown/invalid username: $user"; fi
    done
    while IFS= read -r user; do
        [[ -n $user ]] || continue
        if ask "Remove '$user' from group '$group'?"; then gpasswd -d "$user" "$group"; fi
    done < <(getent group "$group" | cut -d: -f4 | tr ',' '\n')
    echo '[+] Current group:'
    getent group "$group"
}

secure_permissions() {
    local file
    echo 'Restore standard ownership/permissions for account files and the main sudo configuration.'
    ask 'Apply these file permissions?' || return
    for file in /etc/passwd /etc/group /etc/shadow /etc/gshadow; do backup "$file" || return; done
    chown root:root /etc/passwd /etc/group && chmod 644 /etc/passwd /etc/group || return
    chown root:shadow /etc/shadow /etc/gshadow && chmod 640 /etc/shadow /etc/gshadow || return
    if [[ -f /etc/sudoers ]]; then
        backup /etc/sudoers || return
        chown root:root /etc/sudoers && chmod 440 /etc/sudoers || return
        visudo -c || { echo '[!] Sudoers contains an error that needs review.'; return; }
    fi
    echo '[+] Account file permissions updated.'
}

review_activity() {
    local pid user report="$BACKUP_DIR/listeners-and-scheduled-tasks.txt"
    {
        echo '=== Programs accepting network connections ==='
        ss -lntup
        echo '=== Full commands for those listening programs ==='
        while IFS= read -r pid; do ps -p "$pid" -o pid,user,args; done < <(
            ss -lntup | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -nu)
        echo '=== System scheduled commands ==='
        for user in /etc/crontab /etc/cron.d/*; do
            [[ -f $user ]] || continue
            printf '\nFile: %s\n' "$user"; cat -- "$user"
        done
        echo '=== Per-user scheduled commands ==='
        while IFS= read -r user; do
            printf '\nAccount: %s\n' "$user"; crontab -u "$user" -l 2>/dev/null
        done < <(printf 'root\n'; human_users)
        echo '=== System timers ==='
        systemctl list-timers --all --no-pager
    } | tee "$report"
    echo "[+] Review saved to: $report"
    echo 'An unfamiliar program is not automatically malicious. Compare with the README or show your captain.'
}

review_archives() {
    local file
    echo 'Review software archives in user/download locations. Keep authorized files and forensic evidence.'
    while IFS= read -r -d '' file; do
        printf '\nArchive: %q\n' "$file"
        if ask 'Back up and remove this unauthorized archive?'; then backup "$file" && rm -- "$file"; fi
    done < <(find /home /opt /usr/local /usr/games /tmp -type f \( -iname '*.zip' -o -iname '*.7z' -o -iname '*.rar' -o -iname '*.tgz' -o -iname '*.tar.gz' \) -print0 2>/dev/null)
}

guided_walkthrough() {
    local section reply
    echo 'Each section explains its purpose and asks before changing anything.'
    echo 'Use the README for decisions about authorized users, groups, services and files.'
    for section in audit_users password_strength account_lockout blank_passwords manage_groups \
        configure_login_defs password_ages remove_nullok secure_permissions enable_syn_cookies \
        audit_services audit_packages configure_ufw configure_ssh configure_apache find_media \
        review_archives update_packages review_activity; do
        "$section"
        read -r -p 'Press Enter for the next section, or type q to stop the walkthrough: ' reply || return
        [[ ${reply,,} != q ]] || return
    done
}

if (( EUID != 0 )); then echo 'Run: sudo bash ~/Downloads/round1.sh'; exit 1; fi
MAIN_USER=${SUDO_USER:-$(logname 2>/dev/null || echo root)}
BACKUP_DIR=$(mktemp -d /var/backups/round1-XXXXXXXX) || exit 1
SAVED=''
echo 'Run from the VM desktop. Read the current README and finish relevant forensics first.'
echo "Backups: $BACKUP_DIR"
echo 'New to Linux? Choose 20 for a guided walkthrough, or choose a section below.'
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
13) Require stronger NEW passwords (minimum 12 characters)
14) Temporary lockout after failed logins
15) Find empty passwords / lock a blank root password
16) Create groups and review their members
17) Fix sensitive account-file permissions
18) Review listening programs and scheduled tasks
19) Find and review software archives
20) Guided walkthrough (asks before changes)
 0) Exit
MENU
    read -r -p 'Choose a number: ' choice || break
    case $choice in
        1) audit_users ;; 2) audit_services ;; 3) audit_packages ;; 4) configure_ufw ;;
        5) configure_ssh ;; 6) configure_apache ;; 7) password_ages ;; 8) configure_login_defs ;;
        9) remove_nullok ;; 10) enable_syn_cookies ;; 11) find_media ;; 12) update_packages ;;
        13) password_strength ;; 14) account_lockout ;; 15) blank_passwords ;; 16) manage_groups ;;
        17) secure_permissions ;; 18) review_activity ;; 19) review_archives ;;
        20) guided_walkthrough ;;
        0) break ;; *) echo 'Choose a number from the menu.' ;;
    esac
done
