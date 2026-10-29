#!/usr/bin/env bash
# harden-victim.sh - Hardening script for the Attack-Detect-Harden lab (Ubuntu Server victim)
#
# Run ON THE VICTIM VM:   sudo bash harden-victim.sh
# Re-runnable (idempotent). Every config it touches is backed up first.
#
# SAFETY: password SSH login is only disabled if the lab user already has an
# SSH public key in ~/.ssh/authorized_keys. Set up the key BEFORE running
# (see notes/phase6-runbook.md), otherwise that step is skipped so you
# don't lock yourself out.

set -euo pipefail

LAB_USER="${LAB_USER:-labuser}"
SSH_PORT="${SSH_PORT:-22}"
BACKUP_DIR="/root/hardening-backup-$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/var/log/harden-victim.log"

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo bash $0" >&2
  exit 1
fi

if ! id "$LAB_USER" &>/dev/null; then
  echo "User '$LAB_USER' not found. Set LAB_USER=<name> and re-run." >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR"
exec > >(tee -a "$LOG_FILE") 2>&1

step() { echo; echo "=== [$(date +%T)] $* ==="; }
backup() { [[ -e "$1" ]] && cp -a "$1" "$BACKUP_DIR/$(echo "$1" | tr '/' '_')"; return 0; }

export DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------- 1. Packages
step "1. Install security packages"
apt-get update -y
apt-get install -y \
  ufw fail2ban unattended-upgrades apt-listchanges \
  libpam-pwquality libpam-tmpdir apt-show-versions debsums \
  auditd audispd-plugins
# --no-install-recommends: otherwise rkhunter can pull in a mail server that opens port 25
apt-get install -y --no-install-recommends rkhunter

# ---------------------------------------------------------------- 2. Firewall
step "2. Firewall (UFW): default deny inbound, allow SSH only"
# Outbound stays allowed so the Wazuh agent can reach the manager (1514/1515)
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw limit "${SSH_PORT}/tcp" comment 'SSH (rate limited)'
ufw logging low
ufw --force enable
ufw status verbose

# ---------------------------------------------------------------- 3. SSH
step "3. SSH hardening via drop-in config"
# NOTE: sshd uses the FIRST value it sees for a setting, and files in
# sshd_config.d are read in alphabetical order. Ubuntu cloud images often ship
# 50-cloud-init.conf with 'PasswordAuthentication yes', so ours is named 00-*
# so it wins.
mkdir -p /etc/ssh/sshd_config.d
backup /etc/ssh/sshd_config
SSH_DROPIN="/etc/ssh/sshd_config.d/00-hardening.conf"
backup "$SSH_DROPIN"

AUTH_KEYS="/home/${LAB_USER}/.ssh/authorized_keys"
if [[ -s "$AUTH_KEYS" ]]; then
  PASSWORD_AUTH="no"
  echo "SSH key found for $LAB_USER -> disabling password authentication."
else
  PASSWORD_AUTH="yes"
  echo "WARNING: no SSH key found at $AUTH_KEYS."
  echo "         Leaving PasswordAuthentication enabled to avoid a lockout."
  echo "         Set up the key (runbook), then re-run this script."
fi

cat > "$SSH_DROPIN" <<EOF
# Managed by harden-victim.sh
PermitRootLogin no
PasswordAuthentication ${PASSWORD_AUTH}
PermitEmptyPasswords no
PubkeyAuthentication yes
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
AllowUsers ${LAB_USER}
Banner /etc/issue.net
EOF
chmod 644 "$SSH_DROPIN"

# Legal-style warning banner (Lynis likes these)
backup /etc/issue
backup /etc/issue.net
BANNER_TEXT="Authorized access only. All activity may be monitored and logged."
echo "$BANNER_TEXT" > /etc/issue
echo "$BANNER_TEXT" > /etc/issue.net

# Validate BEFORE reloading; abort and restore on failure
if sshd -t; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd
  echo "sshd config valid and reloaded."
else
  echo "sshd config INVALID - removing drop-in." >&2
  rm -f "$SSH_DROPIN"
  exit 1
fi

# ---------------------------------------------------------------- 4. fail2ban
step "4. fail2ban: ban IPs that brute-force SSH"
backup /etc/fail2ban/jail.local
cat > /etc/fail2ban/jail.local <<EOF
# Managed by harden-victim.sh
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
# Add your own machine so you can't ban yourself during testing, e.g.:
# ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled  = true
port     = ${SSH_PORT}
backend  = systemd
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban
sleep 2
fail2ban-client status sshd || true

# ---------------------------------------------------------------- 5. Password policy
step "5. Password policy and aging"
backup /etc/security/pwquality.conf
cat > /etc/security/pwquality.conf <<'EOF'
# Managed by harden-victim.sh
minlen = 12
minclass = 3
maxrepeat = 3
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF

backup /etc/login.defs
set_login_def() {
  local key="$1" val="$2"
  if grep -qE "^\s*${key}\b" /etc/login.defs; then
    sed -i -E "s|^\s*${key}\b.*|${key}\t${val}|" /etc/login.defs
  else
    echo -e "${key}\t${val}" >> /etc/login.defs
  fi
}
set_login_def PASS_MAX_DAYS 90
set_login_def PASS_MIN_DAYS 1
set_login_def PASS_WARN_AGE 7
set_login_def UMASK 027
set_login_def SHA_CRYPT_MIN_ROUNDS 5000

# ---------------------------------------------------------------- 6. Kernel / network
step "6. Kernel and network hardening (sysctl)"
cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
# Managed by harden-victim.sh
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
sysctl --system >/dev/null
echo "sysctl settings applied."

# ---------------------------------------------------------------- 7. Misc
step "7. Disable core dumps and unused kernel modules"
cat > /etc/security/limits.d/99-no-core.conf <<'EOF'
* hard core 0
EOF

cat > /etc/modprobe.d/99-hardening.conf <<'EOF'
# Managed by harden-victim.sh - rarely needed on a server
install usb-storage /bin/true
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
EOF

# ---------------------------------------------------------------- 8. Auditd
step "8. auditd: log security-relevant events"
cat > /etc/audit/rules.d/99-hardening.rules <<'EOF'
# Managed by harden-victim.sh
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /var/log/auth.log -p wa -k authlog
EOF
systemctl enable --now auditd
augenrules --load >/dev/null 2>&1 || true

# ---------------------------------------------------------------- 9. Updates
step "9. Automatic security updates"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl enable --now unattended-upgrades

# ---------------------------------------------------------------- 10. File perms
step "10. Tighten file permissions"
chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
chmod 700 /root
chmod 644 /etc/passwd
chmod 640 /etc/shadow || true
if [[ -f /etc/crontab ]]; then chmod 600 /etc/crontab; fi

# ---------------------------------------------------------------- Summary
step "DONE"
echo "Backups:  $BACKUP_DIR"
echo "Log:      $LOG_FILE"
echo
echo "Quick verification:"
echo "  sudo ufw status verbose"
echo "  sudo sshd -T | grep -Ei 'passwordauthentication|permitrootlogin|maxauthtries|allowusers'"
echo "  sudo fail2ban-client status sshd"
echo "  sudo lynis audit system      # compare with baseline (index 66)"
echo
echo "REBOOT recommended so all settings take effect:  sudo reboot"
