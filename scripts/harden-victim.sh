#!/usr/bin/env bash
# harden-victim.sh - Hardening script for the Attack-Detect-Harden lab (Ubuntu Server victim)
#
# Run ON THE VICTIM VM:   sudo bash harden-victim.sh
# Re-runnable (idempotent). Every config it touches is backed up first.
#
# Built from the Lynis baseline (35 suggestions, hardening index 66).
# Each section header lists the Lynis control IDs it addresses.
# Controls deliberately NOT addressed are listed at the bottom of this file.
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
# Lynis: DEB-0280 (libpam-tmpdir), DEB-0811 (apt-listchanges), DEB-0880 (fail2ban),
#        PKGS-7370 (debsums), PKGS-7394 (apt-show-versions), AUTH-9262 (pwquality),
#        ACCT-9628 (auditd), ACCT-9622 (acct)
step "1. Install security packages"
apt-get update -y
apt-get install -y \
  ufw fail2ban unattended-upgrades apt-listchanges \
  libpam-pwquality libpam-tmpdir apt-show-versions debsums \
  auditd audispd-plugins acct
# --no-install-recommends: otherwise rkhunter can pull in a mail server that opens port 25
apt-get install -y --no-install-recommends rkhunter

# ---------------------------------------------------------------- 2. Firewall
# Lynis: FIRE-4590
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
# Not a numbered Lynis suggestion in the baseline, but closes the brute-force
# path used in Phase 5. Also sets the login banner (BANN-7126, BANN-7130).
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

# Legal-style warning banner
backup /etc/issue
backup /etc/issue.net
BANNER_TEXT="Authorized access only. All activity may be monitored and logged."
echo "$BANNER_TEXT" > /etc/issue
echo "$BANNER_TEXT" > /etc/issue.net

# Validate BEFORE reloading; abort and remove drop-in on failure
if sshd -t; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd
  echo "sshd config valid and reloaded."
else
  echo "sshd config INVALID - removing drop-in." >&2
  rm -f "$SSH_DROPIN"
  exit 1
fi

# ---------------------------------------------------------------- 4. fail2ban
# Lynis: DEB-0880
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

# ---------------------------------------------------------------- 5. Passwords and accounts
# Lynis: AUTH-9229, AUTH-9230 (hash rounds), AUTH-9262 (pwquality), AUTH-9282 (account expiry),
#        AUTH-9286 (min/max age), AUTH-9328 (umask)
step "5. Password policy, hashing rounds, aging and umask"
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
set_login_def SHA_CRYPT_MIN_ROUNDS 10000
set_login_def SHA_CRYPT_MAX_ROUNDS 65536

# login.defs only affects NEW accounts, so apply aging to existing human users
# (UID 1000+). Account expiry is set 1 year out - RENEW IT before then with:
#   sudo chage -E $(date -d '+365 days' +%F) <user>
ACCOUNT_EXPIRY="$(date -d '+365 days' +%F)"
while IFS=: read -r user _ uid _; do
  if (( uid >= 1000 && uid < 65534 )); then
    chage -M 90 -m 1 -W 7 -E "$ACCOUNT_EXPIRY" "$user"
    echo "Password aging applied to $user (account expires $ACCOUNT_EXPIRY)."
  fi
done < /etc/passwd

echo "REMINDER: change the lab user's weak password after this script finishes:  passwd $LAB_USER"

# ---------------------------------------------------------------- 6. Kernel / network
# Lynis: KRNL-6000
step "6. Kernel and network hardening (sysctl)"
cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
# Managed by harden-victim.sh
# --- Network ---
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
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.conf.all.mc_forwarding = 0
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# --- Kernel ---
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.ctrl-alt-del = 0
kernel.core_uses_pid = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 1
net.core.bpf_jit_harden = 2
dev.tty.ldisc_autoload = 0
# --- Filesystem ---
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF
# Some keys may not exist on every kernel; one missing key must not stop the script
sysctl --system >/dev/null || echo "WARNING: some sysctl keys could not be applied (check: sudo sysctl --system)"
echo "sysctl settings applied."

# ---------------------------------------------------------------- 7. Core dumps, modules, protocols
# Lynis: USB-1000 (usb-storage), NETW-3200 (dccp, sctp, rds, tipc)
step "7. Disable core dumps, USB storage, and unused kernel modules/protocols"
cat > /etc/security/limits.d/99-no-core.conf <<'EOF'
* hard core 0
EOF

cat > /etc/modprobe.d/99-hardening.conf <<'EOF'
# Managed by harden-victim.sh - rarely needed on a server
blacklist usb-storage
install usb-storage /bin/true
# Unused filesystems
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
# Unused network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

# ---------------------------------------------------------------- 8. Auditing and accounting
# Lynis: ACCT-9628 (auditd), ACCT-9622 (process accounting)
step "8. auditd and process accounting"
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

# Process accounting (the service is named acct on Ubuntu, psacct on some others)
systemctl enable --now acct 2>/dev/null \
  || systemctl enable --now psacct 2>/dev/null \
  || echo "WARNING: could not enable process accounting service"

# ---------------------------------------------------------------- 9. Updates
# Lynis: DEB-0811, PKGS-7394 (patch management tooling)
step "9. Automatic security updates"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl enable --now unattended-upgrades

# ---------------------------------------------------------------- 10. File permissions
# Lynis: FILE-7524
step "10. Tighten file permissions"
chmod 600 /etc/ssh/sshd_config 2>/dev/null || true
chmod 700 /root
chmod 644 /etc/passwd
chmod 640 /etc/shadow || true
if [[ -f /etc/crontab ]]; then chmod 600 /etc/crontab; fi
for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  if [[ -d "$d" ]]; then chmod 700 "$d"; fi
done
# NOTE: update-grub may reset this file's permissions; re-run this script after kernel updates
if [[ -f /boot/grub/grub.cfg ]]; then chmod 600 /boot/grub/grub.cfg; fi

# ---------------------------------------------------------------- 11. Compilers
# Lynis: HRDN-7222 - only root should be able to run compilers/assemblers
step "11. Restrict compilers to root"
for bin in as cc c++ gcc g++ clang; do
  path="$(command -v "$bin" || true)"
  if [[ -n "$path" ]]; then
    real="$(readlink -f "$path")"
    chown root:root "$real"
    chmod 750 "$real"
    echo "Restricted: $real"
  fi
done

# ---------------------------------------------------------------- Summary
step "DONE"
echo "Backups:  $BACKUP_DIR"
echo "Log:      $LOG_FILE"
echo
echo "Manual follow-ups:"
echo "  1. passwd $LAB_USER                  # replace the deliberately weak password"
echo "  2. sudo reboot                        # applies all settings; also clears LOGG-2190"
echo
echo "Quick verification:"
echo "  sudo ufw status verbose"
echo "  sudo sshd -T | grep -Ei 'passwordauthentication|permitrootlogin|maxauthtries|allowusers'"
echo "  sudo fail2ban-client status sshd"
echo "  sudo lynis audit system      # compare with baseline (index 66, 35 suggestions)"

# ================================================================ NOT ADDRESSED (accepted / informational)
# Document these in the final report as accepted risks or out of scope.
#
#  DEB-0810   apt-listbugs      - Queries the DEBIAN bug tracker, not Ubuntu's, and can
#                                 block unattended apt runs with interactive prompts.
#  BOOT-5122  GRUB password     - Needs an interactive password hash; a mistake can leave the
#                                 VM unbootable. Physical/console access is outside this lab's
#                                 threat model (the VM is on an isolated network).
#  BOOT-5180  Runlevel/services - Informational only; no fix required.
#  BOOT-5264  systemd hardening - Per-service sandboxing; future work
#                                 (systemd-analyze security SERVICE).
#  FILE-6310  /home and /var on separate partitions (x2)
#                               - Cannot be changed on an installed system without repartitioning.
#  NAME-4028  DNS domain name   - Low value for a standalone lab VM.
#  LOGG-2154  External log host - Mitigated differently: the Wazuh agent already ships logs
#                                 to the Wazuh manager.
#  LOGG-2190  Deleted files still in use - Cleared by the reboot after package updates.
#  TOOL-5002  Automation tools  - Informational (Ansible/Puppet); this script is the automation.
#  Also left out on purpose: kernel.modules_disabled=1 (would block loading any kernel module
#  until reboot and can break networking/VirtualBox features).
