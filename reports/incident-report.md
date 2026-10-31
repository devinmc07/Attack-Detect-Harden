# Incident Report: SSH Brute-Force Attack on Lab Server

> **Note:** this is a simulated incident from a controlled lab. The attacker (Kali) and the target (Ubuntu victim) are both my own VMs on the isolated `soclab` network.

| Field | Detail |
|---|---|
| Incident ID | LAB-001 |
| Date | [10/30/2026 |
| Severity | High (Wazuh alert level) Severity |
| Status | Resolved: hardening applied and re-tested |
| Reporter | devmcconk07 |

## 1. Summary

An SSH brute-force attack from the Kali VM against the Ubuntu victim (`victim-ubuntu`) was detected by Wazuh, which raised a high-severity alert on every attempt. The server was vulnerable because it used a weak password, allowed password-based SSH login, had no active firewall, and had nothing to rate-limit or ban repeated failures. After hardening, the same attack was blocked. SSH password login was disabled, only allowing SSH by key. Login attempts limited to 3. fail2ban installed and enabled. UFW firewall enabled.

## 2. Timeline

| Time | Event |
|---|---|
| 10/27/2026 | Baseline recorded: Lynis index 66, only port 22 open, UFW inactive |
| 10/28/2026 | Port scan from Kali against the victim |
| 10/28/2026 | Brute-force run started from Kali |
| 10/28/2026 | First Wazuh alert observed |
| 10/28/2026 | Successful login with the weak password |
| 10/29/2026 | Hardening script applied |
| 10/28/2026 | Attack re-run against the hardened server |
**Note:** In a real scenario, specific times would be provided, however since this is my first project, my log only tracked dates and not times.

## 3. Detection

| Item | Detail |
|---|---|
| Detection tool | Wazuh (agent `victim-ubuntu` to Wazuh manager) |
| Rule ID | T1110 |
| Rule description | Multiple authentication failures followed by a success |
| Alert level | 12 |
| Log source | '/screenshots/pre-hardening/Wazuh' alerts in depth.png |
| Source IP | 10.0.2.15 |
| Target | `victim-ubuntu`, SSH (port 22) |
| Alert frequency | Every attempt |

Evidence: `screenshots/pre-hardening`

## 4. Attack details

- **Method:** repeated SSH password guessing using Hydra
- **Wordlist / account targeted:** Simple 20 password list made just for this project / 'labuser'
- **Number of attempts:** 13
- **Outcome before hardening:** Weak password found followed by successful login

## 5. Impact assessment

In a real environment, a successful login would give an attacker an authenticated shell as a normal user, with a path to privilege escalation, data access and persistence. In this case, I was able to access anything on through the terminal that the user 'labuser' had access to.

## 6. Root cause

1. Weak account password
2. SSH password authentication enabled
3. No host firewall (UFW inactive)
4. No automatic banning or rate limiting of repeated failures
5. Unlimited authentication attempts per connection

## 7. Containment and remediation

Applied with `scripts/harden-victim.sh`:

| Root cause | Fix |
|---|---|
| Weak password | Password policy enforced; lab password replaced |
| Password SSH login | Disabled; key-based login only |
| No firewall | UFW default-deny inbound, SSH rate-limited |
| No banning | fail2ban: 5 failures in 10 minutes means a 1-hour ban |
| Unlimited attempts | `MaxAuthTries 3`, `LoginGraceTime 30`, only the lab user allowed |

## 8. Verification

| Test | Result before | Result after |
|---|---|---|
| SSH brute force from Kali | Successful | Unsuccessful and IP banned |
| Login with the old weak password | Successful | `Permission denied (publickey)` |
| Port scan | Port 22 open | Port 22 open |
| Wazuh visibility | Alerts raised | No alerts raised |

Evidence: `screenshots/post-hardening/ssh refusal from victim.png`

## 9. Lessons learned and recommendations

- Detection worked, but detection alone did not stop the attack; prevention controls were needed.
- Key-only SSH removes the entire password-guessing attack class.
- A firewall and fail2ban add depth even when SSH itself is configured correctly.
- Next step: Wazuh Active Response to block attackers automatically, and alerting on successful logins that follow a burst of failures.
