## 10/27/2026 Phase 1
**What I did:** Built the "soclab" NAT network in VirtualBox, installed the victim Ubuntu VM, established ssh from my Kali attack VM

**What broke:** SSH was initially refused

**How I fixed it:** The SSH server wasn't installed on my fresh Ubuntu VM. Ran 'sudo apt install openssh-server'.

**What I learned:** "Connection refused" means the host is reachable, but nothing is listening on that port

**Next:** Install a Wazuh VM and configure it in Virtual Box 

## 10/27/2026 Phase 2
**What I did:** Imported a WazuhOVA into VirtualBox, put it on the "soclab" network, installed the Wazuh agent onto the victim-ubuntu VM

**What broke:** sudo kept refusing to run on my victim VM when I was trying to install the Wazuh package since my user didn't have admin privileges 

**How I fixed it:** Logged out of the lab's user account and into my admin account, used 'mount -o remount,rw /', 'usermod -aG sudo labuser', and 'passwd labuser' to give the account admin rights and reset the password

**What I learned:** The importance of security controls on different user accounts in a system, and what restrictions are automatically put on linux accounts

**Next:** Create a baseline using Lynis and Nmap

## 10/27/2026 Phase 3
**What I did:** 
- Installed Lynis on the victim Ubuntu VM and ran a full system audit, saving the output to 'lynis-baseline.txt'
- Ran an Nmap scan from Kali against he victim and saved it as 'nmap-baseline.txt'
- Checked the Wazuh Configuration Assessment (SCA) results for the victim agent, but there were none
- Copied the Lynis report from the victim to Kali using the command 'scp', then committed the reports to the GitHub repo

**What broke and how I fixed it:**
**'git push' rejected.** The GitHub repo wasn't empty (had a README), so my local history and the remote' were separate. Fix: forced a push overwrite since the repo was empty

**Baseline results (the 'Before' numbers):**
- Lynis hardening index: [66]
- Lynis warnings / suggestions: [0] / [35]
- Open ports (Nmap): [1]
- Wazuh SCA score [N/A]

**What I learned:**
- Including a baseline gives hardening a measurable before and after

**Next:** Attacking the victim from Kali and catching it in Wazuh

## 10/28/2026 Phase 4
**What I did:** 
- Ran an SSH brute force attack from Kali against the victim Ubuntu machine (port 22) using Hydra
- Confirmed Wazuh fired high severity alerts on every attempt
- Rule triggered: '[40112]' - "[Multiple authentication failures followed by a success.]" (Level 12)
- Source IP in the alert matched Kali's IP, confirming correct attribution
- Attack 1 - port scan ('nmap -sS -sV 10.0.2.3') 
- Attack 2 - Hydra brute force attempt ('hydra -l labuser -P passwords.txt ssh://10.0.2.3 -o ../reports/attack2-hydra.txt')
- Attack 3 - Successful SSH login after brute force 

**What broke:** 
- Wazuh couldn't detect API to connect to

**How I fixed it:**
- Restarted wazuh-manager from wazuh server OVA 

**What I learned:** 
- Wazuh's host-based agent reliably redetects brute-force attempts at the authentication layer. Each failed SSH attempt generated a 'medium severity' alert, after ultiple failed attempts it generated high severity alerts 
- MITRE ATT&CK Techniques: Valid Accounts (T1078), Brute Force (T1110), Sudo and Sudo Caching (T154 and 8.003), 

**Next:** Harden the victim machine

## 10/28/2026 Phase 5
**What I did:** 
- Used the 35 Lynis suggestions from the baseline to make scripts/harden-victim.sh
- Set up SSH key login from Kali before running the script so disabling password login wouldn't lock me out
- Took a pre-hardening snapshot of the victim Ubuntu VM before making the changes
- Changed the deliberately weak 'labuser' password after
- Hardening Applied: UFW deault-deny with rate-limited SSH, SSH hardening (key-only, no root 3 attempts, only 'labuser'), fail2ban, password policy and aging, expanded sysctl settings, auditd and process accounting, login banners, unused protocols and USB storage blocked, compilers restricted to root, automatic security updates
- Re-ran the attacks from Kali and re-measured: Lynis index: 66 to 82, suggestions: 35 to 26, brute-force result: fail
- Took a post hardening snapshot

**What Broke:** 
- 'scp': Kali doesn't run an SSH server by default, so when I tried to get the script from the victim machine there was nothing listening. To fix this, I instead pushed the file from Kali to the victim.

**What I learned:**
- The machine you connect to must be running an SSH server, so 'connection refused' means nothing is listening
- Set up key login and test it from a second terminal before disabling password login
- Some Lynis suggestions aren't worth fixing, so I'll document them as accepted risks
- Verification matters, so I checked each control after running the script to make sure everything matched what I intended

**Next:** Write the README, incident report, and before/after comparison

