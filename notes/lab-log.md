## 10/27/2026
**What I did:** Built the "soclab" NAT network in VirtualBox, installed the victim Ubuntu VM, established ssh from my Kali attack VM

**What broke:** SSH was initially refused
**How I fixed it:** The SSH server wasn't installed on my fresh Ubuntu VM. Ran 'sudo apt install openssh-server'.
**What I learned:** "Connection refused" means the host is reachable, but nothing is listening on that port
**Next:** Install a Wazuh VM and configure it in Virtual Box 

## 10/27/2026
**What I did:** Imported a WazuhOVA into VirtualBox, put it on the "soclab" network, installed the Wazuh agent onto the victim-ubuntu VM
**What broke:** sudo kept refusing to run on my victim VM when I was trying to install the Wazuh package since my user didn't have admin privilages 
**How I fixed it:** Logged out of the lab's user account and into my admin account, used 'mount -o remount,rw /', 'usermod -aG sudo labuser', and 'passwd labuser' to give the account admin rights and reset the password
**What I learned:** The importance of security controls on different user accounts in a system, and what restrictions are automatically put on linux accounts
**Next:** Create a baseline using Lynis and Nmap

## 10/27/2026
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
