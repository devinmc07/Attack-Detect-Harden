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
