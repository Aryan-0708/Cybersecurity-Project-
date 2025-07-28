# Linux Hardening Audit Tool

##  Description
This is a Python-based Linux security auditing tool developed to evaluate the system's basic hardening measures and generate a report with a security score.

##  Tools Used
- Python 3
- UFW (Firewall)
- chkrootkit
- chage
- systemctl
- find, ls, awk, etc.

## Features Implemented
- Firewall status check
- SSH configuration check
- File permission analysis
- Detection of unused services
- Rootkit scan
- World writable file check
- Password expiry policy check
- Sudoers configuration check
- Active ports and connections scan
- Security recommendations
- Scoring system out of 100

##  How to Run
```bash
chmod +x audit.py
sudo python3 audit.py
