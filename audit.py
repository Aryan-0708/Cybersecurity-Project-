# Linux Hardening Audit Tool

# Date: 7 July 2025 

import subprocess
import os
import datetime

print("Linux hardening audit tool starting...")

score = 0

# 1. Firewall status
def check_firewall():
    global score
    result = "\n[+] Checking Firewall Status:\n"
    status = subprocess.getoutput("sudo ufw status")
    result += status + "\n"
    if "active" in status.lower():
        score += 10
        result += "[Pass] Firewall is active\n"
    else:
        result += "[Fail] Firewall is inactive\n"
    return result

# 2. SSH settings
def check_ssh_settings():
    global score
    result = "\n[+] Checking SSH configuration:\n"
    sshd_config = subprocess.getoutput("cat /etc/ssh/sshd_config")
    if "PermitRootLogin no" in sshd_config:
        result += "Root login is disabled\n"
        score += 5
    else:
        result += "Root login is enabled\n"
    if "PasswordAuthentication no" in sshd_config:
        result += "Password authentication is disabled (using keys)\n"
        score += 5
    else:
        result += "Password Authentication is enabled\n"
    return result

# 3. File permissions
def check_file_permissions():
    global score
    result = "\n[+] Checking File Permissions:\n"
    files_to_check = ["/etc/passwd", "/etc/shadow"]
    for file in files_to_check:
        if os.path.exists(file):
            permissions = subprocess.getoutput(f"ls -l {file}")
            result += f"{file} permission: {permissions}\n"
            score += 5
        else:
            result += f"{file} does not exist\n"
    return result

# 4. Unused services
def check_unused_services():
    result = "\n[+] Checking unused services:\n"
    services = subprocess.getoutput("systemctl list-units --type=service --state=running")
    result += "Running services:\n" + services
    return result

# 5. Rootkit indicators
def check_rootkits():
    result = "\n[+] Checking for rootkits:\n"
    rootkit_result = subprocess.getoutput("sudo chkrootkit")
    result += rootkit_result
    return result

# 6. User accounts
def check_user_accounts():
    result = "\n[+] Checking User Accounts:\n"
    all_users = subprocess.getoutput("cut -d: -f1 /etc/passwd")
    result += "All users:\n" + all_users + "\n"
    uid0_users = subprocess.getoutput("awk -F: '($3 == 0) {print $1}' /etc/passwd")
    result += "\nUsers with UID 0 (should only be root):\n" + uid0_users + "\n"
    return result

# 7. World Writable Files Check
def check_world_writable_files():
    global score
    result = "\n[+] Checking World Writable Files:\n"
    ww_files = subprocess.getoutput("find / -type f -perm -0002 -exec ls -l {} \; 2>/dev/null")
    if ww_files:
        result += ww_files + "\n"
    else:
        result += "No world writable files found.\n"
        score += 5
    return result

# 8. Password Expiry Policy Check
def check_password_expiry():
    global score
    result = "\n[+] Checking Password Expiry Policy:\n"
    users = ["root"]
    for user in users:
        expiry = subprocess.getoutput(f"sudo chage -l {user}")
        result += f"{user}:\n{expiry}\n"
    score += 5
    return result

# 9. Active Ports and Connections Scan
def check_active_ports():
    result = "\n[+] Checking Active Ports and Connections:\n"
    ports = subprocess.getoutput("sudo netstat -tulnp")
    result += ports + "\n"
    return result

# 10. Sudoers File Check
def check_sudoers():
    result = "\n[+] Checking Sudoers File Configuration:\n"
    sudoers = subprocess.getoutput("cat /etc/sudoers")
    result += sudoers + "\n"
    return result

# 11. Security Recommendations Section
def security_recommendations():
    result = "\n[+] Security Recommendations:\n"
    if score < 50:
        result += "System hardening required. Review firewall, SSH, and permissions.\n"
    else:
        result += "Overall security posture is good. Continue regular audits.\n"
    return result

# Main audit runner
def run_audit():
    report = ""
    now = datetime.datetime.now()
    report += f"Linux Hardening Audit Report\nGenerated on: {now.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    report += check_firewall()
    report += check_ssh_settings()
    report += check_file_permissions()
    report += check_unused_services()
    report += check_rootkits()
    report += check_user_accounts()
    report += check_world_writable_files()
    report += check_password_expiry()
    report += check_active_ports()         
    report += check_sudoers()              
    report += security_recommendations()
    report += f"\nFinal Security Score: {score}/100\n"
    with open("audit_report.txt", "w") as f:
        f.write(report)
    print("[+] Audit completed. Report saved to audit_report.txt")

if __name__ == "__main__":
    run_audit()
