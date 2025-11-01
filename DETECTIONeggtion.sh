#!/bin/bash

# Configuration
LOGFILE="/var/log/irsec_scan_$(date +%F_%H%M%S).log"
# Services required for scoring or basic functionality (adjust if services change!)
SCORED_SVCS="sshd vsftpd mysqld httpd apache2 wazuh docker" 
# System users to exclude from 'extras' check (adjust for specific distributions)
SYSTEM_EXCLUDES="root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody systemd-network systemd-resolve systemd-timesync systemd-coredump" 
# Users listed in the packet for your team's network
PACKET_USERS="drwho martymcfly arthurdent sambeckett loki riphunter theflash tonystark drstrange bartallen merlin terminator mrpeabody jamescole docbrown professorparadox"

echo "$(date): Starting Linux detection scan" | tee -a $LOGFILE
echo "--- LOG FILE: $LOGFILE ---" | tee -a $LOGFILE

# --- PROCESSES (ps aux) ---
echo -e "\n=== 🚨 PROCESSES (ps aux - Top 20 by CPU/MEM) ===" >> $LOGFILE
echo "Top CPU:" >> $LOGFILE
ps aux --sort=-%cpu | head -21 >> $LOGFILE
echo "Top MEM:" >> $LOGFILE
ps aux --sort=-%mem | head -21 >> $LOGFILE
echo -e "\nSuspicious Command Names (nc/miner/backdoor):" >> $LOGFILE
ps aux | grep -E "(nc|netcat|ncat|miner|crypto|backdoor|reverse|shell|pty)" | grep -v grep >> $LOGFILE

# --- SERVICES (systemctl) ---
echo -e "\n=== 💡 SERVICES (systemctl --type=service) ===" >> $LOGFILE
echo "All Active Services:" >> $LOGFILE
systemctl list-units --type=service --state=active --no-pager >> $LOGFILE
echo -e "\nAll Enabled (Persistent) Services:" >> $LOGFILE
systemctl list-unit-files --type=service --state=enabled --no-pager >> $LOGFILE

# --- NETWORK (ss -tuln) ---
echo -e "\n=== 📡 LISTENING PORTS (ss -tuln or netstat) ===" >> $LOGFILE
if command -v ss >/dev/null; then
    echo "Listening Ports (ss -tuln):" >> $LOGFILE
    ss -tuln >> $LOGFILE
else
    echo "Listening Ports (netstat -tuln):" >> $LOGFILE
    netstat -tuln >> $LOGFILE
fi
echo -e "\nWARNING: Non-Scored Ports (review these!):" >> $LOGFILE
# Filters out common ports (SSH 22, FTP 21, MySQL 3306, HTTP/HTTPS 80/443, Wazuh default 55000)
# Modify ports based on the Scored Services list [cite: 145]
ss -tuln | awk 'NR>1 {
    split($5, a, ":"); port = a[length(a)]; 
    if (port !~ /^(22|21|3306|80|443|55000)$/ && port >= 1024) 
        print $0
}' >> $LOGFILE

# --- CRON JOBS (Persistence) ---
echo -e "\n=== 🕰️ CRON JOBS ===" >> $LOGFILE
echo "User Crontab (crontab -l):" >> $LOGFILE
crontab -l 2>/dev/null || echo "No user crontab found." >> $LOGFILE
echo -e "\nSystem Crontab (/etc/crontab):" >> $LOGFILE
cat /etc/crontab 2>/dev/null >> $LOGFILE
echo -e "\nCron.d files (/etc/cron.d/):" >> $LOGFILE
ls -la /etc/cron.d/ 2>/dev/null >> $LOGFILE

# --- USERS (/etc/passwd) ---
echo -e "\n=== 👥 USERS (/etc/passwd locals) ===" >> $LOGFILE
echo "All Users:" >> $LOGFILE
getent passwd | cut -d: -f1 >> $LOGFILE

# Flag users NOT listed in the packet, excluding system accounts
echo -e "\nWARNING: Extra Users (Potential Malicious/New Accounts):" >> $LOGFILE
# Build a regex pattern for expected users
EXPECTED_REGEX=$(echo $PACKET_USERS $SYSTEM_EXCLUDES | sed 's/ /|/g')
getent passwd | cut -d: -f1 | grep -vE "^($EXPECTED_REGEX)$" | grep -vE "(^$|#)" >> $LOGFILE


echo -e "\n$(date): Scan complete. Full output in $LOGFILE"
cat $LOGFILE | grep -E "WARNING|ERROR|Suspicious|KILL|SUSPECT|Found" # Quick filter to console

# Run: chmod +x scan_suspicious.sh && ./scan_suspicious.sh
