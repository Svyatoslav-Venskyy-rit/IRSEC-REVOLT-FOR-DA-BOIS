#!/bin/bash

# Configuration
LOGFILE="/var/log/irsec_remediation.log"
# Services that MUST NOT be touched to maintain score [cite: 145]
SCORED_SVCS="ssh vsftpd mysql httpd apache2 wazuh docker"
# Populate these lists from your scan_suspicious.sh output before running!
SUSPECT_PROCS="nc netcat ncat miner crypto backdoor" # Processes to search for
SUSPECT_SVCS="randomservice unknown-daemon telnet" # Example services to stop/disable
NON_SCORED_PORTS="1234 8080" # Example ports to block

echo "$(date): Starting interactive remediation" | tee -a $LOGFILE

# --- Kill Suspicious Processes ---
echo -e "\n=== PROCESS REMEDIATION ==="
for proc in $SUSPECT_PROCS; do
    PIDS=$(pgrep -f $proc)
    if [ ! -z "$PIDS" ]; then
        echo "Found suspicious process '$proc' (PIDs: $PIDS). Kill? (y/n)"
        read -r confirm
        if [ "$confirm" = "y" ]; then
            kill -9 $PIDS
            echo "$(date): Killed suspicious process '$proc' PIDs $PIDS" >> $LOGFILE
            echo "Killed PIDs: $PIDS"
        fi
    fi
done

# --- Disable Unknown Services ---
echo -e "\n=== SERVICE REMEDIATION ==="
for svc in $SUSPECT_SVCS; do
    if systemctl is-active --quiet $svc; then
        # Check if the suspect service name is NOT one of the scored services
        if [[ ! " ${SCORED_SVCS[@]} " =~ " ${svc} " ]]; then
            echo "Service '$svc' active. Stop/disable? (y/n)"
            read -r confirm
            if [ "$confirm" = "y" ]; then
                systemctl stop $svc
                systemctl disable $svc
                echo "$(date): Stopped/disabled suspect service '$svc'" >> $LOGFILE
                echo "Stopped/disabled: $svc"
            fi
        else
            echo "Service '$svc' is a SCORED SERVICE. Skipping stop/disable."
        fi
    fi
done

# --- Close Non-Scored Ports (using UFW or IPTABLES) ---
echo -e "\n=== FIREWALL REMEDIATION ==="
if command -v ufw >/dev/null; then
    ufw status | grep -q "inactive" && ufw enable
    for port in $NON_SCORED_PORTS; do
        echo "Block port $port with ufw? (y/n)"
        read -r confirm
        if [ "$confirm" = "y" ]; then
            ufw deny $port
            echo "$(date): UFW denied port $port" >> $LOGFILE
            echo "UFW denied: $port"
        fi
    done
elif command -v iptables >/dev/null; then
    for port in $NON_SCORED_PORTS; do
        echo "Block port $port with iptables? (y/n)"
        read -r confirm
        if [ "$confirm" = "y" ]; then
            # Adds rule to drop TCP traffic to the port
            iptables -A INPUT -p tcp --dport $port -j DROP
            # Remember to save iptables config manually! (e.g., netfilter-persistent save)
            echo "$(date): iptables dropped TCP port $port" >> $LOGFILE
            echo "iptables dropped: $port"
        fi
    done
fi

# --- Cron Job Clean-up ---
echo -e "\n=== CRON REMEDIATION ==="
echo "WARNING: Review all cron jobs manually before proceeding. Clear user crontab completely? (y/n)"
read -r confirm
if [ "$confirm" = "y" ]; then
    crontab -r # WARNING: Wipes the entire user crontab for the current user
    echo "$(date): Cleared user crontab via 'crontab -r'" >> $LOGFILE
    echo "User crontab cleared."
fi

echo -e "\n$(date): Remediation complete. Rerun scan."

# Run: chmod +x remediate_suspicious.sh && ./remediate_suspicious.sh
