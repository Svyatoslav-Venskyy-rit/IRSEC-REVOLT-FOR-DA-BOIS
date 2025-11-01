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

# REVISED CRON JOB CLEAN-UP BLOCK (Interactive Targeting)
echo -e "\n=== CRON REMEDIATION (Interactive Targeted Removal) ==="

# 1. Check if a user crontab exists
crontab -l > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "User crontab found. Do you want to remove a specific malicious job? (y/n)"
    read -r confirm
    
    if [ "$confirm" = "y" ]; then
        echo "Enter the UNIQUE PHRASE/SIGNATURE of the malicious cron job (e.g., /tmp/backdoor_script.sh):"
        read -r MALICIOUS_PHRASE
        
        if [ -z "$MALICIOUS_PHRASE" ]; then
            echo "No phrase entered. Aborting targeted cron removal." >> $LOGFILE
        else
            echo "Targeting jobs containing: '$MALICIOUS_PHRASE'"
            
            # 2. Export the current crontab to a temporary file
            crontab -l > /tmp/current_crontab.txt
            
            # 3. Use sed to remove the line containing the malicious phrase
            # The 'd' command deletes the line matching the pattern
            sed "/$MALICIOUS_PHRASE/d" /tmp/current_crontab.txt > /tmp/clean_crontab.txt
            
            # 4. Check if a change occurred (safety check)
            if cmp -s /tmp/current_crontab.txt /tmp/clean_crontab.txt; then
                echo "$(date): WARNING: Malicious phrase '$MALICIOUS_PHRASE' was NOT found in crontab. No changes made." >> $LOGFILE
            else
                # 5. Load the clean crontab back to the system
                crontab /tmp/clean_crontab.txt
                echo "$(date): Removed cron job with phrase '$MALICIOUS_PHRASE'. Clean crontab reloaded." >> $LOGFILE
                echo "Successfully removed the targeted cron job: $MALICIOUS_PHRASE."
            fi
            
            # Clean up temporary files
            rm /tmp/current_crontab.txt /tmp/clean_crontab.txt
        fi
    fi
else
    echo "No user crontab found for the current user. Skipping." >> $LOGFILE
fi

echo -e "\n$(date): Remediation complete. Rerun scan."

# Run: chmod +x remediate_suspicious.sh && ./remediate_suspicious.sh
