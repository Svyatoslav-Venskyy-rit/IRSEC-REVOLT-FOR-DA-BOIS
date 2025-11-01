#!/bin/bash

# Configuration
LOGFILE="/var/log/irsec_remediation.log"
INPUT_CSV="new_passwords.csv" # CSV file with a list of passwords (one per line, no header)
OUTPUT_CSV="password_rotation_report.csv"
# Target users are local accounts that need rotation
TARGET_USERS="root drwho martymcfly arthurdent sambeckett loki riphunter theflash tonystark drstrange bartallen merlin terminator mrpeabody jamescole docbrown professorparadox"

echo "$(date): Starting password rotation from CSV ($INPUT_CSV)" | tee -a $LOGFILE
echo "User,New_Password,Old_Hash" > $OUTPUT_CSV # Header for the report

if [ ! -f "$INPUT_CSV" ]; then
    echo "ERROR: Input file $INPUT_CSV not found. Aborting." | tee -a $LOGFILE
    exit 1
fi

# Read passwords into an array, stripping potential Windows-style carriage returns (\r)
mapfile -t PASSWORDS < <(tr -d '\r' < "$INPUT_CSV")

PASSWORD_INDEX=0
USERS_TO_ROTATE=($TARGET_USERS)

if [ ${#PASSWORDS[@]} -lt ${#USERS_TO_ROTATE[@]} ]; then
    echo "ERROR: Not enough passwords in $INPUT_CSV. Needs at least ${#USERS_TO_ROTATE[@]}." | tee -a $LOGFILE
    exit 1
fi

for user in "${USERS_TO_ROTATE[@]}"; do
    if id "$user" >/dev/null 2>&1; then
        NEW_PWD="${PASSWORDS[$PASSWORD_INDEX]}"
        
        # Log old hash for the report
        OLD_HASH=$(grep "^$user:" /etc/shadow 2>/dev/null | cut -d: -f2)
        if [ -z "$OLD_HASH" ]; then
            OLD_HASH="N/A (User not in shadow file)"
        fi
        
        # Change password using chpasswd
        echo "$user:$NEW_PWD" | chpasswd
        
        # Write to report CSV and internal log
        echo "$user,$NEW_PWD,$OLD_HASH" >> $OUTPUT_CSV
        echo "$(date): Rotated password for $user (Old hash: $OLD_HASH)" >> $LOGFILE
        echo "Rotated password for user: $user"
        
        PASSWORD_INDEX=$((PASSWORD_INDEX + 1))
    else
        echo "User $user not found—skip." | tee -a $LOGFILE
        echo "$user,Skipped (User not found),N/A" >> $OUTPUT_CSV
    fi
done

echo -e "\nRotation done. Report saved to $OUTPUT_CSV. **Securely delete $INPUT_CSV and $OUTPUT_CSV after use!**"

# Run: chmod +x rotate_passwords.sh && sudo ./rotate_passwords.sh
