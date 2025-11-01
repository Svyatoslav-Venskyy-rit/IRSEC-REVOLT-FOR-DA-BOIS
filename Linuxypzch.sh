#!/bin/bash

# Configuration
LOGFILE="/var/log/irsec_remediation.log"
INPUT_CSV="new_passwords.csv" # CSV file with a list of passwords (MUST HAVE A HEADER NOW)
OUTPUT_CSV="password_rotation_report.csv"
# Target users are local accounts that need rotation
TARGET_USERS="root drwho martymcfly arthurdent sambeckett loki riphunter theflash tonystark drstrange bartallen merlin terminator mrpeabody jamescole docbrown professorparadox"

echo "$(date): Starting password rotation from CSV ($INPUT_CSV)" | tee -a $LOGFILE
echo "User,New_Password,Old_Hash" > $OUTPUT_CSV # Header for the report

if [ ! -f "$INPUT_CSV" ]; then
    echo "ERROR: Input file $INPUT_CSV not found. Aborting." | tee -a $LOGFILE
    exit 1
fi

# --- FIX IMPLEMENTED HERE ---
# Read passwords into an array, skipping the first line (the header).
# This ensures that "Password" or "New_Password" is not used as a credential.
mapfile -t PASSWORDS < <(tail -n +2 "$INPUT_CSV" | tr -d '\r')

PASSWORD_INDEX=0
USERS_TO_ROTATE=($TARGET_USERS)

if [ ${#PASSWORDS[@]} -lt ${#USERS_TO_ROTATE[@]} ]; then
    # We now check against the number of lines *after* the header is removed.
    echo "ERROR: Not enough passwords in $INPUT_CSV. Needs at least ${#USERS_TO_ROTATE[@]} valid passwords (excluding header)." | tee -a $LOGFILE
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


### **Change Summary**

The critical fix is in this line:

```bash
# OLD: mapfile -t PASSWORDS < <(tr -d '\r' < "$INPUT_CSV")
# NEW:
mapfile -t PASSWORDS < <(tail -n +2 "$INPUT_CSV" | tr -d '\r')
