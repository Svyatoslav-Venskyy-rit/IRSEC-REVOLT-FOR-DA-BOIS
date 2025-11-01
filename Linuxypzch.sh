#!/bin/bash

# Configuration
LOGFILE="/var/log/irsec_remediation_$(date +%F_%H%M%S).log" # Use a timestamped logfile
INPUT_CSV="new_passwords.csv" # CSV file with a list of passwords (MUST HAVE A HEADER NOW)
OUTPUT_CSV="password_rotation_report.csv"
PROTECTED_USER="whiteteam" # User whose password MUST NOT be rotated

# Target users are local accounts that need rotation. I've added whiteteam here
# to ensure the script explicitly checks and skips it during the loop.
TARGET_USERS="root drwho martymcfly arthurdent sambeckett loki riphunter theflash tonystark drstrange bartallen merlin terminator mrpeabody jamescole docbrown professorparadox whiteteam"

echo "$(date): Starting password rotation from CSV ($INPUT_CSV)" | tee -a $LOGFILE
echo "User,New_Password,Old_Hash" > $OUTPUT_CSV # Header for the report

if [ ! -f "$INPUT_CSV" ]; then
    echo "ERROR: Input file $INPUT_CSV not found. Aborting." | tee -a $LOGFILE
    exit 1
fi

# Read passwords into an array, skipping the first line (the header).
mapfile -t PASSWORDS < <(tail -n +2 "$INPUT_CSV" | tr -d '\r')

PASSWORD_INDEX=0
USERS_TO_ROTATE=($TARGET_USERS)

if [ ${#PASSWORDS[@]} -lt ${#USERS_TO_ROTATE[@]} ]; then
    # We check against the number of lines *after* the header is removed.
    echo "ERROR: Not enough passwords in $INPUT_CSV. Needs at least ${#USERS_TO_ROTATE[@]} valid passwords (excluding header)." | tee -a $LOGFILE
    exit 1
fi

for user in "${USERS_TO_ROTATE[@]}"; do
    
    # 1. Fetch the new password based on the current position (index)
    NEW_PWD="${PASSWORDS[$PASSWORD_INDEX]}"

    # 🚨 CRITICAL CHECK: SKIP THE PROTECTED USER
    if [ "$user" == "$PROTECTED_USER" ]; then
        echo "$(date): SKIP: Protected account $PROTECTED_USER is EXCLUDED from rotation." | tee -a $LOGFILE
        echo "$user,Skipped (Protected),$NEW_PWD,N/A" >> $OUTPUT_CSV
    
    # 2. Check if the user exists on the system
    elif id "$user" >/dev/null 2>&1; then
        
        # Log old hash for the report
        OLD_HASH=$(grep "^$user:" /etc/shadow 2>/dev/null | cut -d: -f2)
        if [ -z "$OLD_HASH" ]; then
            OLD_HASH="N/A (User not in shadow file)"
        fi
        
        # Change password using chpasswd
        echo "$user:$NEW_PWD" | chpasswd
        
        # Write to report CSV and internal log
        echo "$user,$NEW_PWD,$OLD_HASH" >> $OUTPUT_CSV
        echo "$(date): SUCCESS: Rotated password for $user (Old hash: $OLD_HASH)" >> $LOGFILE
        echo "Rotated password for user: $user"
    
    # 3. Handle users in the list that do not exist on the system
    else
        echo "$(date): User $user not found on system—skip rotation." | tee -a $LOGFILE
        echo "$user,Skipped (User not found),$NEW_PWD,N/A" >> $OUTPUT_CSV
    fi
    
    # 4. CRITICAL: Increment the password index. The password is consumed for this position,
    # regardless of whether the user was rotated or skipped.
    PASSWORD_INDEX=$((PASSWORD_INDEX + 1))
done

echo -e "\n$(date): Rotation done. Report saved to $OUTPUT_CSV. **Securely delete $INPUT_CSV and $OUTPUT_CSV after use!**" | tee -a $LOGFILE

# Run: chmod +x secure_password_rotation.sh && sudo ./secure_password_rotation.sh
