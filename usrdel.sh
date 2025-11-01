#!/bin/bash

# Configuration
LOGFILE="/var/log/irsec_user_remediation_$(date +%F_%H%M%S).log"
# Users listed in the IRSeC packet (Local + Domain Users you manage)
EXPECTED_USERS="root drwho martymcfly arthurdent sambeckett loki riphunter theflash tonystark drstrange bartallen merlin terminator mrpeabody jamescole docbrown professorparadox"
# System accounts are typically UID < 1000, but we'll include common low-UID exceptions
SYSTEM_UIDS_MAX=1000

echo "$(date): Starting Interactive User Deletion Scan" | tee -a $LOGFILE
echo "--- LOG FILE: $LOGFILE ---" | tee -a $LOGFILE
echo "USERS EXCLUDED FROM REVIEW (Scored or Expected): $EXPECTED_USERS" >> $LOGFILE
echo "---" >> $LOGFILE

# Get all accounts with UID >= 1000 (standard for regular users)
# Filter out accounts that are explicitly expected/scored
ALL_USERS=$(getent passwd | awk -F: -v max_uid=$SYSTEM_UIDS_MAX '{if ($3 >= max_uid) print $1}')
USERS_TO_REVIEW=()

# Filter out the explicitly expected users from the list of high-UID accounts
for user in $ALL_USERS; do
    IS_EXPECTED=0
    for expected in $EXPECTED_USERS; do
        if [ "$user" == "$expected" ]; then
            IS_EXPECTED=1
            break
        fi
    done
    
    if [ $IS_EXPECTED -eq 0 ]; then
        USERS_TO_REVIEW+=("$user")
    fi
done

echo "Found ${#USERS_TO_REVIEW[@]} unexpected user(s) for review." | tee -a $LOGFILE

# --- Interactive Review and Deletion Loop ---
if [ ${#USERS_TO_REVIEW[@]} -eq 0 ]; then
    echo "No unexpected accounts found (UID >= $SYSTEM_UIDS_MAX)." | tee -a $LOGFILE
else
    for user_to_delete in "${USERS_TO_REVIEW[@]}"; do
        
        # Get details for the user
        USER_INFO=$(getent passwd "$user_to_delete")
        echo -e "\n-----------------------------------------------------"
        echo "🚨 UNEXPECTED ACCOUNT FOUND:" | tee -a $LOGFILE
        echo "   Username: $user_to_delete" | tee -a $LOGFILE
        echo "   Full Details: $USER_INFO" | tee -a $LOGFILE
        echo "-----------------------------------------------------"
        
        echo "Do you want to DELETE this user and their home directory? (y/n)"
        read -r confirm
        
        if [ "$confirm" = "y" ]; then
            # The -r flag removes the home directory and mail spool
            userdel -r "$user_to_delete"
            
            if [ $? -eq 0 ]; then
                echo "$(date): SUCCESS: Deleted user $user_to_delete (including home directory)." | tee -a $LOGFILE
            else
                echo "$(date): ERROR: Failed to delete user $user_to_delete." | tee -a $LOGFILE
            fi
        else
            echo "$(date): SKIP: User $user_to_delete retained per confirmation." | tee -a $LOGFILE
        fi
    done
fi

echo -e "\n$(date): Interactive user management complete." | tee -a $LOGFILE

# Run: chmod +x user_management_interactive.sh && sudo ./user_management_interactive.sh


### **How to Run the Script**

1.  **Make executable:**
    ```bash
    chmod +x user_management_interactive.sh
    ```
2.  **Run with privileges (mandatory for user deletion):**
    ```bash
    sudo ./user_management_interactive.sh
    ```
