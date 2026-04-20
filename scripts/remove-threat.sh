#!/bin/bash

LOCAL=$(dirname "$0")
cd "$LOCAL/.." || exit 1
PWD=$(pwd)

LOG_FILE="${PWD}/../logs/active-responses.log"
QUARANTINE_DIR="/var/ossec/quarantine"

mkdir -p "$QUARANTINE_DIR"

read INPUT_JSON

FILENAME=$(echo "$INPUT_JSON" | jq -r .parameters.alert.data.virustotal.source.file)
COMMAND=$(echo "$INPUT_JSON" | jq -r .command)

# Validate filename
if [ -z "$FILENAME" ] || [ "$FILENAME" = "null" ]; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') Invalid filename. Abort." >> "$LOG_FILE"
    exit 1
fi

if [ "$COMMAND" = "add" ]; then
    printf '{"version":1,"origin":{"name":"remove-threat","module":"active-response"},"command":"check_keys","parameters":{"keys":[]}}\n'

    read RESPONSE
    COMMAND2=$(echo "$RESPONSE" | jq -r .command)

    if [ "$COMMAND2" != "continue" ]; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') AR aborted for $FILENAME" >> "$LOG_FILE"
        exit 0
    fi
fi

echo "AR started at $(date) for file: $FILENAME" >> /tmp/ar_log.txt

if [ -f "$FILENAME" ]; then
    BASENAME=$(basename "$FILENAME")

    # Backup trước khi xóa
    cp "$FILENAME" "$QUARANTINE_DIR/$BASENAME"

    # Xóa file
    rm -f "$FILENAME"

    if [ $? -eq 0 ]; then
        echo "$(date '+%Y/%m/%d %H:%M:%S') Removed: $FILENAME (backup: $QUARANTINE_DIR/$BASENAME)" >> "$LOG_FILE"
        echo "AR success at $(date)" >> /tmp/ar_log.txt
    else
        echo "$(date '+%Y/%m/%d %H:%M:%S') ERROR removing: $FILENAME" >> "$LOG_FILE"
        echo "AR failed at $(date)" >> /tmp/ar_log.txt
    fi
else
    echo "$(date '+%Y/%m/%d %H:%M:%S') File not found: $FILENAME" >> "$LOG_FILE"
fi

exit 0