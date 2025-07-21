#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Define the destination directory
DEST_DIR="raw_files"

# Create the destination directory if it doesn't exist
mkdir -p "$DEST_DIR"

# Define the filename prefix
FILENAME_PREFIX="tcpdump"

# Run tcpdump with specified options:
# - Capture TCP traffic
# - Interface: tun0
# - No name resolution (-n)
# - Less verbose (-q)
# - Print timestamp without the link-layer header (-t)
# - Line buffered output (-l)
# - Rotate files every 1 MB (-C 1) or every 300 seconds (-G 300)
# - Write output to files with timestamps in their names
sudo tcpdump tcp -i tun0 -n -q -t -l -C 1 -G 60 -s 100 \
    -w "${DEST_DIR}/${FILENAME_PREFIX}-%Y%m%d-%H%M%S.pcap" \
    &
    
# Optional: Save the PID of the tcpdump process for future reference
echo "tcpdump is running with PID $!"


