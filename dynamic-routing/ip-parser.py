#!/usr/bin/env python3

import os
import sys
import glob
import subprocess
import pcapkit
from ipaddress import ip_address
from bsddb3 import db

def is_file_being_written(filepath):
    """
    Checks if a file is currently being written to by a process (e.g., tcpdump).
    Uses 'lsof' (list open files) command.

    Args:
        filepath (str): The path to the file.

    Returns:
        bool: True if the file is being written to, False otherwise.
    """
    try:
        result = subprocess.run(['lsof', '-t', filepath], capture_output=True, text=True, check=True)
        return bool(result.stdout.strip())  # If there's output, the file is open
    except subprocess.CalledProcessError:
        return False # lsof failed. Assume file is *not* open
    except FileNotFoundError:
        print("Error: lsof is not installed.  Please install it (e.g., 'sudo apt install lsof' or equivalent).")
        sys.exit(1)


def extract_unique_ips_from_pcap(pcap_file):
    """
    Extracts unique IP addresses from a pcap file, excluding local IP and any non-IP packets.

    Args:
        pcap_file (str): Path to the pcap file.
        local_ip (str): The local IP address to exclude.

    Returns:
        set: A set of unique IP addresses.
    """
    unique_ips = set()
    try:
        with pcapkit.io.PCAP.loadfile(filepath=pcap_file) as packets:
            for packet in packets:
                try:
                    if hasattr(packet, 'ip'):  # Check if the packet contains an IP field
                        src_ip = str(packet.ip.src)
                        dst_ip = str(packet.ip.dst)
                        if not (src_ip == local_ip or dst_ip == local_ip):
                            unique_ips.add(src_ip)
                            unique_ips.add(dst_ip)
                except AttributeError:  # Handle packets without ip layer (e.g., ARP)
                    pass  # Ignore packets without IP layer

    except pcapkit.io.PcapError as e:
        print(f"Error reading {pcap_file}: {e}")
    except Exception as e:
        print(f"Unexpected error processing {pcap_file}: {e}")

    return unique_ips


def main():
    """
    Main function to process pcap files, extract IPs, and store them in a Berkeley DB.
    """
    if len(sys.argv) != 4:
        print("Usage: python3 ./get-unique-ip.py raw_file_dir local_ip db_file")
        sys.exit(1)

    raw_file_dir = sys.argv[1]
    local_ip = sys.argv[2]
    db_file = sys.argv[3]

    if not os.path.isdir(raw_file_dir):
        print(f"Error: raw_file_dir '{raw_file_dir}' does not exist or is not a directory.")
        sys.exit(1)

    try:
        # Open or create the Berkeley DB
        db_env = db.DBEnv()
        db_env.set_cachesize(0, 1024 * 1024 * 1024, 1) # cache size : 1GB
        db_env.open('.',db.DB_CREATE | db.DB_PRIVATE | db.DB_THREAD)

        db_obj = db.DB(db_env)
        db_obj.open(db_file, "hash", db.DB_CREATE)
    except db.DBError as e:
          print(f"Error opening/creating database: {e}")
          sys.exit(1)

    pcap_files = sorted(glob.glob(os.path.join(raw_file_dir, "*.pcap")))
    processed_files = set() # Keep track of processed files to avoid duplicates
    try:
        for pcap_file in pcap_files:
            if pcap_file in processed_files:
                continue # Skip files already processed
            if not is_file_being_written(pcap_file):
                unique_ips = extract_unique_ips_from_pcap(pcap_file)
                if unique_ips: # Only process if there are unique IP addresses.
                    print(f"Processing {pcap_file}...")
                    for ip in unique_ips:
                        try: # Try to add them to the db.
                            db_obj.put(ip.encode(), b"")  # Use b"" as value (empty)
                        except db.DBError as e:
                            print(f"Error inserting IP {ip} into database: {e}")
                processed_files.add(pcap_file) # Mark as processed

            else:
                print(f"Skipping {pcap_file} (being written to)...")

    except KeyboardInterrupt:
        print("\nInterrupted by user.  Closing database safely.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        try:
            db_obj.close()
            db_env.close()
            print(f"Database closed. Saved data to: {db_file}")
        except db.DBError as e:
            print(f"Error closing database: {e}")
    print("Done.")

if __name__ == "__main__":
    main()


