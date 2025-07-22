
import argparse
import os
import sys
import json
import psycopg2
import subprocess
import time

def read_config(config_path):
    """Reads the JSON configuration file."""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"Error reading config file: {e}")
        sys.exit(1)

# the action can be add or delete
def append_to_ipset_entry(ip: str, set_name: str) -> bool:
    """
    Check if an IP exists in an ipset. If it does not, add it.

    Parameters:
    - ip (str): The IP address to check/add.
    - set_name (str): The name of the ipset.

    Returns:
    - bool: True if the IP exists or was successfully added, False otherwise.
    """
    try:
        # First, check if the IP exists in the ipset
        check_cmd = ['ipset', 'test', set_name, ip]
        result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode == 0:
            # IP exists in the ipset
            print(f"IP {ip} already exists in ipset '{set_name}'.")
            return True
        else:
            # IP does not exist, attempt to add it
            add_cmd = ['ipset', 'add', set_name, ip]
            add_result = subprocess.run(add_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if add_result.returncode == 0:
                # Successfully added the IP
                print(f"IP {ip} added to ipset '{set_name}'.")
                return True
            else:
                # Failed to add the IP
                return False
    except FileNotFoundError:
        # ipset command not found
        print("Error: ipset command not found.")
        return False
    except Exception as e:
        # Handle other unforeseen exceptions
        print(f"An unexpected error occurred: {e}")
        return False


# the action can be add or delete
def remove_from_ipset_entry(ip: str, set_name: str) -> bool:
    """
    Check if an IP exists in an ipset. If it does not, add it.

    Parameters:
    - ip (str): The IP address to check/add.
    - set_name (str): The name of the ipset.

    Returns:
    - bool: True if the IP exists or was successfully added, False otherwise.
    """
    try:
        # First, check if the IP exists in the ipset
        check_cmd = ['ipset', 'test', set_name, ip]
        result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode != 0:
            # IP exists in the ipset
            print(f"IP {ip} does not exists in ipset '{set_name}'.")
            return True
        else:
            # IP does exist, attempt to remove it
            del_cmd = ['ipset', 'del', set_name, ip]
            del_result = subprocess.run(del_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if del_result.returncode == 0:
                # Successfully added the IP
                print(f"IP {ip} deleted from ipset '{set_name}'.")
                return True
            else:
                # Failed to remove the IP
                return False
    except FileNotFoundError:
        # ipset command not found
        print("Error: ipset command not found.")
        return False
    except Exception as e:
        # Handle other unforeseen exceptions
        print(f"An unexpected error occurred: {e}")
        return False

def parse_arguments():
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(
        description="Extracts unique IPs and ports from pcap files, checks if tcpdump is writing to them, and writes them to a database."
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to configuration file (JSON format)."
    )
    return parser.parse_args()

def main():
    print("Starting the IP set management script...")
    args = parse_arguments()
    
    if not args.config:
        print("Error: Configuration file path is required.")
        sys.exit(1)

    if not os.path.exists(args.config):
        print(f"Error: Configuration file '{args.config}' does not exist.")
        sys.exit(1)


    config = read_config(args.config)

    # Extract config parameters
    db_config = config.get("database", {})
    default_gateway = config.get("default_gateway", "10.8.0.1")
    alternative_gateway = config.get("alternative_gateway", "192.168.71.1")
    waiting_interval = config.get("waiting_interval", 5)
    update_route_threshold = config.get("update_route_threshold", 1.4)
    route_stale_hours = config.get("route_stale_hours", 72)

    # Validate required config parameters
    required_db_keys = ["name", "user", "password"]
    if not all(k in db_config for k in required_db_keys):
        print("Error: Database configuration must include 'name', 'user', and 'password'.")
        sys.exit(1)

    # Database connection parameters
    db_params = {
        "dbname": db_config["name"],
        "user": db_config["user"],
        "password": db_config["password"],
        "host": db_config.get("host", "localhost"),
        "port": db_config.get("port", 5432),
    }

    try:
        conn = psycopg2.connect(**db_params)
    except psycopg2.Error as e:
        print(f"Error connecting to the database: {e}")
        sys.exit(1)

    # enumerate lines from the table ip_route_table, find out those rows:
    # the column default_gateway_rtt is larger than alternative_gateway_rtt and the current_gateway is the default gateway

    while True:
        # Find out the ip routes that haven't been seen more than route_stale_hours
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip_address, port, default_gateway_rtt, alternative_gateway_rtt, current_gateway
            FROM ip_route_table WHERE
            (last_hit_time IS NULL OR last_hit_time < (NOW() - INTERVAL '%s hours'))
        """, (route_stale_hours,))
        rows = cursor.fetchall()
        cursor.close()
        # in the case the current_gateway is not the default gateway, we must delete it from the ipset
        if rows:
            print("IPs that are staled:", len(rows))
            for row in rows:
                ip, port, default_rtt, alternative_rtt, current_gateway = row
                if current_gateway != default_gateway:
                    # delete the IP set if it is in the ipset
                    if remove_from_ipset_entry(ip, "bypass_vpn"):
                        print(f"IP {ip} removed from ipset 'bypass_vpn'.")

                # delete the row from the database
                cursor.execute("""
                    DELETE FROM ip_route_table WHERE ip_address = %s
                """, (ip,))
                conn.commit()
                print(f"Database updated for IP {ip}, removed from ipset 'bypass_vpn'.")
                    
        # Query to get the IPs that need gateway testing
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip_address, port, default_gateway_rtt, alternative_gateway_rtt, current_gateway
            FROM ip_route_table WHERE
            last_hit_time > (NOW() - INTERVAL '%s hours') ORDER BY last_hit_time DESC
        """, (route_stale_hours,))

        # get the first row
        rows = cursor.fetchall()

        # for each row, try to add the ip to the ipset 'bypass_vpn'
        if rows:
            for row in rows:
                ip, port, default_rtt, alternative_rtt, current_gateway = row
                # Check if the default RTT is larger than the alternative RTT more than 20%
                if not default_rtt:
                    default_rtt = 10000

                if not alternative_rtt:
                    alternative_rtt = 10000

                if alternative_rtt and default_rtt >= alternative_rtt * update_route_threshold:
                    if current_gateway == default_gateway:

                        #print(f"Set IPSET: IP: {ip}, Port: {port}, Default RTT: {default_rtt}, Alternative RTT: {alternative_rtt}, Current Gateway: {current_gateway}")
                        # Here you would typically call a function to add the IP to the ipset
                        if append_to_ipset_entry(ip, "bypass_vpn"):
                            # update the database to set the column current_gateway to the alternative gateway
                            cursor.execute("""
                                UPDATE ip_route_table
                                SET current_gateway = %s
                                WHERE ip_address = %s
                            """, (alternative_gateway, ip))
                            conn.commit()
                            print(f"IP {ip} is appended into ipset.")
                        else:
                            print(f"Failed to add IP {ip} to ipset 'bypass_vpn'.")
                else: # should back to default gateway
                    if current_gateway != default_gateway:
                        # delete the IP set if it is in the ipset
                        if remove_from_ipset_entry(ip, "bypass_vpn"):
                            print(f"IP {ip} removed from ipset.")

                        # update the database to set the column current_gateway to the default gateway
                            cursor.execute("""
                                UPDATE ip_route_table
                                SET current_gateway = %s
                                WHERE ip_address = %s
                            """, (default_gateway, ip))
                            conn.commit()
                        #print(f"IP {ip} back to default gateway, removed from ipset 'bypass_vpn'.")



        else:
            print("No IPs need gateway testing.")

        cursor.close()
        # to sleep few seconds before the next iteration
        time.sleep(waiting_interval)


if __name__ == "__main__":
    main()


