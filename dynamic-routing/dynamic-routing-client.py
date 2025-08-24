import argparse
from collections import defaultdict
import glob
import os
import subprocess
import sys
from datetime import datetime, timezone
import time
import json
import psycopg2
import asyncio
import aiohttp
from scapy.all import rdpcap, IP
from prometheus_client import Counter, start_http_server

# Define Prometheus metrics
gateway_received_bytes_total = Counter(
    'dynamic_routing_gateway_received_bytes_total',
    'Total received bytes per device (source IP)',
    ['device']
)

gateway_transmitted_bytes_total = Counter(
    'dynamic_routing_gateway_transmitted_bytes_total',
    'Total transmitted bytes per device (destination IP)',
    ['device']
)

tested_IP_total = Counter(
    'dynamic_routing_tested_IP_total',
    'Total number of IPs tested'
)


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


def read_config(config_path):
    """Reads the JSON configuration file."""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"Error reading config file: {e}")
        sys.exit(1)


def is_file_being_written(filepath):
    """Checks if a file is currently being written to by tcpdump using lsof."""
    try:
        result = subprocess.run(["lsof", "-t", filepath], capture_output=True, text=True, check=True)
        # If lsof returns a process ID, the file is open
        return bool(result.stdout.strip())
    except subprocess.CalledProcessError:
        # lsof can also error if the file doesn't exist or is invalid. Consider it not being written.
        return False
    except FileNotFoundError:  # lsof not found on the system
        print("Error: lsof not found. Please install it (e.g., sudo apt install lsof). Cannot reliably check for open files.")
        sys.exit(1)  # or return False, depending on desired behavior


def extract_unique_ip_ports_with_time(filepath, local_ips):
    """Extracts unique IP addresses and their associated ports from a pcap file using scapy."""
    # check if the file name started with tun, which is the VPN
    ip_port_to_times = defaultdict(set) 
    
    try:
        packets = rdpcap(filepath)
        for packet in packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[IP].sport if hasattr(packet[IP], 'sport') else None
                dst_port = packet[IP].dport if hasattr(packet[IP], 'dport') else None
                
                # Accurate packet length from IP layer
                try:
                    bytes_len = packet[IP].len  # Original packet length from pcap record
                except AttributeError:
                    print(f"Warning: Packet in {filepath} missing 'len' field in IP layer. Using captured length instead.")
                    bytes_len = len(packet)

                
                # if both src and dst IP are in the 10.8.x.x or 192.168.x.x, ignore it
                if (src_ip.startswith("10.8.") or src_ip.startswith("192.168.")) and (dst_ip.startswith("10.8.") or dst_ip.startswith("192.168.")):
                    continue

                # get the device name from the first part of file name before '-'
                device_name = os.path.basename(filepath).split('-')[0]
                if dst_ip in  local_ips:
                    gateway_received_bytes_total.labels(device=device_name).inc(bytes_len)
                elif src_ip in local_ips:
                    gateway_transmitted_bytes_total.labels(device=device_name).inc(bytes_len)

                # Extract ports if TCP or UDP layers are present
                if packet.haslayer('TCP'):
                    src_port = packet['TCP'].sport
                    dst_port = packet['TCP'].dport
                    ip_port_to_times[(src_ip, src_port)].add(float(packet.time))
                    ip_port_to_times[(dst_ip, dst_port)].add(float(packet.time))
                elif packet.haslayer('UDP'):
                    src_port = packet['UDP'].sport
                    dst_port = packet['UDP'].dport
                    ip_port_to_times[(src_ip, src_port)].add(float(packet.time))
                    ip_port_to_times[(dst_ip, dst_port)].add(float(packet.time))
                else:
                    # Non-TCP/UDP packets do not have ports; skip them
                    continue
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
    return {k: sorted(v) for k, v in ip_port_to_times.items()}


def create_ip_route_table(conn):
    """Creates the IP_ROUTE_TABLE in the database if it doesn't exist."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS IP_ROUTE_TABLE (
                    ip_address inet,
                    port integer,
                    current_gateway inet,
                    default_gateway inet,
                    default_gateway_rtt integer,
                    alternative_gateway_rtt integer,
                    create_time timestamp with time zone NOT NULL DEFAULT now(),
                    last_hit_time timestamp with time zone NOT NULL DEFAULT now(),
                    last_test_time timestamp with time zone,
                    PRIMARY KEY (ip_address)
                );
            """)
        conn.commit()
        print("IP_ROUTE_TABLE created or already exists.")
    except psycopg2.Error as e:
        print(f"Error creating IP_ROUTE_TABLE: {e}")
        return False
    return True

def insert_or_update_ips(conn, ip_port_to_times, local_ips, default_gateway):
    """Inserts or updates IP addresses and their ports in the database, excluding the local IP."""
    try:
        with conn.cursor() as cur:
            for (ip, port), timestamps in ip_port_to_times.items():
                if ip in local_ips:
                    continue  # Skip the local IP

                # get the maximum timestamp from timestamps
                max_timestamp = max(timestamps)
                try:
                    cur.execute("""
                        INSERT INTO IP_ROUTE_TABLE (ip_address, port, current_gateway, default_gateway, last_hit_time)
                        VALUES (%s, %s, %s,%s, to_timestamp(%s))
                        ON CONFLICT (ip_address) 
                            DO UPDATE SET 
                                port = EXCLUDED.port,
                                last_hit_time = GREATEST(IP_ROUTE_TABLE.last_hit_time, EXCLUDED.last_hit_time);
                    """, (ip, port, default_gateway, default_gateway, max_timestamp))
                except psycopg2.errors.InvalidTextRepresentation as e:
                    print(f"Skipping invalid IP address or port: {ip}:{port} due to: {e}")
                    continue

        conn.commit()
        print(f"Inserted/Updated {len(ip_port_to_times)} IP:Port pairs in the database.")
    except psycopg2.Error as e:
        print(f"Error inserting/updating IPs and ports in the database: {e}")
        return False
    return True


def select_ips_to_test(conn, test_result_stale_hours):
    """Selects IPs that need gateway testing."""
    try:
        with conn.cursor() as cur:
            query = f"""
            SELECT ip_address, port FROM IP_ROUTE_TABLE 
            WHERE 
                last_hit_time > (NOW() - INTERVAL '1 hour') AND 
                (last_test_time IS NULL OR 
                 last_hit_time - last_test_time > INTERVAL '{test_result_stale_hours} hours' OR
                 default_gateway_rtt IS NULL)
            ORDER BY last_hit_time DESC
        """
            cur.execute(query)
            results = cur.fetchall()
            return results
    except psycopg2.Error as e:
        print(f"Error selecting IPs to test: {e}")
        return []


async def process_ips_async(conn, ips_to_test, config):
    """Processes IPs that need gateway testing asynchronously."""
    route_detector_server = config.get("route_detector_server", "192.168.71.51:8080")
    max_parallel = config.get("max_requests_in_parallel", 4)
    alternative_gateway = config.get("alternative_gateway", "192.168.71.1")
    default_gateway = config.get("default_gateway", "10.8.0.1")

    url = f"http://{route_detector_server}/test_route"

    # Semaphore to limit the number of concurrent requests
    semaphore = asyncio.Semaphore(max_parallel)

    async with aiohttp.ClientSession() as session:
        tasks = []
        for ip, port in ips_to_test:
            task = asyncio.create_task(process_single_ip(session, semaphore, url, conn, ip, port, default_gateway, alternative_gateway))
            tasks.append(task)
        await asyncio.gather(*tasks)



def select_ips_to_test(conn, test_result_stale_hours):
    """Selects IPs that need gateway testing."""
    try:
        with conn.cursor() as cur:
            query = f"""
            SELECT ip_address, port FROM IP_ROUTE_TABLE 
            WHERE 
                last_hit_time > (NOW() - INTERVAL '1 hour') AND 
                (last_test_time IS NULL OR 
                 last_hit_time - last_test_time > INTERVAL '{test_result_stale_hours} hours' OR
                 default_gateway_rtt IS NULL)
            ORDER BY last_hit_time DESC
        """
            cur.execute(query)
            results = cur.fetchall()
            return results
    except psycopg2.Error as e:
        print(f"Error selecting IPs to test: {e}")
        return []


async def process_ips_async(conn, ips_to_test, config):
    """Processes IPs that need gateway testing asynchronously."""
    route_detector_server = config.get("route_detector_server", "192.168.71.51:8080")
    max_parallel = config.get("max_requests_in_parallel", 4)
    alternative_gateway = config.get("alternative_gateway", "192.168.71.1")
    default_gateway = config.get("default_gateway", "10.8.0.1")

    url = f"http://{route_detector_server}/test_route"

    # Semaphore to limit the number of concurrent requests
    semaphore = asyncio.Semaphore(max_parallel)

    async with aiohttp.ClientSession() as session:
        tasks = []
        for ip, port in ips_to_test:
            task = asyncio.create_task(process_single_ip(session, semaphore, url, conn, ip, port, default_gateway, alternative_gateway))
            tasks.append(task)
        await asyncio.gather(*tasks)

async def test_gateway(session, url, ip, port, current_gateway, alternative_gateways):
    """Sends a POST request to the route detector and returns the response."""
    payload = {
        "destination_ip": ip,
        "destination_port": port,
        "current_gateway": current_gateway,
        "alternative_gateways": alternative_gateways
    }
    headers = {
        "Content-Type": "application/json"
    }
    try:
        async with session.post(url, json=payload, headers=headers) as response:
            if response.status == 200:
                return await response.json()
            else:
                print(f"Failed to test gateway for {ip}:{port}. Status code: {response.status}")
                return None
    except Exception as e:
        print(f"Exception while testing gateway for {ip}:{port}: {e}")
        return None

async def process_single_ip(session, semaphore, url, conn, ip, port, default_gateway, alternative_gateway):
    """Processes a single IP:Port pair for gateway testing."""
    async with semaphore:
        response = await test_gateway(session, url, ip, port, default_gateway, [alternative_gateway])
        if response and "results" in response:
            results = response["results"]
            alternative_rtt = None

            for result in results:
                gateway = result.get("gateway")
                rtt_stats = result.get("rtt_stats_ms", {})
                avg_rtt = rtt_stats.get("average")

                if gateway == default_gateway:
                    default_rtt = avg_rtt
                elif gateway == alternative_gateway:
                    alternative_rtt = avg_rtt

            # Update RTTs in the database
            try:
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE IP_ROUTE_TABLE
                        SET 
                            default_gateway_rtt = %s,
                            alternative_gateway_rtt = %s,
                            last_test_time = now()
                        WHERE ip_address = %s AND port = %s
                    """, (default_rtt, alternative_rtt, ip, port))
                conn.commit()
                print(f"Updated RTTs for {ip}:{port} - Current: {default_rtt} ms, Alternative: {alternative_rtt} ms.")
            except psycopg2.Error as e:
                print(f"Error updating RTTs for {ip}:{port}: {e}")

        else:
            print(f"No valid response for {ip}:{port}. Skipping RTT update.")


def process_ips_to_test(conn, ips_to_test, config):
    """Processes IPs that need gateway testing."""
    if not ips_to_test:
        return

    print(f"Testing gateways for {len(ips_to_test)} IPs.")
    asyncio.run(process_ips_async(conn, ips_to_test, config))



def main():
    args = parse_arguments()
    config = read_config(args.config)

    # Extract config parameters
    db_config = config.get("database", {})
    raw_file_dir = config.get("raw_file_directory")
    local_ips = config.get("local_ips")
    route_test_interval = config.get("route_test_interval", 3)
    default_gateway = config.get("default_gateway", "10.8.0.1")
    waiting_interval = config.get("waiting_interval", 5)
    metrics_listen_port = config.get("metrics_listen_port", 8100)

    # Start Prometheus metrics server
    start_http_server(metrics_listen_port)
    print(f"Prometheus metrics available at http://localhost:{metrics_listen_port}/metrics")


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

    if not create_ip_route_table(conn):
        conn.close()
        sys.exit(1)

    while True:
        # Process pcap files
        pcap_files = sorted(glob.glob(os.path.join(raw_file_dir, "*.pcap*")))  # Sort for processing order

        for filepath in pcap_files:
            if is_file_being_written(filepath):
                print(f"Skipping {filepath} - being written to by tcpdump.")
                continue
            
            # remove file with 0 size
            if os.path.getsize(filepath) == 0:
                print(f"Skipping {filepath} - file is empty.")
                #os.remove(filepath)
                continue


            print(f"Processing {filepath}")
            ip_port_to_times = extract_unique_ip_ports_with_time(filepath, local_ips)

            if ip_port_to_times:
                insert_or_update_ips(conn, ip_port_to_times, local_ips, default_gateway)

            # remove the file
            print(f"deleting {filepath}")
            os.remove(filepath)

        # Select and process IPs that need gateway testing
        ips_to_test = select_ips_to_test(conn, route_test_interval)
        if ips_to_test:
            print(f"Testing gateways for {len(ips_to_test)} IPs.")
            process_ips_to_test(conn, ips_to_test, config)

        # to sleep few seconds before the next iteration
        time.sleep(waiting_interval)
        

    conn.close()
    print("Done.")


if __name__ == "__main__":
    main()
