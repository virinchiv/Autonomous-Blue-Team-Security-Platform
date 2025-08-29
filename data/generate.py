# import time
# import random

# # Zeek conn.log header (tab-separated)
# header = (
#     "ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
#     "proto\tduration\torig_bytes\tresp_bytes\tconn_state\n"
# )

# # Get current timestamp
# now = time.time()

# # --- Simulate a few network flows ---
# # Flow 1: A normal, established web browsing session
# flow_1_ip_orig = "192.168.1.104"
# flow_1_ip_resp = "172.217.164.196" # A Google IP
# flow_1_port_orig = 54321

# # Multiple "packets" for the same flow
# log_data = [
#     f"{now-30:.6f}\tC1a2b3\t{flow_1_ip_orig}\t{flow_1_port_orig}\t{flow_1_ip_resp}\t443\ttcp\t-\t650\t-\tS0\n",
#     f"{now-25:.6f}\tC1a2b3\t{flow_1_ip_orig}\t{flow_1_port_orig}\t{flow_1_ip_resp}\t443\ttcp\t-\t-\t1200\tS1\n",
#     f"{now-10:.6f}\tC1a2b3\t{flow_1_ip_orig}\t{flow_1_port_orig}\t{flow_1_ip_resp}\t443\ttcp\t20.123456\t1200\t8500\tSF\n", # Final log for the flow
# ]

# # Flow 2: A short, rejected connection (possible scan)
# flow_2_ip_orig = "104.244.42.1" # A suspicious IP
# flow_2_ip_resp = "192.168.1.150"
# log_data.append(
#     f"{now-5:.6f}\tC4d5e6\t{flow_2_ip_orig}\t60001\t{flow_2_ip_resp}\t445\ttcp\t0.001234\t40\t0\tREJ\n"
# )

# # Flow 3: Another normal flow to a different server
# log_data.append(
#     f"{now-2:.6f}\tC7f8g9\t192.168.1.104\t54322\t13.107.42.16\t443\ttcp\t3.456789\t800\t4500\tSF\n"
# )


# # Write to file
# with open("test_conn.log", "w") as f:
#     f.write(header)
#     for line in log_data:
#         f.write(line)

# print("Generated 'test_conn.log' for testing.")




import time
import random
import ipaddress

# --- Configuration ---
NUM_BENIGN_FLOWS = 2000
NUM_DDOS_PACKETS = 5000
NUM_PORTS_TO_SCAN = 50
NUM_BRUTE_FORCE_ATTEMPTS = 100
NUM_BOTNET_CHECKINS = 30

VICTIM_IP = "192.168.1.150"
ATTACKER_IP = "104.244.42.1"
BRUTE_FORCER_IP = "185.191.205.10"
BOT_IP = "192.168.1.77"
C2_SERVER_IP = "45.146.165.48"

# --- Helper Functions ---
def random_ip(network="192.168.1.0/24"):
    """Generates a random IP from a local network."""
    return str(ipaddress.IPv4Address(random.randint(
        int(ipaddress.IPv4Network(network).network_address) + 1,
        int(ipaddress.IPv4Network(network).broadcast_address) - 1
    )))

def generate_benign_traffic(num_flows):
    logs = []
    popular_servers = ["8.8.8.8", "1.1.1.1", "172.217.164.196", "31.13.78.35"]
    for _ in range(num_flows):
        local_ip = random_ip()
        server_ip = random.choice(popular_servers)
        local_port = random.randint(49152, 65535)
        server_port = random.choice([53, 80, 443])
        duration = random.uniform(1.0, 120.0)
        orig_bytes = random.randint(60, 1500)
        resp_bytes = random.randint(200, 25000) if server_port != 53 else random.randint(80, 500)
        
        logs.append(
            f"{time.time() - random.uniform(1, 3600):.6f}\tC{random.getrandbits(64):x}\t{local_ip}\t{local_port}\t"
            f"{server_ip}\t{server_port}\ttcp\t{duration:.6f}\t{orig_bytes}\t{resp_bytes}\tSF\n"
        )
    return logs

def simulate_port_scan(attacker_ip, victim_ip, num_ports):
    logs = []
    ports_to_scan = random.sample([21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5900, 8080], min(num_ports, 14))
    start_time = time.time() - 120 # Simulate the scan starting 2 minutes ago
    
    for i, port in enumerate(ports_to_scan):
        duration = random.uniform(0.001, 0.05)
        conn_state = random.choice(["S0", "REJ"]) # SYN sent no reply, or Rejected
        logs.append(
            f"{start_time + i*0.2:.6f}\tC{random.getrandbits(64):x}\t{attacker_ip}\t{random.randint(40000, 50000)}\t"
            f"{victim_ip}\t{port}\ttcp\t{duration:.6f}\t60\t0\t{conn_state}\n"
        )
    return logs

def simulate_ddos(victim_ip, num_packets):
    logs = []
    # Spoof source IPs from many different networks
    attacker_ips = [str(ipaddress.IPv4Address(random.getrandbits(32))) for _ in range(num_packets)]
    start_time = time.time() - 60 # Simulate DDoS starting 1 minute ago
    
    for i, ip in enumerate(attacker_ips):
        duration = 0.0
        # SYN Flood on web port
        logs.append(
            f"{start_time + i*0.001:.6f}\tC{random.getrandbits(64):x}\t{ip}\t{random.randint(1024, 65535)}\t"
            f"{victim_ip}\t80\ttcp\t{duration:.6f}\t40\t0\tS0\n"
        )
    return logs
    
def simulate_brute_force(attacker_ip, victim_ip, target_port, num_attempts):
    logs = []
    start_time = time.time() - 300 # Simulate 5 minutes ago
    
    for i in range(num_attempts):
        duration = random.uniform(0.1, 1.5)
        # Most attempts are rejected
        conn_state = "REJ" if i < num_attempts -1 else "SF" # Simulate one success at the end
        logs.append(
            f"{start_time + i*1.5:.6f}\tC{random.getrandbits(64):x}\t{attacker_ip}\t{random.randint(40000, 50000)}\t"
            f"{victim_ip}\t{target_port}\ttcp\t{duration:.6f}\t{random.randint(100, 400)}\t{random.randint(100, 400)}\t{conn_state}\n"
        )
    return logs

def simulate_botnet_c2(bot_ip, c2_server_ip, num_checkins):
    logs = []
    start_time = time.time() - 3600 # An hour ago
    # Botnets are regular. Key feature is the consistent interval.
    interval = 60.0 
    
    for i in range(num_checkins):
        ts = start_time + i * interval + random.uniform(-2, 2) # Add jitter
        duration = random.uniform(0.5, 2.0)
        # Small, consistent heartbeat packets
        orig_bytes = random.randint(60, 120)
        resp_bytes = random.randint(80, 200)
        logs.append(
            f"{ts:.6f}\tC{random.getrandbits(64):x}\t{bot_ip}\t{random.randint(40000, 50000)}\t"
            f"{C2_SERVER_IP}\t4444\ttcp\t{duration:.6f}\t{orig_bytes}\t{resp_bytes}\tSF\n"
        )
    return logs

# --- Main Generation Logic ---
if __name__ == "__main__":
    print("Generating synthetic log data...")
    
    all_logs = []
    
    print(f"-> Generating {NUM_BENIGN_FLOWS} benign flows...")
    all_logs.extend(generate_benign_traffic(NUM_BENIGN_FLOWS))
    
    print(f"-> Simulating Port Scan on {NUM_PORTS_TO_SCAN} ports from {ATTACKER_IP}...")
    all_logs.extend(simulate_port_scan(ATTACKER_IP, VICTIM_IP, NUM_PORTS_TO_SCAN))
    
    print(f"-> Simulating DDoS with {NUM_DDOS_PACKETS} packets on {VICTIM_IP}...")
    all_logs.extend(simulate_ddos(VICTIM_IP, NUM_DDOS_PACKETS))
    
    print(f"-> Simulating SSH Brute Force with {NUM_BRUTE_FORCE_ATTEMPTS} attempts from {BRUTE_FORCER_IP}...")
    all_logs.extend(simulate_brute_force(BRUTE_FORCER_IP, VICTIM_IP, 22, NUM_BRUTE_FORCE_ATTEMPTS))

    print(f"-> Simulating Botnet C2 with {NUM_BOTNET_CHECKINS} check-ins from {BOT_IP}...")
    all_logs.extend(simulate_botnet_c2(BOT_IP, C2_SERVER_IP, NUM_BOTNET_CHECKINS))
    
    print("Shuffling logs for realism...")
    random.shuffle(all_logs)
    
    # Zeek conn.log header (tab-separated)
    header = (
        "ts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
        "proto\tduration\torig_bytes\tresp_bytes\tconn_state\n"
    )

    with open("test_conn.log", "w") as f:
        f.write(header)
        for line in all_logs:
            f.write(line)

    print(f"\n✅ Successfully generated {len(all_logs)} log entries in 'test_conn.log'.")