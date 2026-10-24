import sys
import logging
from scapy.all import *
import pandas as pd
from tabulate import tabulate
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

def read_pcap(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        logger.error(f"PCAP file not found: {pcap_file}")
        sys.exit(1)
    except Scapy_Exception as e:
        logger.error(f"Error reading PCAP file: {e}")
        sys.exit(1)
    return packets

def extract_packet_data(packets):
    packet_data = []
    for packet in tqdm(packets, desc="Processing packets for analytics", unit="packet"):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            size = len(packet)
            packet_data.append({"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol, "size": size})
    return pd.DataFrame(packet_data)

def protocol_name(number):
    protocol_dict = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    return protocol_dict.get(number, f"Unknown({number})")

def analyze_packet_data(df):
    if df.empty:
        return 0, pd.DataFrame(), pd.DataFrame(), pd.Series(), pd.DataFrame()
        
    total_bandwidth = df["size"].sum()
    protocol_counts = df["protocol"].value_counts(normalize=True) * 100
    protocol_counts.index = protocol_counts.index.map(protocol_name)

    ip_communication = df.groupby(["src_ip", "dst_ip"]).size().sort_values(ascending=False)
    ip_communication_percentage = (ip_communication / ip_communication.sum() * 100)
    ip_communication_table = pd.concat([ip_communication, ip_communication_percentage], axis=1).reset_index()
    ip_communication_table.columns = ["Source IP", "Destination IP", "Count", "Percentage"]

    protocol_frequency = df["protocol"].value_counts()
    protocol_frequency.index = protocol_frequency.index.map(protocol_name)

    protocol_counts_df = pd.concat([protocol_frequency, protocol_counts], axis=1).reset_index()
    protocol_counts_df.columns = ["Protocol", "Count", "Percentage"]

    ip_communication_protocols = df.groupby(["src_ip", "dst_ip", "protocol"]).size().reset_index()
    ip_communication_protocols.columns = ["Source IP", "Destination IP", "Protocol", "Count"]
    ip_communication_protocols["Protocol"] = ip_communication_protocols["Protocol"].apply(protocol_name)

    total_per_ip_pair = ip_communication_protocols.groupby(["Source IP", "Destination IP"])["Count"].transform('sum')
    ip_communication_protocols["Percentage"] = (ip_communication_protocols["Count"] / total_per_ip_pair) * 100

    return total_bandwidth, protocol_counts_df, ip_communication_table, protocol_frequency, ip_communication_protocols

def extract_packet_data_security(packets):
    packet_data = []
    for packet in tqdm(packets, desc="Processing packets for security anomalies", unit="packet"):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            size = len(packet)
            
            dst_port = 0
            tcp_flags = ""
            
            if TCP in packet:
                dst_port = packet[TCP].dport
                tcp_flags = str(packet[TCP].flags)
            elif UDP in packet:
                dst_port = packet[UDP].dport

            packet_data.append({
                "src_ip": src_ip, 
                "dst_ip": dst_ip, 
                "protocol": protocol, 
                "size": size, 
                "dst_port": dst_port,
                "tcp_flags": tcp_flags
            })
    return pd.DataFrame(packet_data)

def detect_port_scanning(df, port_scan_threshold):
    if df.empty:
        return
    port_scan_df = df.groupby(['src_ip', 'dst_port']).size().reset_index(name='count')
    unique_ports_per_ip = port_scan_df.groupby('src_ip').size().reset_index(name='unique_ports')
    potential_port_scanners = unique_ports_per_ip[unique_ports_per_ip['unique_ports'] >= port_scan_threshold]
    ip_addresses = potential_port_scanners['src_ip'].unique()
    
    if len(ip_addresses) > 0:
        logger.warning(f"\n[⚠️ SECURITY ALERT] Potential Port Scanning detected from IPs: {', '.join(ip_addresses)}")
        logger.warning(f"Detail:\n{tabulate(potential_port_scanners, headers=['Attacker IP', 'Unique Ports Probed'], tablefmt='grid')}\n")

def detect_syn_flood(df, syn_threshold=100):
    if df.empty:
        return
    syn_packets = df[df['tcp_flags'] == 'S']
    syn_counts = syn_packets.groupby('src_ip').size().reset_index(name='syn_packet_count')
    flooders = syn_counts[syn_counts['syn_packet_count'] >= syn_threshold]
    
    if not flooders.empty:
        logger.warning(f"[⚠️ SECURITY ALERT] Potential TCP SYN Flood Attack (DoS) detected!")
        logger.warning(f"Detail:\n{tabulate(flooders, headers=['Attacker IP', 'SYN Packet Volume'], tablefmt='grid')}\n")

def print_results(total_bandwidth, protocol_counts_df, ip_communication_table, ip_communication_protocols):
    if total_bandwidth < 10**9:
        bandwidth_unit = "Mbps"
        total_bandwidth /= 10**6
    else:
        bandwidth_unit = "Gbps"
        total_bandwidth /= 10**9

    logger.info(f"\n==================== NETWORK AUDIT REPORT ====================")
    logger.info(f"Total network throughput processed: {total_bandwidth:.2f} {bandwidth_unit}")
    logger.info("\n📊 Protocol Distribution Breakdown:")
    logger.info(tabulate(protocol_counts_df, headers=["Protocol", "Total Packets", "Percentage Share"], tablefmt="grid"))
    
    logger.info("\n📈 Top Conversing IP Nodes:")
    logger.info(tabulate(ip_communication_table.head(10), headers=["Source IP", "Destination IP", "Packet Count", "Percentage"], tablefmt="grid", floatfmt=".2f"))

    logger.info("\n🔗 Shared Protocol Details between Nodes:")
    logger.info(tabulate(ip_communication_protocols.head(10), headers=["Source IP", "Destination IP", "Protocol", "Volume", "Percentage"], tablefmt="grid", floatfmt=".2f"))

def main(pcap_file, port_scan_threshold, syn_threshold):
    packets = read_pcap(pcap_file)
    
    analytics_df = extract_packet_data(packets)
    total_bandwidth, protocol_counts, ip_communication_table, protocol_frequency, ip_communication_protocols = analyze_packet_data(analytics_df)
    
    print_results(total_bandwidth, protocol_counts, ip_communication_table, ip_communication_protocols)
    
    security_df = extract_packet_data_security(packets)
    detect_port_scanning(security_df, port_scan_threshold)
    detect_syn_flood(security_df, syn_threshold)

if __name__ == "__main__":
    if __name__ == "__main__":
        if len(sys.argv) < 2:
            logger.error("Usage Error: Please provide the target PCAP file path.")
            logger.error("Example: python script.py sample.pcap [port_threshold] [syn_threshold]")
            sys.exit(1)
    
    
    pcap_file = sys.argv[1] 
    
    port_threshold = 100
    syn_threshold = 150

    if len(sys.argv) >= 3:
        try: port_threshold = int(sys.argv[2]) 
        except ValueError: logger.warning("Invalid port threshold. Using default (100).")
            
    if len(sys.argv) >= 4:
        try: syn_threshold = int(sys.argv[3]) # FIX
        except ValueError: logger.warning("Invalid SYN threshold. Using default (150).")
    
    main(pcap_file, port_threshold, syn_threshold)
