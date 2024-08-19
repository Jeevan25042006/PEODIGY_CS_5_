from scapy.all import sniff, IP, TCP, UDP, Raw
from scapy.layers.inet import ICMP

# Specify the log file
log_file = "packet_log.txt"

def packet_callback(packet):
    with open(log_file, "a") as f:
        # Check if the packet has an IP layer
        if IP in packet:
            # Extract relevant information
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto

            # Determine the protocol
            if proto == 6:  # TCP
                protocol = "TCP"
            elif proto == 17:  # UDP
                protocol = "UDP"
            elif proto == 1:  # ICMP
                protocol = "ICMP"
            else:
                protocol = str(proto)

            # Write source and destination IP addresses to the log file
            f.write(f"Source IP: {ip_src}\n")
            f.write(f"Destination IP: {ip_dst}\n")
            f.write(f"Protocol: {protocol}\n")

            # If TCP or UDP, write port information to the log file
            if protocol == "TCP" or protocol == "UDP":
                src_port = packet[protocol].sport
                dst_port = packet[protocol].dport
                f.write(f"Source Port: {src_port}\n")
                f.write(f"Destination Port: {dst_port}\n")
            
            # Write payload data if available
            if Raw in packet:
                f.write(f"Payload: {packet[Raw].load}\n")

            # Write additional information (like flags for TCP packets)
            if protocol == "TCP":
                flags = packet[TCP].flags
                f.write(f"Flags: {flags}\n")
            
            f.write("-" * 50 + "\n")

# Start sniffing the network
print("Starting packet sniffer...")
sniff(prn=packet_callback, store=0)
