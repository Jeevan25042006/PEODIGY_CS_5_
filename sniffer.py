
from scapy.all import *
def sniff_packets(interface):
    packets = sniff(iface=interface, prn=process_packet)
def process_packet(packet):
    print("Packet Summary:")
    print(packet.summary())
    print("\nPacket Layers:")
    for layer in packet.layers:
        print(layer.name)
    print("\nSource IP:", packet[IP].src)
    print("Destination IP:", packet[IP].dst)
    print("Protocol:", packet[IP].proto)
    print("Payload Data:", packet.payload)
interface = "eth1"  # Change this to the appropriate interface on your system
sniff_packets(interface)
