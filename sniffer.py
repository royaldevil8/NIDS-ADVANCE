from scapy.all import sniff
from detector import analyze_packet
from shared import packet_queue

def process_packet(pkt):
    print(pkt.summary())

    print("CALLING ANALYZER")
    data = analyze_packet(pkt)
    print("GOT:", data)

    if data:
        print("SNIFFER PUT:", data)
        packet_queue.put(data)

def start_sniffing():
    sniff(prn=process_packet, store=False)
