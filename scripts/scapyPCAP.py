from scapy.all import  *
import base64

packets = rdpcap('gnome.pcap')

for packet in packets:
    if DNSQR in packet:
        if packet[DNS].id == 0x1337:
            data = packet[DNS].an.rdata
            decoded = base64.b64decode(data)
            print decoded
