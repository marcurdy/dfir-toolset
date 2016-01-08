from scapy.all import  *
import base64

pkts = rdpcap('gnome.pcap')

commands = []

image = False
image_data = ''

# For each packet in the pcap, check for the DSN Transaction ID of 0x1337
# This was identified via manual analysis of the pcap itself
# Each of these packets contains a base64 encoded string containing
# command information.
for packet in pkts:
    if DNSQR in packet:
        if packet[DNS].id == 0x1337:
            data = packet[DNS].an.rdata
            decoded = base64.b64decode(data)
            if 'JFIF' in decoded or image:
                image_data += decoded.replace('FILE:', '')
                image = True
                continue

            # Only append commands that don't have FILE in the command
            commands.append(decoded)

with open('picture', 'wb') as f:
    f.write(image_data)

for command in commands:
    print command
