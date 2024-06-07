from scapy.all import sniff, Ether, IP, ICMP, TCP, UDP
import json

# Unpack Ethernet frame
def unpack_ethernet_frame(packet):
    eth = packet[Ether]
    dest_mac = eth.dst
    src_mac = eth.src
    eth_proto = eth.type
    data = packet.payload
    return dest_mac, src_mac, eth_proto, data

# Unpack IPv4 packet
def unpack_ipv4_packet(packet):
    ip = packet[IP]
    version = ip.version
    header_length = ip.ihl * 4
    ttl = ip.ttl
    proto = ip.proto
    src = ip.src
    target = ip.dst
    data = packet.payload
    return version, header_length, ttl, proto, src, target, data

# Unpack ICMP packet
def unpack_icmp_packet(packet):
    icmp = packet[ICMP]
    icmp_type = icmp.type
    code = icmp.code
    checksum = icmp.chksum
    data = packet.payload
    return icmp_type, code, checksum, data

# Unpack TCP segment
def unpack_tcp_segment(packet):
    tcp = packet[TCP]
    src_port = tcp.sport
    dest_port = tcp.dport
    sequence = tcp.seq
    acknowledgement = tcp.ack
    offset_reserved_flags = tcp.dataofs * 4
    flag_urg = tcp.flags.U
    flag_ack = tcp.flags.A
    flag_psh = tcp.flags.P
    flag_rst = tcp.flags.R
    flag_syn = tcp.flags.S
    flag_fin = tcp.flags.F
    data = packet.payload
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

# Unpack UDP segment
def unpack_udp_segment(packet):
    udp = packet[UDP]
    src_port = udp.sport
    dest_port = udp.dport
    size = len(udp)
    data = packet.payload
    return src_port, dest_port, size, data

# Capture packets
def capture_packets(count):
    captured_packets = []
    packet_number = 1

    def process_packet(packet):
        nonlocal packet_number
        if packet_number > count:
            return

        if Ether in packet:
            dest_mac, src_mac, eth_proto, data = unpack_ethernet_frame(packet)
            packet_info = {
                'Packet Number': packet_number,
                'Destination MAC': dest_mac,
                'Source MAC': src_mac,
                'Ethernet Protocol': eth_proto,
            }

            if IP in packet:
                version, header_length, ttl, proto, src, target, data = unpack_ipv4_packet(packet)
                packet_info.update({
                    'Version': version,
                    'Header Length': header_length,
                    'TTL': ttl,
                    'Protocol': proto,
                    'Source IP': src,
                    'Destination IP': target,
                })

                if proto == 1 and ICMP in packet:
                    icmp_type, code, checksum, data = unpack_icmp_packet(packet)
                    packet_info.update({
                        'ICMP Type': icmp_type,
                        'Code': code,
                        'Checksum': checksum,
                        'Data': data.original.hex()
                    })

                elif proto == 6 and TCP in packet:
                    src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = unpack_tcp_segment(packet)
                    packet_info.update({
                        'Source Port': src_port,
                        'Destination Port': dest_port,
                        'Sequence': sequence,
                        'Acknowledgment': acknowledgement,
                        'Flags': {
                            'URG': flag_urg,
                            'ACK': flag_ack,
                            'PSH': flag_psh,
                            'RST': flag_rst,
                            'SYN': flag_syn,
                            'FIN': flag_fin,
                        },
                        'Data': data.original.hex()
                    })

                elif proto == 17 and UDP in packet:
                    src_port, dest_port, size, data = unpack_udp_segment(packet)
                    packet_info.update({
                        'Source Port': src_port,
                        'Destination Port': dest_port,
                        'Length': size,
                        'Data': data.original.hex()
                    })

            captured_packets.append(packet_info)
            packet_number += 1

    sniff(count=count, prn=process_packet)

    return captured_packets

# Save packets to file
def save_packets_to_file(packets, filename):
    with open(filename, 'w') as file:
        json.dump(packets, file, indent=4)

if __name__ == "__main__":
    packet_count = 10  # Adjust the number of packets you want to capture
    packets = capture_packets(packet_count)
    save_packets_to_file(packets, 'captured_packets.json')
    print(f"Captured {packet_count} packets and saved to captured_packets.json")
