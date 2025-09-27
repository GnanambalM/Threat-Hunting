# Single doc extraction
from scapy.all import rdpcap, Raw, TCP, IP
def extract_docx_from_capture(capture_file, result_file):
    network_packets = rdpcap(capture_file)
    extracted_data = bytearray()
    docx_started = False
    primary_signature = b'\x50\x4B\x03\x04'
    secondary_signature = b'\x50\x4B\x03\x04\x4B\x50'
    for pkt in network_packets:
        print(pkt)
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if not docx_started:
                if primary_signature in payload:
                    docx_started = True
                    start_idx = payload.index(primary_signature)
                    extracted_data.extend(payload[start_idx:])
                    print(f"Detected .docx start signature in packet: {pkt.summary()}")
                elif secondary_signature in payload:
                    docx_started = True
                    start_idx = payload.index(secondary_signature)
                    extracted_data.extend(payload[start_idx:])
                    print(f"Detected alternate .docx signature in packet: {pkt.summary()}")
            else:
                extracted_data.extend(payload)
    if extracted_data:
        with open(result_file, 'wb') as output:
            output.write(extracted_data)
        print(f"Successfully extracted .docx to '{result_file}'")
    else:
        print("No .docx file signatures detected in the capture file.")
if __name__ == '__main__':
    input_pcap = r"C:\Users\TEMP\Downloads\captures.pcapng"
    output_docx = 'extracted_document.docx'
    extract_docx_from_capture(input_pcap, output_docx)

# Multi doc extraction
from scapy.all import rdpcap, Raw, TCP, IP
def extract_docx_multiple(pcap_file, output_dir):
    packets = rdpcap(pcap_file)
    data_stream = bytearray()
    start = b'\x50\x4B\x03\x04'
    end = b'\x50\x4B\x05\x06'
    docx_count = 0
    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            data_stream += pkt[Raw].load
    index = 0
    while True:
        start_idx = data_stream.find(start, index)
        if start_idx == -1:
            break
        end_idx = data_stream.find(end, start_idx)
        if end_idx == -1:
            break
        end_idx += 22
        docx_data = data_stream[start_idx:end_idx]
        output_file = f"{output_dir}/extracted_{docx_count + 1}.docx"
        with open(output_file, 'wb') as f:
            f.write(docx_data)
        print(f"Saved DOCX {docx_count + 1} to {output_file}")
        docx_count += 1
        index = end_idx
    if docx_count == 0:
        print("No DOCX found in capture.")
    else:
        print(f"Total DOCX files extracted: {docx_count}")
extract_docx_multiple(
    "multidoc.pcapng", "./extracted_docs"
)

# filters
1) Basic IP / Host filters
ip                          # show IPv4 traffic
ip6                         # show IPv6 traffic
ip.addr == 192.168.1.10     # traffic to/from host
ip.src == 10.0.0.5          # packets with source IP
ip.dst == 8.8.8.8           # packets with destination IP
not ip.addr == 127.0.0.1    # exclude loopback
net 192.168.1.0/24          # traffic in subnet
2) Ports & Protocol ports
tcp                        # all TCP
udp                        # all UDP
tcp.port == 80             # TCP port equals 80
tcp.dstport == 4444        # destination port
tcp.srcport == 22          # source port
udp.port == 53             # DNS port
tcp.port >= 1024 && tcp.port <= 65535
3) Protocol filters (common)
http
dns
ftp
ftp-data
smtp
pop
imap
tls or ssl                 # TLS/SSL
ssl.record.version == 0x0303 # TLS 1.2 record version check
smb || smb2
ntlmssp                    # NTLM authentication
ssh
arp
icmp
dhcp
mdns
dns and http               # combined (both shown)
4) HTTP / Web traffic
http.request               # all HTTP requests
http.response              # HTTP responses
http.request.method == "GET"
http.request.method == "POST"
http contains ".pdf"       # payload contains .pdf string
http.request.uri contains "/download"
http.host == "example.com"
http.user_agent contains "curl"
http.authbasic             # HTTP Basic Auth headers
http.content_type contains "application/pdf"
5) File carving / payload signatures (magic bytes)
Search raw frames or TCP payload for magic bytes:
frame contains "%PDF"      # PDF
frame contains "MZ"        # PE (EXE/DLL)
frame contains "PK"        # Zip / DOCX / XLSX
tcp contains "%PDF"
tcp contains "MZ"
tcp contains "JFIF"        # JPEG
tcp contains "PNG"         # PNG header
6) DNS & suspicious DNS
dns
dns.qry.name == "example.com"
dns.qry.name contains "subdomain"
dns.flags.response == 0        # DNS queries only
dns.resp.addr == 1.2.3.4       # DNS response with that IP
frame.len > 200 && dns         # long DNS packets (possible tunneling)
dns.qry.name matches "^[A-Za-z0-9+/]{50,}\."  # regex-like (note: use display filter features carefully)
7) Authentication / Credentials / Cleartext secrets
http.authbasic                       # HTTP Basic auth
ftp.request.command == "USER"
ftp.request.command == "PASS"
smtp.auth                             # SMTP AUTH
telnet                                # telnet (cleartext)
imap && (contains "LOGIN" || imap.request.command == "LOGIN")
frame contains "username"
frame contains "password"
8) TCP flags / Scans / Recon
tcp.flags.syn == 1 && tcp.flags.ack == 0   # SYN only (scan-like)
tcp.flags.reset == 1                       # RST packets
tcp.flags.fin == 1 && tcp.len == 0        # FIN probe
tcp.analysis.retransmission               # retransmissions
tcp.analysis.out_of_order
tcp.seq
9) Large transfers / possible exfiltration
tcp.len > 1000                              # TCP payload > 1000 bytes
frame.len > 1500
ip.src == <victim_ip> && tcp.len > 1000     # large outbound payloads from victim
tcp contains "Content-Disposition"          # file upload/download in HTTP
10) TLS / HTTPS inspection
tls                                         # TLS traffic
ssl.handshake.extensions_server_name == "example.com"   # SNI
tls.handshake.type == 1                     # ClientHello
tls.record.version == 0x0304               # TLS 1.3
tls.alert_message.level == 2               # fatal alert
ssl || tls                                  # older versions
11) SMB / Lateral movement / Windows file share
smb || smb2
nbtns                                      # NetBIOS name service
smb2 && smb2.cmd == 0x0006                 # SMB2 CREATE (file create/open)
smb2 && smb2.nt_status == 0xC000000D       # access denied / specific NTSTATUS
smb2 && frame contains "NT_CREATE"
12) Email (SMTP/POP/IMAP) attachments
smtp
smtp.req.parameter contains "MAIL FROM"
smtp && frame contains "Content-Disposition: attachment"
pop || imap
13) ARP / MITM detection
arp
arp.opcode == 1          # ARP request
arp.opcode == 2          # ARP reply
eth.addr == 00:11:22:33:44:55    # filter by MAC
arp.duplicate-address-detected   # heuristic
14) ICMP / ping / traceroute
icmp
icmp.type == 8           # Echo request
icmp.type == 0           # Echo reply
icmp.code
15) HTTP(s) object export & stream helpers
Use Follow → HTTP Stream or Follow → TCP Stream in UI.
Export objects: File → Export Objects → HTTP/FTP/SMB to grab transferred files.
tshark -r capture.pcap -Y "http && http.content_type" -T fields -e http.host -e http.request.uri    # tshark example to extract HTTP objects (summary):
16) Useful tshark commands (for automation)
tshark -r capture.pcap -q -z conv,ip    # List top talkers (IP addresses) by packets
tshark -r capture.pcap -Y http.request -T fields -e ip.src -e http.host -e http.request.uri    # Extract all HTTP URIs requested
tshark -r capture.pcap -q -z follow,tcp,raw,3 > stream3.bin    # Save TCP stream payload to file (stream 3)
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name -e dns.a    # Extract DNS queries/responses
17) Frame/time-based filters
frame.time >= "2025-09-26 12:00:00" && frame.time <= "2025-09-26 12:10:00"
frame.number == 1234
frame.len > 1000
18) Boolean logic & combination examples
ip.addr == 10.0.0.5 && (http || dns)        # host + these protocols
tcp.port == 80 && http.request.method == "POST"  # POSTs to port 80
ip.src == 10.0.0.5 && tcp.flags.syn==1 && tcp.flags.ack==0  # SYN scans from host
not (ip.addr == 192.168.1.1)               # exclude specific host
19) Regex-like content searching
Wireshark display filters do not support full PCRE in all fields — but matches exists for some:
http.file_data matches "[A-Za-z0-9+/]{100}"   # use with caution (field-dependent)
20) Quick forensics recipes (copy-paste)
ip.src == 10.0.0.5 && tcp.len > 1000    # Find large outbound flows from host 10.0.0.5:
http && (http.content_type contains "application/octet-stream" || http contains ".exe")    # Find HTTP downloads of EXE:
dns && (dns.qry.name contains ".xyz" || dns.qry.name contains ".top")    # Find DNS queries to suspicious TLDs (.xyz, .top):
ip.addr == <victim_ip> && (http || dns) && frame.len < 200    # Find potential C2 beaconing (repeated small requests to same endpoint):
http.authbasic    # Find Basic Auth credentials in HTTP:
ftp.request.command == "USER" || ftp.request.command == "PASS"    # Find FTP login attempts:
21) Performance tips
Limit view with ip.addr == <host> while investigating that host.
Use Follow TCP/HTTP Stream to reconstruct interactions.
Use Statistics → Protocol Hierarchy / Conversations / Endpoints to discover where to focus.
Export objects early (File → Export Objects) to speed file analysis.
22) Where to look (workflow)
Protocol Hierarchy → which protocols dominate?
Conversations / Endpoints → top talkers (by bytes/packets).
Time sequence → timeline of events (use frame numbers/time).
Follow streams & Export Objects → get files and credentials.
Use display filters above to answer specific exam questions.
Step 1
http → PDFs, executables, images.
ftp-data → uploaded/downloaded files.
smtp → email attachments.
smb2 → Windows file shares.
Step 2
Right click a packet → Follow → TCP Stream or Follow → HTTP Stream.
Look for file headers (magic numbers).
Common file signatures:
%PDF → PDF file
PK → ZIP / DOCX / XLSX / JAR (since they are zipped)
MZ → Windows EXE/DLL
GIF89a or PNG or JFIF → images
(a) Find if there are any remote attempts made to the system
What to look for: unusual inbound connection attempts, many SYNs from one remote IP to your host, repeated login attempts, connections to unusual ports, or RST/ICMP unreachable responses.
Quick filters to surface “remote attempts” (replace <victim_ip>):
# Any traffic to victim (start here)
ip.dst == <victim_ip>
# SYN-only attempts (common sign of connection attempts / scans)
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == <victim_ip>
# Many different destination ports to same victim → scanning
ip.dst == <victim_ip> && (tcp.flags.syn == 1 && tcp.flags.ack == 0)
# ICMP unreachable or port unreachable (failed attempts)
icmp && ip.dst == <victim_ip>
# For UDP-based probing (lots of small UDP packets to many ports)
udp && ip.dst == <victim_ip>
Replace <victim_ip> with the host you’re investigating.
Apply the SYN-only filter to see inbound connection attempts. If one remote IP shows many result lines to many ports → remote scan/attempts.
Use Statistics → Conversations → IPv4 and sort by packets to find top remote talkers.
(b) Filter the traffic for the suspicious one
Assuming you identified a suspicious remote IP (call it <remote_ip>) from (a), filter only traffic between that remote IP and the victim.
# Traffic between victim and the suspicious remote IP
ip.addr == <victim_ip> && ip.addr == <remote_ip>
# Only inbound from remote to victim
ip.src == <remote_ip> && ip.dst == <victim_ip>
# Only outbound from victim to remote
ip.src == <victim_ip> && ip.dst == <remote_ip>
Tip: After applying the filter, right-click a packet → Follow → TCP Stream (or UDP/HTTP) to see the full conversation and payload. Export objects if file transfers are present.
(c) Filter by specific IP address
Single-host filters — copy/paste and replace <ip>:
# Any packet to/from the IP
ip.addr == <ip>
# Packets sent from the IP
ip.src == <ip>
# Packets sent to the IP
ip.dst == <ip>
Variants:
Combine with protocol: ip.addr == <ip> && http
Combine with time/frame: ip.addr == <ip> && frame.number >= 100 && frame.number <= 500
(d) Filter by specific port
Replace <port> with the numeric port and optionally <ip> to narrow.
tcp.port == <port> || udp.port == <port>    # Any traffic using TCP or UDP port (source OR destination)
tcp.dstport == <port>    # Only TCP destination port
tcp.srcport == <port>    # Only TCP source port
ip.dst == <victim_ip> && tcp.dstport == 4444    # Narrow to a host and port: traffic to victim IP on port 4444
Common ports to check: 22 (SSH), 443 (HTTPS), 80 (HTTP), 445 (SMB), 21 (FTP), 3389 (RDP), 4444/8080/1337 (often C2/reverse shells).
(e) Filter by TCP flags
Basic flag filters:
tcp.flags.syn == 1    # SYN packet
tcp.flags.syn == 1 && tcp.flags.ack == 0    # SYN without ACK (initial connect attempt)
tcp.flags.syn == 1 && tcp.flags.ack == 1    # SYN+ACK (server reply)
tcp.flags.ack == 1    # ACK packets
tcp.flags.reset == 1    # RST (reset)
# abbreviated alias also works: tcp.flags.rst == 1
tcp.flags.fin == 1    # FIN (connection close)
tcp.flags.push == 1    # PSH (push)
tcp.flags.urg == 1    # URG (urgent)
Compound suspicious patterns:
tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src == <remote_ip>    # Lots of SYNs from one source → scan
tcp.flags.reset == 1 && ip.addr == <victim_ip>    # Many RSTs (e.g., aborted connections)
tcp.flags.fin == 1 && tcp.len == 0    # FIN probes (rare but used in scanning)
Counting / summarizing: After filtering, use Statistics → Conversations or Statistics → Endpoints, or use Analyze → Statistics → IO Graphs to plot SYN counts or RSTs over time.
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src | sort | uniq -c | sort -nr    # Count SYN (connection attempts) per source IP
tshark -r capture.pcap -Y "ip.addr==<victim_ip> && ip.addr==<remote_ip>"    # Show all packets between victim and remote
tshark -r capture.pcap -q -z "follow,tcp,raw,5"    # Extract TCP stream payload to file for stream 5
Open pcap → Statistics → Protocol Hierarchy → spot suspicious protocols.
Statistics → Conversations → find top remote IPs to victim.
Apply tcp.flags.syn==1 && tcp.flags.ack==0 && ip.dst==<victim_ip> to find connection attempts.
Take the most frequent ip.src from step 3 → apply ip.src==<that_ip> && ip.dst==<victim_ip> for the full interaction.
Follow stream / export objects / check payloads and flags (RST/FIN) for success/failure.
