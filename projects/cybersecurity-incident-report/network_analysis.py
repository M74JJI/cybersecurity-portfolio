import pyshark

def analyze_network_log(file_path):
    """Analyze the pcap/pcapng network capture file and return DNS and ICMP issues."""
    cap = pyshark.FileCapture(file_path)
    
    dns_issues = []
    icmp_issues = []
    udp_protocol = None  # For storing UDP-related issues
    icmp_error_msg = None  # For storing ICMP error messages

    # Loop through the captured packets
    for packet in cap:
        try:
            # Check for DNS packets (usually port 53)
            if 'DNS' in packet:
                if packet.dns.flags_response == '0':  # DNS query
                    dns_issues.append(f"DNS Query: {packet.dns.qry_name} - Port: {packet.dns.qry_port}")
            
            # Check for ICMP Echo Reply packets
            if 'ICMP' in packet:
                if packet.icmp.type == '0':  # ICMP Echo Reply
                    if 'unreachable' in packet.icmp.payload:
                        icmp_issues.append(f"ICMP Unreachable Error: {packet.icmp.payload}")
                        icmp_error_msg = packet.icmp.payload  # Save the ICMP error message

            # Check for UDP packets (e.g., related to DNS or other services)
            if 'UDP' in packet:
                udp_protocol = f"UDP Packet: {packet.ip.src} -> {packet.ip.dst} Port: {packet.udp.srcport}"
        
        except AttributeError:
            pass  # Ignore packets without the required protocols

    return dns_issues, icmp_issues, udp_protocol, icmp_error_msg
