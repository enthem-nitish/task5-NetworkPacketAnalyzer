#!/usr/bin/env python3

import sys
import time
import json
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw, Ether, IPv6, conf
except ImportError:
    print("Error: Scapy is required. Install with: pip install scapy")
    sys.exit(1)

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''

class PacketAnalyzer:
    def __init__(self, interface=None, verbose=True):
        self.interface = interface
        self.verbose = verbose
        self.packet_count = 0
        self.start_time = datetime.now()
        self.protocol_stats = defaultdict(int)
        self.ip_connections = defaultdict(int)
        self.captured_packets = []
        self.max_packets_stored = 1000
        self.filter_string = None
        self.suspicious_ports = {22, 23, 3389, 5900, 5800, 445, 139}
        
        conf.sniff_promisc = True
        
        self.protocol_map = {
            1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 58: "ICMPv6"
        }
        
        self.port_services = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
            25: "SMTP", 53: "DNS", 67: "DHCP-S", 68: "DHCP-C",
            69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPCBIND",
            123: "NTP", 135: "MSRPC", 137: "NETBIOS-NS", 138: "NETBIOS-DGM",
            139: "NETBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMPTRAP",
            179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
            465: "SMTPS", 514: "SYSLOG", 587: "SMTP", 636: "LDAPS",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MYSQL",
            3389: "RDP", 5432: "POSTGRES", 5900: "VNC", 6379: "REDIS",
            8080: "HTTP-ALT", 8443: "HTTPS-ALT"
        }

    def _get_service_name(self, port):
        return self.port_services.get(port, "Unknown")

    def _get_protocol_name(self, proto_num):
        return self.protocol_map.get(proto_num, f"PROTO-{proto_num}")

    def _format_ip(self, ip_addr):
        if COLOR_ENABLED:
            return f"{Fore.CYAN}{ip_addr}{Style.RESET_ALL}"
        return ip_addr

    def _format_port(self, port):
        if COLOR_ENABLED:
            if port in self.suspicious_ports:
                return f"{Fore.RED}{port}{Style.RESET_ALL}"
            return f"{Fore.YELLOW}{port}{Style.RESET_ALL}"
        return str(port)

    def _format_protocol(self, protocol):
        if COLOR_ENABLED:
            colors = {
                "TCP": Fore.GREEN, "UDP": Fore.BLUE, "ICMP": Fore.MAGENTA,
                "ARP": Fore.YELLOW, "DNS": Fore.CYAN, "HTTP": Fore.RED,
                "HTTPS": Fore.GREEN
            }
            color = colors.get(protocol, Fore.WHITE)
            return f"{color}{protocol}{Style.RESET_ALL}"
        return protocol

    def _format_payload(self, data, max_len=50):
        if not data:
            return "No payload"
        try:
            text = data.decode('ascii', errors='replace')
            printable = ''.join(c if c.isprintable() else '.' for c in text)
            if len(printable) > max_len:
                return printable[:max_len] + "..."
            return printable
        except:
            hex_str = data[:20].hex().upper()
            if len(data) > 20:
                return f"HEX: {hex_str}..."
            return f"HEX: {hex_str}"

    def _extract_http_info(self, packet):
        http_info = {}
        if Raw in packet:
            try:
                payload = packet[Raw].load.decode('ascii', errors='ignore')
                lines = payload.split('\r\n')
                for line in lines:
                    if line.startswith('GET ') or line.startswith('POST '):
                        http_info['method'] = line.split()[0]
                        http_info['uri'] = line.split()[1]
                        http_info['http_version'] = line.split()[2] if len(line.split()) > 2 else "HTTP/1.1"
                    elif line.startswith('Host:'):
                        http_info['host'] = line.split(': ', 1)[1] if ': ' in line else line.split(':')[1].strip()
                    elif line.startswith('User-Agent:'):
                        http_info['user_agent'] = line.split(': ', 1)[1] if ': ' in line else line.split(':')[1].strip()
                    if len(http_info) >= 4:
                        break
            except:
                pass
        return http_info if http_info else None

    def _analyze_dns(self, packet):
        dns_info = {}
        if DNS in packet and packet[DNS].qr == 0:
            if packet[DNS].qd:
                qname = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                qtype = packet[DNS].qd.qtype
                dns_info['query'] = qname
                dns_info['type'] = self._get_dns_type(qtype)
        elif DNS in packet and packet[DNS].qr == 1:
            dns_info['response'] = "DNS Response"
            if packet[DNS].an:
                for answer in packet[DNS].an:
                    if hasattr(answer, 'rdata'):
                        dns_info['answer'] = answer.rdata
                        break
        return dns_info if dns_info else None

    def _get_dns_type(self, qtype):
        dns_types = {
            1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
            15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"
        }
        return dns_types.get(qtype, f"TYPE-{qtype}")

    def _check_suspicious_activity(self, src_ip, dst_ip, src_port, dst_port):
        alerts = []
        if src_port in self.suspicious_ports:
            alerts.append(f"Suspicious source port: {src_port} ({self._get_service_name(src_port)})")
        if dst_port in self.suspicious_ports:
            alerts.append(f"Suspicious destination port: {dst_port} ({self._get_service_name(dst_port)})")
        connection_key = f"{src_ip}->{dst_ip}"
        if connection_key in self.ip_connections:
            if self.ip_connections[connection_key] > 20:
                alerts.append(f"Potential port scanning detected: {self.ip_connections[connection_key]} connections")
        return alerts

    def packet_callback(self, packet):
        self.packet_count += 1
        if self.filter_string and not self._apply_filter(packet):
            return
        packet_info = self._analyze_packet(packet)
        if packet_info:
            self.captured_packets.append(packet_info)
            if len(self.captured_packets) > self.max_packets_stored:
                self.captured_packets.pop(0)
            self.protocol_stats[packet_info['protocol']] += 1
            if packet_info['src_ip'] and packet_info['dst_ip']:
                key = f"{packet_info['src_ip']}->{packet_info['dst_ip']}"
                self.ip_connections[key] += 1
            self._display_packet(packet_info)

    def _apply_filter(self, packet):
        if not self.filter_string:
            return True
        filter_lower = self.filter_string.lower()
        if IP in packet:
            if filter_lower in packet[IP].src.lower() or filter_lower in packet[IP].dst.lower():
                return True
        if TCP in packet or UDP in packet:
            sport = getattr(packet, 'sport', None) or getattr(packet, 'sport', 0)
            dport = getattr(packet, 'dport', None) or getattr(packet, 'dport', 0)
            if str(sport) == filter_lower or str(dport) == filter_lower:
                return True
        return False

    def _analyze_packet(self, packet):
        info = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': None, 'dst_ip': None,
            'src_port': None, 'dst_port': None,
            'protocol': 'Unknown', 'size': len(packet),
            'payload': None, 'flags': None, 'ttl': None,
            'http': None, 'dns': None, 'alerts': [],
            'service': None, 'mac_src': None, 'mac_dst': None
        }
        
        if Ether in packet:
            info['mac_src'] = packet[Ether].src
            info['mac_dst'] = packet[Ether].dst
        
        if IP in packet:
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['ttl'] = packet[IP].ttl
            proto = packet[IP].proto
            info['protocol'] = self._get_protocol_name(proto)
            
            if TCP in packet:
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
                info['flags'] = packet[TCP].flags
                info['service'] = self._get_service_name(info['dst_port'])
                if Raw in packet:
                    info['payload'] = bytes(packet[Raw].load)
                http_info = self._extract_http_info(packet)
                if http_info:
                    info['http'] = http_info
                    info['protocol'] = 'HTTP'
            
            elif UDP in packet:
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
                info['service'] = self._get_service_name(info['dst_port'])
                if Raw in packet:
                    info['payload'] = bytes(packet[Raw].load)
                dns_info = self._analyze_dns(packet)
                if dns_info:
                    info['dns'] = dns_info
                    info['protocol'] = 'DNS'
            
            elif ICMP in packet:
                info['type'] = packet[ICMP].type
                info['code'] = packet[ICMP].code
                if Raw in packet:
                    info['payload'] = bytes(packet[Raw].load)
        
        elif ARP in packet:
            info['protocol'] = 'ARP'
            info['src_ip'] = packet[ARP].psrc
            info['dst_ip'] = packet[ARP].pdst
            info['mac_src'] = packet[ARP].hwsrc
            info['mac_dst'] = packet[ARP].hwdst
            info['operation'] = "Request" if packet[ARP].op == 1 else "Reply"
        
        elif IPv6 in packet:
            info['src_ip'] = packet[IPv6].src
            info['dst_ip'] = packet[IPv6].dst
            info['protocol'] = 'IPv6'
            if TCP in packet:
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
                info['protocol'] = 'TCPv6'
                if Raw in packet:
                    info['payload'] = bytes(packet[Raw].load)
        
        if info['src_ip'] and info['dst_ip']:
            alerts = self._check_suspicious_activity(
                info['src_ip'], info['dst_ip'],
                info['src_port'] or 0, info['dst_port'] or 0
            )
            info['alerts'] = alerts
        
        return info

    def _display_packet(self, info):
        if not self.verbose:
            return
        
        print("-" * 80)
        print(f"{Style.BRIGHT}Packet #{self.packet_count}{Style.RESET_ALL} - {info['timestamp']}")
        print(f"  {Style.BRIGHT}Protocol:{Style.RESET_ALL} {self._format_protocol(info['protocol'])}")
        print(f"  {Style.BRIGHT}Size:{Style.RESET_ALL} {info['size']} bytes")
        
        if info['mac_src'] and info['mac_dst']:
            print(f"  MAC: {info['mac_src']} -> {info['mac_dst']}")
        
        if info['src_ip'] and info['dst_ip']:
            src_display = self._format_ip(info['src_ip'])
            dst_display = self._format_ip(info['dst_ip'])
            
            if info['src_port'] and info['dst_port']:
                print(f"  {Style.BRIGHT}Source:{Style.RESET_ALL} {src_display}:{self._format_port(info['src_port'])}")
                print(f"  {Style.BRIGHT}Destination:{Style.RESET_ALL} {dst_display}:{self._format_port(info['dst_port'])}")
                if info['service']:
                    print(f"  {Style.BRIGHT}Service:{Style.RESET_ALL} {info['service']}")
            else:
                print(f"  {Style.BRIGHT}Source:{Style.RESET_ALL} {src_display}")
                print(f"  {Style.BRIGHT}Destination:{Style.RESET_ALL} {dst_display}")
        
        if info.get('ttl'):
            print(f"  {Style.BRIGHT}TTL:{Style.RESET_ALL} {info['ttl']}")
        
        if info.get('flags'):
            print(f"  {Style.BRIGHT}Flags:{Style.RESET_ALL} {info['flags']}")
        
        if info.get('operation'):
            print(f"  {Style.BRIGHT}Operation:{Style.RESET_ALL} {info['operation']}")
        
        if info.get('http'):
            http = info['http']
            print(f"  {Style.BRIGHT}HTTP:{Style.RESET_ALL}")
            if 'method' in http:
                print(f"    Method: {http['method']}")
            if 'uri' in http:
                print(f"    URI: {http['uri']}")
            if 'host' in http:
                print(f"    Host: {http['host']}")
            if 'user_agent' in http:
                print(f"    User-Agent: {http['user_agent']}")
        
        if info.get('dns'):
            dns = info['dns']
            print(f"  {Style.BRIGHT}DNS:{Style.RESET_ALL}")
            if 'query' in dns:
                print(f"    Query: {dns['query']} ({dns.get('type', 'Unknown')})")
            if 'answer' in dns:
                print(f"    Answer: {dns['answer']}")
        
        if info.get('payload'):
            payload_str = self._format_payload(info['payload'], 80)
            print(f"  {Style.BRIGHT}Payload:{Style.RESET_ALL} {payload_str}")
        
        if info.get('alerts'):
            for alert in info['alerts']:
                if COLOR_ENABLED:
                    print(f"  {Fore.RED}⚠ ALERT: {alert}{Style.RESET_ALL}")
                else:
                    print(f"  ⚠ ALERT: {alert}")
        
        print("-" * 80)

    def start_sniffing(self, count=None, timeout=None, promiscuous=True):
        print(f"\n{Style.BRIGHT}Comillas Negras - Network Packet Analyzer{Style.RESET_ALL}")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Interface: {self.interface if self.interface else 'Default'}")
        print(f"Promiscuous mode: {promiscuous}")
        print(f"Press Ctrl+C to stop capture\n")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                count=count,
                timeout=timeout,
                store=False,
                promisc=promiscuous
            )
        except KeyboardInterrupt:
            print(f"\n\n{Style.BRIGHT}Capture interrupted by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}Error during capture: {e}{Style.RESET_ALL}")
        
        self.print_statistics()

    def print_statistics(self):
        duration = datetime.now() - self.start_time
        print(f"\n{Style.BRIGHT}=== Capture Statistics ==={Style.RESET_ALL}")
        print(f"  Total packets captured: {self.packet_count}")
        print(f"  Duration: {duration.total_seconds():.2f} seconds")
        print(f"  Packets per second: {self.packet_count / max(1, duration.total_seconds()):.2f}")
        
        print(f"\n  {Style.BRIGHT}Protocol Distribution:{Style.RESET_ALL}")
        for protocol, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / max(1, self.packet_count)) * 100
            bar = "█" * int(percentage / 2)
            print(f"    {self._format_protocol(protocol)}: {count} ({percentage:.1f}%) {bar}")
        
        print(f"\n  {Style.BRIGHT}Top Connections:{Style.RESET_ALL}")
        for conn, count in sorted(self.ip_connections.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"    {conn}: {count} packets")

    def export_packets(self, filename=None):
        if not filename:
            filename = f"packet_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        export_data = {
            'capture_info': {
                'start_time': self.start_time.isoformat(),
                'end_time': datetime.now().isoformat(),
                'total_packets': self.packet_count
            },
            'packets': self.captured_packets,
            'statistics': {
                'protocols': dict(self.protocol_stats),
                'connections': dict(self.ip_connections)
            }
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            print(f"\nPackets exported to: {filename}")
        except Exception as e:
            print(f"Error exporting packets: {e}")

    def set_filter(self, filter_string):
        self.filter_string = filter_string
        print(f"Filter set to: {filter_string}")

class InteractiveMode:
    def __init__(self):
        self.analyzer = PacketAnalyzer(verbose=True)
        self.running = False
    
    def run(self):
        print(f"\n{Style.BRIGHT}{'='*60}{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}Comillas Negras - Interactive Packet Analyzer{Style.RESET_ALL}")
        print(f"{'='*60}")
        print("\nCommands:")
        print("  start [count] - Start capturing packets (optional: number of packets)")
        print("  stop          - Stop capturing")
        print("  filter [expr] - Set a filter (IP, port, etc.)")
        print("  stats         - Display statistics")
        print("  export        - Export captured packets to JSON")
        print("  clear         - Clear captured packets")
        print("  help          - Show this help")
        print("  quit/exit     - Exit the program")
        print("=" * 60)
        
        while True:
            try:
                command = input(f"\n{Fore.GREEN}sniffer>{Style.RESET_ALL} ").strip().lower()
                
                if not command:
                    continue
                
                parts = command.split()
                cmd = parts[0]
                
                if cmd in ['quit', 'exit', 'q']:
                    print("Exiting...")
                    break
                
                elif cmd == 'start':
                    count = int(parts[1]) if len(parts) > 1 else None
                    print(f"Starting capture... (Press Ctrl+C to stop)")
                    self.analyzer.start_sniffing(count=count)
                
                elif cmd == 'stop':
                    print("Stopping capture...")
                    self.running = False
                
                elif cmd == 'filter':
                    if len(parts) > 1:
                        filter_str = ' '.join(parts[1:])
                        self.analyzer.set_filter(filter_str)
                    else:
                        print("Current filter:", self.analyzer.filter_string or "None")
                
                elif cmd == 'stats':
                    self.analyzer.print_statistics()
                
                elif cmd == 'export':
                    self.analyzer.export_packets()
                
                elif cmd == 'clear':
                    self.analyzer.captured_packets.clear()
                    self.analyzer.protocol_stats.clear()
                    self.analyzer.ip_connections.clear()
                    self.analyzer.packet_count = 0
                    print("Cleared all captured packets")
                
                elif cmd == 'help':
                    print("\nCommands:")
                    print("  start [count] - Start capturing packets")
                    print("  stop          - Stop capturing")
                    print("  filter [expr] - Set a filter")
                    print("  stats         - Display statistics")
                    print("  export        - Export captured packets")
                    print("  clear         - Clear captured packets")
                    print("  quit/exit     - Exit the program")
                
                else:
                    print(f"Unknown command: {cmd}. Type 'help' for available commands.")
            
            except KeyboardInterrupt:
                print("\nInterrupted")
                continue
            except Exception as e:
                print(f"Error: {e}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Comillas Negras - Network Packet Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python packet_analyzer.py                  # Start interactive mode
  python packet_analyzer.py -i eth0          # Capture on interface eth0
  python packet_analyzer.py -c 100           # Capture 100 packets
  python packet_analyzer.py -f "192.168.1.1" # Filter packets from IP
  python packet_analyzer.py --export         # Export to JSON after capture

DISCLAIMER: This tool is for educational purposes only.
Unauthorized use may violate laws and regulations.
        """
    )
    
    parser.add_argument('-i', '--interface', help='Network interface to capture from')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    parser.add_argument('-t', '--timeout', type=int, help='Capture timeout in seconds')
    parser.add_argument('-f', '--filter', help='Filter packets (IP, port, etc.)')
    parser.add_argument('-v', '--verbose', action='store_true', default=True, help='Verbose output')
    parser.add_argument('--quiet', action='store_true', help='Quiet mode (minimal output)')
    parser.add_argument('--export', help='Export captured packets to specified file')
    parser.add_argument('--interactive', action='store_true', help='Start in interactive mode')
    parser.add_argument('--no-promisc', action='store_false', dest='promiscuous', help='Disable promiscuous mode')
    
    args = parser.parse_args()
    
    import os
    if os.name != 'nt':
        if os.geteuid() != 0:
            print(f"{Fore.RED}Warning: Packet sniffing typically requires root privileges.{Style.RESET_ALL}")
            print("Try running with: sudo python packet_analyzer.py\n")
    
    if args.interactive or (not any([args.interface, args.count, args.timeout])):
        interactive = InteractiveMode()
        interactive.run()
        return
    
    analyzer = PacketAnalyzer(interface=args.interface, verbose=not args.quiet)
    
    if args.filter:
        analyzer.set_filter(args.filter)
    
    if args.export:
        analyzer.start_sniffing(count=args.count, timeout=args.timeout, promiscuous=args.promiscuous)
        analyzer.export_packets(args.export)
    else:
        analyzer.start_sniffing(count=args.count, timeout=args.timeout, promiscuous=args.promiscuous)

if __name__ == "__main__":
    main()
