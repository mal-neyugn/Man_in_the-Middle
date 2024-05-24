from scapy.all import sniff, Ether, IP, TCP, UDP, conf, Raw, DNS, ARP
import os
import sys
import threading

class NetSniff:
    def __init__(self, interface=None, filter=None):
        self.interface = interface
        self.filter = filter
        self.sniffing = True

    def start_sniffing(self):
        try:
            print(f"Starting sniffing on {self.interface} with filter '{self.filter}'")
            sniff(iface=self.interface, filter=self.filter, prn=self.process_packet, stop_filter=self.stop_sniffing_filter)
        except Exception as e:
            print(f"Error during sniffing: {e}")
            self.sniffing = False

    def process_packet(self, packet):
        try: 
            # Display basic packet information with details
            print("\n[+] Packet captured:")
            if packet.haslayer(Ether):
                eth = packet[Ether]
                print(f"    Ethernet Frame: {eth.src} -> {eth.dst}, Type: {eth.type}")

            if packet.haslayer(IP):
                ip = packet[IP]
                print(f"    IP Packet: {ip.src} -> {ip.dst}, TTL: {ip.ttl}, Protocol: {ip.proto}")

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                print(f"    TCP Segment: {tcp.sport} -> {tcp.dport}, Flags: {tcp.flags}, Seq: {tcp.seq}, Ack: {tcp.ack}")
                if packet.haslayer(Raw):
                    payload = packet[Raw].load.decode(errors='ignore')
                    if tcp.dport == 80 or tcp.sport == 80:
                        print("    HTTP Data:")
                        print(f"    {payload}")

            if packet.haslayer(UDP):
                udp = packet[UDP]
                print(f"    UDP Datagram: {udp.sport} -> {udp.dport}")

            if packet.haslayer(ARP):
                arp = packet[ARP]
                print(f"    ARP Packet: {arp.psrc} -> {arp.pdst}, Operation: {arp.op}")

            if packet.haslayer(DNS):
                dns = packet[DNS]
                print(f"    DNS Packet: ID: {dns.id}, QD: {dns.qdcount}, AN: {dns.ancount}, NS: {dns.nscount}, AR: {dns.arcount}")
        except Exception as e:
            print(f"Error processing packet: {e}")
            
    def stop_sniffing(self):
        self.sniffing = False
        print("Sniffing stopped.")

    def stop_sniffing_filter(self, packet):
        return not self.sniffing

def check_root_privileges():
    if os.name != 'nt' and os.geteuid() != 0:
        print("You need to run this script as root.")
        sys.exit(1)

def listen_for_exit(sniffer):
    while True:
        user_input = input()
        if user_input.strip().lower() == "exit":
            sniffer.stop_sniffing()
            break

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Network Sniffing Module")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on", required=True)
    parser.add_argument("-f", "--filter", help="BPF filter for packet sniffing", required=False)

    args = parser.parse_args()

    check_root_privileges()

    if os.name == 'nt':
        conf.use_pcap = True

    sniffer = NetSniff(interface=args.interface, filter=args.filter)

    exit_listener_thread = threading.Thread(target=listen_for_exit, args=(sniffer,))
    exit_listener_thread.daemon = True
    exit_listener_thread.start()

    try:
        sniffer.start_sniffing()
    except KeyboardInterrupt:
        sniffer.stop_sniffing()

if __name__ == "__main__":
    main()
