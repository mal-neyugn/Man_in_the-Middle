from scapy.all import ARP, Ether, srp
import os

def scan_network(ip_range):
    # Tạo một gói tin ARP request để gửi tới tất cả các địa chỉ IP trong dải mạng
    arp_request = ARP(pdst=ip_range)
    # Tạo gói tin Ethernet để chứa ARP request
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Kết hợp ARP request và gói tin Ethernet
    packet = ether/arp_request

    # Gửi gói tin và nhận phản hồi
    result = srp(packet, timeout=3, verbose=False)[0]

    # Duyệt qua các phản hồi và in ra địa chỉ IP và MAC
    for sent, received in result:
        # Lấy địa chỉ MAC và IP từ gói tin nhận được
        mac = received.hwsrc
        ip = received.psrc
        print(f"IP: {ip} - MAC: {mac}")

def get_gateway_ip(interface):
    gateway_ip = None
    if os.name == 'posix':
        cmd = f"ip route show | grep {interface} | grep default | awk '{{print $3}}'"
        gateway_ip = os.popen(cmd).read().strip()
    elif os.name == 'nt':
        output = os.popen("route print -4").read()
        lines = output.split('\n')
        for line in lines:
            if interface in line and "0.0.0.0" in line:
                parts = line.split()
                gateway_ip = parts[2]
                break
    return gateway_ip

def get_my_ip(interface):
    my_ip = None
    if os.name == 'posix':
        cmd = f"ifconfig {interface} | grep 'inet ' | awk '{{print $2}}'"
        my_ip = os.popen(cmd).read().strip()
    elif os.name == 'nt':
        output = os.popen("ipconfig").read()
        if interface in output:
            start = output.index(interface)
            my_ip_section = output[start:].split('IPv4 Address')[1].split(': ')[1]
            my_ip = my_ip_section.split('\n')[0].strip()
    return my_ip

def main():
    # Lấy tên giao diện mạng từ người dùng
    interface = input("Write the interface you want to scan (e.g., eth0, Vmnet8, vboxnet0, or Wi-Fi): ")

    # Lấy địa chỉ IP của gateway/router
    router_ip = get_gateway_ip(interface)

    # Lấy địa chỉ IP của máy
    my_ip = get_my_ip(interface)

    if router_ip:
        print("Router IP:", router_ip)
        scan_network(router_ip + '/24')
    elif my_ip:
        print("My IP:", my_ip)
        scan_network(my_ip + '/24')
    else:
        print("Unable to determine the gateway IP or your IP.")

if __name__ == "__main__":
    main()
