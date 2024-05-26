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
        cmd = "ip route show | grep " + interface + " | awk '{print $3}'"
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

def main():
    
    # Lấy Địa chỉ IP của router hoặc dải mạng cần quét
    interface = input("Write the interface you want to scan (e.g., eth0, Vmnet8, vboxnet0, or Wi-Fi): ")

    # Lấy địa chỉ IP của gateway/router
    router_ip = get_gateway_ip(interface)
    #Linux
    if os.name == 'posix':
        myip = os.popen("ifconfig " + interface + " | grep \"inet \" | awk \'{print $2}\'").read().replace("\n", "")
    # Window
    elif os.name == 'nt':
        output = os.popen("ipconfig").read()
        myip = output[output.index(interface):].split("IPv4 Address")[1].split(": ")[1].split("\n")[0]


    if router_ip:
        print("Router IP:", router_ip)
        scan_network(router_ip + '/24')
    else:
        print("Unable to determine the gateway IP.")
        scan_network(myip + '/24')  

if __name__ == "__main__":
    main()