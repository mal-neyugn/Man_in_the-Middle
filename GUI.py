#!/usr/bin/env python3

import netProbe
import arpSpoof
import controlPacket
import netSniff
import os 
import modifyPacket


def check_root_privileges():
    if os.name != 'nt' and os.geteuid() != 0:
        print("You need to run this script as root.\n")
        exit()


def main():

    check_root_privileges()
    
    while(True):

        print("""  
  __  __             ___        _   _          __  __ _    _    _ _     
 |  \/  |__ _ _ _   |_ _|_ _   | |_| |_  ___  |  \/  (_)__| |__| | |___ 
 | |\/| / _` | ' \   | || ' \  |  _| ' \/ -_) | |\/| | / _` / _` | / -_)
 |_|  |_\__,_|_||_| |___|_||_|  \__|_||_\___| |_|  |_|_\__,_\__,_|_\___|                                                                                                                            
              """)
        print("""
            author: Nguyễn Minh Tài, Nguyễn Tùng Lâm, Trần Quang Huy
              
            ----- DASHBOARD -----
              1. Network Probe
              2. ARP Spoof 
              3. Control Packet
              4. Net Sniff
              999. Exit
              """)
        options = int(input("Lựa chọn option:  "))
        if(options == 1):
            netProbe.main()
        elif(options == 2):
            arpSpoof.main()
        elif(options ==3):
            controlPacket.main()
        elif(options == 4):
            netSniff.main()
        elif(options == 5):
            modifyPacket.main()
        elif(options == 999):
            exit()

if __name__ == "__main__":
    main()