#!/usr/bin/env python3

import netProbe
import arpSpoof
import controlPacket
import os
import sys

def checkRoot():
    if os.geteuid() != 0:
        print("This file must be run as root. !")
        sys.exit(1)


def main():
    checkRoot()
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
              999. Thoát chương trình
              """)
        options = int(input("Lựa chọn option:  "))
        if(options == 1):
            netProbe.main()
        elif(options == 2):
            arpSpoof.main()
        elif(options ==3):
            controlPacket.main()
        elif(options == 999):
            exit()

if __name__ == "__main__":
    main()