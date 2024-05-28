import subprocess

def main():
    print("""
        Do you want forward or intercept packet ? (select option number)
          Option 1 : Forward packet 
          Option 2 : Intercept packet
    """)
    option = int(input("Your choice: "))
    if(option == 1):
        try:
            bash = subprocess.Popen(['/home/kali/Man-in-the-Middle_G60/Man_in_the-Middle/forwardPacket.sh'], shell=True)
            bash.wait()
            print("Set up Forward Packet success !")
        except Exception as e:
            print(e)
    elif(option == 2):
        try:
            bash = subprocess.Popen(['/home/kali/Man-in-the-Middle_G60/Man_in_the-Middle/interceptPacket.sh'], shell=True)
            bash.wait()
            print("Set up Intercept Packet success !")
        except Exception as e:
            print(e)
    
if __name__ == "__main__":
    main()