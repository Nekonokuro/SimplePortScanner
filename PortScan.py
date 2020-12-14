import nmap
import re

print("--------------------------------(^◔ᴥ◔^)----------------------------------")
print("\n---(^◔ᴥ◔^)--- Hello, this is simple nmap port scanner ---(^◔ᴥ◔^)--- \n")
print("--------------------------------(^◔ᴥ◔^)----------------------------------")
def EndDecor():
    print("--------------------------------(^◔ᴥ◔^)----------------------------------")
    print("\n---(^◔ᴥ◔^)----------------- END OF SCAN ----------------(^◔ᴥ◔^) --- \n")
    print("--------------------------------(^◔ᴥ◔^)----------------------------------")
def PortScan():
    ip_regex = """^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$"""

    target_ip = input("Enter target IP address to scan:\n>> ")

    if re.search(ip_regex, target_ip):

        target_scan = nmap.PortScanner()
        ports  = [21,22,23,25,53,69,80,88,110,135,139,143,389,443,445,993,3389]
        scan_type = (input("""\nChoose a type of scan:
                            1. UDP
                            2. TCP
                            3. Full scan\n>>> """))

        if scan_type == "1":
            target_scan.scan(target_ip)
            print("Target status: ", target_scan[target_ip].state())
            print("Getting list of ports. Please, wait.")
            for port in ports:
                
                udp_scan = target_scan.scan(target_ip, str(port), "-v -sU")
                print(f"Port {port} on {target_ip} is {udp_scan['scan'][target_ip]['udp'][port]['state']}")
            EndDecor()
                            
        elif scan_type == "2":
            target_scan.scan(target_ip)
            print("Target status: ", target_scan[target_ip].state())
            print("Getting list of ports. Please, wait.")
            for port in ports:

                tcp_scan = target_scan.scan(target_ip, str(port), "-v -sS")
                print(f"Port {port} on {target_ip} is {tcp_scan['scan'][target_ip]['tcp'][port]['state']}")
            EndDecor()
        elif scan_type == "3":
            target_scan.scan(target_ip)
            print("Target status: ", target_scan[target_ip].state())
            print("Getting list of ports. Please, wait.")
            for port in ports:
                full_scan = target_scan.scan(target_ip, str(port), "-v -A -O -sS -sV -sC")
                print(f"Port {port} on {target_ip} is {full_scan['scan'][target_ip]['tcp'][port]['state']}")
            EndDecor()
        else:
                print("[!] Error. Please, enter a valid option 1, 2 or 3.")
                PortScan()
    else:
        print("\n[!]Please, enter valid IP address[!]\n")
        PortScan()

PortScan()

