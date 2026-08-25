import socket
import threading
import queue
import nmap
import ipaddress

def discover_hosts(target):
    hosts_list = []
    nm = nmap.PortScanner() # stores object created from portscanner class and storing it into variable nm
    nm.scan(hosts=target, arguments="-sn") #using scan() function to ping scan given ip address or entire network
    for host in nm.all_hosts():
        hosts_list.append(host)

    return hosts_list # returns list of host found from ping scan

def port_scan(ip_addr, thread_num=1000):
# for each ip address pass through, new port numbers and threads are generated
    print("-------------------------------------------------------------------------")
    print(f"Scanning for ports on {ip_addr}...")


    #generates 6000 port numbers using for loop and adds it to a queue
    q = queue.Queue()
    for port in range(1,6000):
        q.put(port) # append for queues


    def scan_ports():
        while not q.empty():
            port = q.get()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: # creates TCP socket to connect to ports to verify open status
                try:
                    s.connect((ip_addr, port)) # attempts to connect to with ip address and port
                    print(f"[{ip_addr}] : port {port} is open")
                except:
                    pass
            q.task_done() # once the process is done (all ports scanned) the program will carry on to the next sequence


    threads = []

    for x in range(thread_num): # creates 1000 threads to exectute scan_ports function
        t = threading.Thread(target=scan_ports, daemon=True) #function to set task for threads and make them daemon threads
        t.start()
        threads.append(t) # adds the threads to list to be stored

    q.join() # from task_done it will continue from here
    print()
    print(f"Scan for {ip_addr} is complete")

def os_scan(target):

    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments="-O")
    #scans the ip address or network with -O (nmap -O <target>) to retrieve operating system data from the found hosts

    for host in nm.all_hosts(): #for loop to loop through all hosts found
        osmatches = nm[host].get("osmatch",[]) # attempt to get values from the key 'osmatch' from results stored in a dictionary, [] if it doesn't retrieve it returns empty value
        if osmatches:
            opsys = osmatches[0]["name"] # creates variable to store value from the key "name"
            print(f"{host}: {opsys}")
        else:
            print(f"{host} Operating System is unknown")

def find_mac_addr():
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments="-sn") #ping scan

    for host in nm.all_hosts():

        getvendor = nm[host].get("vendor", [])
        #loops through found hosts, and attempts to get vendor info from the dictinoary from key:'vendor'

        if getvendor:
            for mac_addr, vendor in getvendor.items(): # if found it will exctract both MAC address and Vendor values as items
                print(f"""
                Host:{host}
                MAC Address:{mac_addr}
                Vendor:{vendor}""")
        else:
            print(f"""
                Host:{host}
                MAC Address:{mac_addr}
                Vendor: Unknown""")

def validate_target(target): # function to validate the IP address given by the user
    try:
        ipaddress.ip_address(target) # function to validate, target as the parameter
        return True # returns as valid
    except ValueError:
        pass

    try:
        ipaddress.ip_network(target, strict=False) # same but for a subnet
        # strict=False will not crash the program if the user enters anything but .0/24 as the last oct, will just set it to 0 and scan the whole network
        # 192.168.1.55/24 = changes the 55 to 0 and scans the network regardless instead of crashing
        return True
    except ValueError:
        return False

def options():

    global scan_type, target
    while True:

        print("""
1. Host Discovery Scan 
2. Port Scan
3. Operating System Scan
4. MAC Address + Vendor
5. Exit
            """)

        while True:
            scan_type = input("Enter scan type: ")
            if scan_type in ("1", "2", "3", "4", "5"):
                break
            print("Invalid scan type")

        if scan_type == "5":
            break

        print()
        target = input("Enter target host/subnet: ")

        while not validate_target(target):
            print("Invalid IP address entered!")
            target = input("Enter target host/subnet: ")
            if validate_target(target):
                break

        if scan_type == "1":

            x = discover_hosts(target)
            print("----------------------------------------------------------------------------------")
            print(f"Live hosts found: {len(x)}")
            for host in x:
                print(host)
            print("----------------------------------------------------------------------------------")

        elif scan_type == "2":
            print()
            x = discover_hosts(target)
            print("----------------------------------------------------------------------------------")
            for host in x:
                port_scan(host)
            print("----------------------------------------------------------------------------------")

        elif scan_type == "3":
            os_scan(target)

        elif scan_type == "4":
            find_mac_addr()

        else:
            print("Invalid scan type")

options()
