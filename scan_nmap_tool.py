# Based on pages 111–120 in Krishna's Python for Cybersecurity

import nmap

def banner():
    print("=" * 50)
    print("         Python Nmap Scanner Tool")
    print("=" * 50)

def get_target():
    target = input("\nEnter target IP address or range: ").strip()
    return target

def menu():
    print("\nChoose a scan type:")
    print("1. SYN ACK Scan")
    print("2. UDP Scan")
    print("3. OS Detection")
    print("4. Full TCP Connect Scan")
    print("5. Top 100 Ports Scan")
    print("6. Vulnerability Script Scan")

def run_scan(scanner, target, scan_type):
    try:
        if scan_type == "1":
            print(f"\n[*] Running SYN ACK Scan on {target}")
            scanner.scan(hosts=target, arguments="-v -sS")
        elif scan_type == "2":
            print(f"\n[*] Running UDP Scan on {target}")
            scanner.scan(hosts=target, arguments="-v -sU")
        elif scan_type == "3":
            print(f"\n[*] Running OS Detection on {target}")
            scanner.scan(hosts=target, arguments="-O")
        elif scan_type == "4":
            print(f"\n[*] Running Full TCP Connect Scan on {target}")
            scanner.scan(hosts=target, arguments="-v -sT")
        elif scan_type == "5":
            print(f"\n[*] Running Top 100 Ports Scan on {target}")
            scanner.scan(hosts=target, arguments="-F")
        elif scan_type == "6":
            print(f"\n[*] Running Vulnerability Script Scan on {target}")
            scanner.scan(hosts=target, arguments="--script vuln")
        else:
            print("[-] Invalid selection.")
            return

        # Display results
        for host in scanner.all_hosts():
            print(f"\n[+] Host: {host} | State: {scanner[host].state()}")
            for proto in scanner[host].all_protocols():
                print(f"    Protocol: {proto}")
                for port in sorted(scanner[host][proto].keys()):
                    state = scanner[host][proto][port]['state']
                    print(f"        Port {port}: {state}")
    except Exception as e:
        print(f"[-] Error running scan: {e}")

def main():
    banner()
    scanner = nmap.PortScanner()

    while True:
        target = get_target()
        menu()
        scan_type = input("Enter your choice (1-6): ").strip()
        run_scan(scanner, target, scan_type)

        again = input("\nWould you like to scan another host? (y/n): ").lower()
        if again != "y":
            print("Exiting scanner.")
            break

if __name__ == "__main__":
    main()
