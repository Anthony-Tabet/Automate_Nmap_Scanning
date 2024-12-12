import nmap
import time
import sys
import socket
import argparse

def resolve_target(target):
    try:
        # Attempt to resolve the domain to an IP address
        ip_address = socket.gethostbyname(target)
        return ip_address
    except socket.gaierror:
        print(f"Error: Could not resolve domain '{target}'. Skipping.")
        return None

def run_nmap_scan(target, scan_speed):
    # Initialize Nmap scanner
    scanner = nmap.PortScanner()
    
    # Run Nmap scan
    scan_arguments = f'-sS -T{scan_speed}'  # -sS for stealth scan, -T for timing template
    scanner.scan(target, arguments=scan_arguments)
    
    # Collect scan results
    results = []
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                if state == 'open':
                    results.append((host, proto, port))
    return results

def check_incomplete_results(results):
    # Criteria to determine if the results are incomplete or bogus
    if not results:  # If no results, consider it incomplete
        return True
    return False

def scan_with_slowdown(target, rounds=3):
    scan_speed = 4  # Start with a higher scan speed
    complete_results = []
    
    for round in range(rounds):
        print(f"Running round {round + 1} with scan speed T{scan_speed}...")
        
        # Run scan with current speed
        results = run_nmap_scan(target, scan_speed)
        
        if check_incomplete_results(results):
            print("Results appear incomplete. Slowing down scan speed...")
            scan_speed = max(scan_speed - 1, 1)  # Gradually decrease speed down to T1
        else:
            complete_results.extend(results)
        
        # Small delay between scans
        time.sleep(2)

    # Filter unique results to avoid duplicates across rounds
    unique_results = list(set(complete_results))
    return unique_results

def generate_report(results):
    print("\nScan Report")
    print("===========")
    for host, proto, port in results:
        print(f"Host: {host}, Protocol: {proto}, Port: {port} - OPEN")

def main():
    parser = argparse.ArgumentParser(description="NMAP scan with gradual slowdown on incomplete results.")
    parser.add_argument("targets", nargs='+', help="IP addresses or domains to scan")
    args = parser.parse_args()
    
    all_results = []
    for target in args.targets:
        # Resolve domain to IP if necessary
        resolved_target = resolve_target(target)
        if resolved_target:
            print(f"\nScanning target: {resolved_target} (Resolved from: {target})")
            results = scan_with_slowdown(resolved_target)
            all_results.extend(results)
    
    # Generate final report with all unique open ports
    generate_report(list(set(all_results)))

if __name__ == "__main__":
    main()
