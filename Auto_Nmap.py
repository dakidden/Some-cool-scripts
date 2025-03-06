import nmap
import argparse

def scan_network(target, scan_type, output_file):
    nm = nmap.PortScanner()
    print(f"Running Nmap scan on {target} with scan type {scan_type}...")
    try:
        nm.scan(hosts=target, arguments=scan_type)
    except Exception as e:
        print(f"Error running Nmap scan: {e}")
        return
    
    results = nm.all_hosts()
    try:
        with open(output_file, "w") as f:
            for host in results:
                f.write(f"Host: {host} ({nm[host].hostname()})\n")
                f.write(f"State: {nm[host].state()}\n")
                for proto in nm[host].all_protocols():
                    f.write(f"Protocol: {proto}\n")
                    ports = nm[host][proto].keys()
                    for port in ports:
                        f.write(f"Port: {port} | State: {nm[host][proto][port]['state']}\n")
                f.write("\n")
        print(f"Scan completed. Results saved to {output_file}")
    except IOError as e:
        print(f"Error writing to file {output_file}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automate Nmap scans")
    parser.add_argument("target", help="Target IP address or range")
    parser.add_argument("scan_type", help="Nmap scan type (e.g., -sV, -sS, -A)")
    parser.add_argument("output_file", help="File to save scan results")
    
    args = parser.parse_args()
    scan_network(args.target, args.scan_type, args.output_file)
