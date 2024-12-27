import os
import csv
import datetime
import nmap

class NmapScanner:
    def __init__(self):
        self.__scanner = nmap.PortScanner()

    def __run_scan(self, target: str, arguments: str) -> list[dict]:
        self.__scanner.scan(hosts=target, arguments=arguments)
        results = []

        for host in self.__scanner.all_hosts():
            for proto in self.__scanner[host].all_protocols():
                for port in self.__scanner[host][proto]:
                    service_info = self.__scanner[host][proto][port]
                    results.append({
                        'IP': host,
                        'Protocol': proto,
                        'Port': port,
                        'State': service_info['state'],
                        'Name': service_info.get('name', ''),
                        'Product': service_info.get('product', ''),
                        'Version': service_info.get('version', '')
                    })
        
        return results
    
    def __save_results_to_csv(self, results: list[dict], filename: str) -> None:
        if results:
            dirs = os.path.dirname(filename)
            if dirs:
                os.makedirs(dirs, exist_ok=True)

            keys = results[0].keys()
            with open(filename, 'w', newline='') as output_file:
                dict_writer = csv.DictWriter(output_file, fieldnames=keys)
                dict_writer.writeheader()
                dict_writer.writerows(results)
        else:
            print(f"No results to save in {filename}.")
    
    def scan(self, target: str, arguments: str, results_dir: str) -> list[dict]:
        scan_name = f"scan_{ datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S') }"
        save_dir = os.path.join(results_dir, scan_name)
        initial_results_file = os.path.join(save_dir, "initial_scan_results.csv")
        
        print(f"Running scan with nmap with arguments: { arguments }...")
        
        # -A: Aggressive scan, -T3: Normal timing, -v: Verbose output
        results = self.__run_scan(target, "-A -T3 -v")
        self.__save_results_to_csv(results, initial_results_file)

        return results





    
