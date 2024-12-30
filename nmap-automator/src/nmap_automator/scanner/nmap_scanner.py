import os
import csv
import nmap

class NmapScanner:
    def __init__(self):
        self.__scanner = nmap.PortScanner()

    def __run_scan(self, target: str, arguments: str) -> list[dict]:
        try:
            print(f"Starting Nmap scan on target: {target} with arguments: {arguments}")
            self.__scanner.scan(hosts=target, arguments=arguments)
        except Exception as e:
            print(f"Error running Nmap scan: {e}")
            return []

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
            print(f"Results saved to: {filename}")
        else:
            print(f"No results to save in {filename}.")

    def scan(self, target: str, arguments: str = "-A -T3 -v", save_dir: str = "./results") -> list[dict]:
        """
        Perform an Nmap scan on the specified target using the given arguments.
        
        :param target: Target IP, hostname, or range.
        :param arguments: Nmap arguments (e.g., "-A -T3 -v").
        :param save_dir: Directory to save scan results.
        :return: List of results as dictionaries.
        """
        initial_results_file = os.path.join(save_dir, "initial_scan_results.csv")

        # Run the scan
        results = self.__run_scan(target, arguments)

        # Save the results
        self.__save_results_to_csv(results, initial_results_file)

        return results
