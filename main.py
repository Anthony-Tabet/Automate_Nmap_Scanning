import nmap
import csv
import os
import pandas as pd
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY"),
)

def run_nmap_scan(target, scan_arguments):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments=scan_arguments)
    results = []

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port in scanner[host][proto]:
                service_info = scanner[host][proto][port]
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

def save_results_to_csv(results, filename="scan_results.csv"):
    if results:
        keys = results[0].keys()
        with open(filename, 'w', newline='') as output_file:
            dict_writer = csv.DictWriter(output_file, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(results)
    else:
        print(f"No results to save in {filename}.")

def classify_scan(results):
    # Format the scan results as a string for the prompt
    prompt = f"Classify the following scan results as Completed, Incomplete, or False Positive Rich:\n\n{results}"
    
    # Use OpenAI's chat completion to classify the scan results
    user_msg_input_class = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a system that classifies scan results as 'Completed', 'Incomplete', or 'False Positive Rich' based on the scan data provided."},
            {"role": "user", "content": prompt},
        ],
        temperature=1,
        top_p=1
    )

    # Extract the classification result from the response
    classification = user_msg_input_class.choices[0].message.content.strip()
    return classification

def scan_with_fallback(target):
    # Step 1: Run initial aggressive scan
    print("Running initial aggressive scan...")
    results = run_nmap_scan(target, '-A -T3 -v')
    save_results_to_csv(results, "initial_scan_results.csv")

    # Step 2: Classify scan results
    classification = classify_scan(results)

    # Step 3: If scan is classified as incomplete or false positive rich, run a lighter scan
    if classification.lower() in ["incomplete", "false positive rich"]:
        print("Running lighter scan due to incomplete/false positive results...")
        results = run_nmap_scan(target, '-sS -T2')
        save_results_to_csv(results, "light_scan_results.csv")
    
    return results

def generate_final_report():
    # Combine results from initial and any follow-up scans
    df_initial = pd.read_csv("initial_scan_results.csv")
    try:
        df_light = pd.read_csv("light_scan_results.csv")
        df_combined = pd.concat([df_initial, df_light]).drop_duplicates()
    except FileNotFoundError:
        df_combined = df_initial  # No follow-up scan file

    df_combined.to_csv("final_scan_report.csv", index=False)
    print("Final report saved as final_scan_report.csv")

def main():
    target = "www.megacorpone.com"
    results = scan_with_fallback(target)
    generate_final_report()

if __name__ == "__main__":
    main()
