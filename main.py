import nmap
import csv
import os
import argparse
import pandas as pd
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

SCAN_STATUS_COMPLETED = "_completed"
SCAN_STATUS_INCOMPLETE = "_incomplete"
SCAN_STATUS_FPR = "_false_positive_rich"

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
    if not results:
        print("Empty results array. Skipping classification.")
        return '{"status": "empty", "explanation": "No data available for classification."}'
    prompt = (
        f"You are a system that classifies scan results as '{SCAN_STATUS_COMPLETED}', '{SCAN_STATUS_INCOMPLETE}', or '{SCAN_STATUS_FPR}' "
        "based on the scan data provided and returns a JSON response with fields 'status' and 'explanation'.\n\n"
        f"{results}"
    )

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {
                "role": "system",
                "content": prompt
            }
        ],
        temperature=1,
        top_p=1
    )

    classification = response.choices[0].message.content.strip()
    return classification

def suggest_arguments_with_llm(results):
    if not results:
        print("Empty results array. Cannot suggest new arguments.")
        return []
    prompt = (
        f"You are an expert in NMAP and network scanning. Based on the following results, "
        "return a JSON response with an array 'suggested_arguments' and a field 'explanation'.\n\n"
        f"{results}"
    )

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": prompt}
        ],
        temperature=1,
        top_p=1
    )

    suggestion = response.choices[0].message.content.strip()
    try:
        suggestion_json = eval(suggestion)  # Convert JSON-like response to dict
        arguments = suggestion_json.get("suggested_arguments", [])
        explanation = suggestion_json.get("explanation", "")
        print(f"Suggested Arguments: {arguments}\nExplanation: {explanation}")
        return arguments
    except Exception as e:
        print(f"Error parsing suggestion response: {e}")
        return []

def scan_with_fallback(target, use_llm):
    print("Running initial aggressive scan...")
    results = run_nmap_scan(target, '-A -T3 -v')
    save_results_to_csv(results, "initial_scan_results.csv")

    classification = classify_scan(results)
    try:
        classification_json = eval(classification)
        status = classification_json.get("status", "").lower()
    except Exception as e:
        print(f"Error parsing classification response: {e}")
        status = ""

    if status == SCAN_STATUS_INCOMPLETE.lower() or status == SCAN_STATUS_FPR.lower():
        if use_llm:
            print("Scan classified as incomplete/false positive rich. Suggesting new arguments using LLM...")
            suggested_arguments = suggest_arguments_with_llm(results)

            if suggested_arguments:
                arguments_str = " ".join(suggested_arguments)
                print(f"Running scan with suggested arguments: {arguments_str}")
                results = run_nmap_scan(target, arguments_str)
            else:
                print("No valid arguments suggested. Falling back to rule-based lighter scan...")
                results = run_nmap_scan(target, '-sS -T2')
        else:
            print("Scan classified as incomplete/false positive rich. Falling back to rule-based lighter scan...")
            results = run_nmap_scan(target, '-sS -T2')

        save_results_to_csv(results, "light_scan_results.csv")

    return results

def generate_final_report():
    df_initial = pd.read_csv("initial_scan_results.csv")
    try:
        df_light = pd.read_csv("light_scan_results.csv")
        df_combined = pd.concat([df_initial, df_light]).drop_duplicates()
    except FileNotFoundError:
        df_combined = df_initial

    df_combined.to_csv("final_scan_report.csv", index=False)
    print("Final report saved as final_scan_report.csv")

def main():
    parser = argparse.ArgumentParser(description="NMAP Scan Automation with LLM Integration")
    parser.add_argument("--targets", help="Target IP addresses or domains (comma-separated)")
    parser.add_argument("--llm-driven", action="store_true", help="Use LLM for argument suggestions instead of rule-based fallback")
    args = parser.parse_args()

    targets = args.targets.split(",")
    for target in targets:
        print(f"Scanning target: {target}")
        results = scan_with_fallback(target, args.llm_driven)
        print(results)

    generate_final_report()

if __name__ == "__main__":
    main()
