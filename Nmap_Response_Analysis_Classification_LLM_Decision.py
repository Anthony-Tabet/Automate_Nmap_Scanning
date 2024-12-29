import nmap
import csv
import pandas as pd
from dotenv import load_dotenv
import os
import google.generativeai as genai  # For Gemini API integration
from openai import OpenAI
from ollama import chat, ChatResponse

# Load environment variables
load_dotenv()

# Initialize OpenAI and Google API clients
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

# Function to call the Gemini API (assumed to be a REST API)
def classify_with_gemini(results):
    try:
        google_api_key = os.environ.get("GOOGLE_API_KEY")
        if not google_api_key:
            raise ValueError("Google API key is missing.")

        # Initialize the Gemini 1.5 model using Google's GenAI SDK
        model = genai.GenerativeModel('models/gemini-1.5-pro')  # Ensure the correct model name is used

        # Prepare the context and question (scan results)
        prompt = (
            f"""
            Classify the following scan results as Completed, Incomplete, or False Positive Rich. 
            Also, recommend the next scan type (e.g., -sS, -T2, etc.) based on your analysis:
            \n\n{results}
            """
        )

        # Safety settings (optional but good practice to ensure no harmful outputs)
        safety_settings = [
            {
                "category": "HARM_CATEGORY_DANGEROUS", 
                "threshold": "BLOCK_NONE"
            },
            {
                "category": "HARM_CATEGORY_HARASSMENT", 
                "threshold": "BLOCK_NONE"
            },
            {
                "category": "HARM_CATEGORY_HATE_SPEECH",
                "threshold": "BLOCK_NONE"
            },
            {
                "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", 
                "threshold": "BLOCK_NONE"
            },
            {
                "category": "HARM_CATEGORY_DANGEROUS_CONTENT", 
                "threshold": "BLOCK_NONE"
            },
        ]

        # Call the Gemini model for classification
        response = model.generate_content([prompt], safety_settings=safety_settings)
        classification, next_scan = (
            response.text.strip().split('\n')[0], 
            response.text.strip().split('\n')[1]
        )
        print(f"Gemini classification: {classification}, Next scan suggestion: {next_scan}")
        return classification, next_scan
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        return "Error with Gemini", ""

# Function to classify using Ollama (Local Model Inference)
def classify_with_ollama(results):
    try:
        prompt = (
            f"""
            Classify the following scan results as Completed, Incomplete, or False Positive Rich.
            Also, recommend the next scan type (e.g., -sS, -T2, etc.) 
            based on your analysis:\n\n{results}
            """
        )

        # Use Ollama's local model for classification (llama2 or another model you have available)
        response: ChatResponse = chat(
            model="gemma2",
            messages=[{"role": "user", "content": prompt}]
        )

        classification, next_scan = (
            response.message.content.strip().split('\n')[0], 
            response.message.content.strip().split('\n')[1]
        )
        print(f"Ollama with Gemma 2 classification: {classification}, Next scan suggestion: {next_scan}")
        return classification, next_scan
    except Exception as e:
        print(f"Error calling Ollama with Gemma 2 locally: {e}")
        return "Error with Ollama", ""

# Function to classify scan results and decide the next scan type using OpenAI, Gemini, and Ollama
def classify_scan(results):
    classifications = {}

    prompt = (
        f"""
        Classify the following scan results as Completed, Incomplete, or False Positive Rich. 
        Also, recommend the next scan type (e.g., -sS, -T2, etc.) based on your analysis:\n\n{results}
        """
    )

    # Try OpenAI first
    try:
        user_msg_input_class = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {
                    "role": "system", 
                    "content": (
                        """
                        You are a system that classifies scan results as 'Completed', 'Incomplete', 
                        or 'False Positive Rich' and recommends the next nmap scan type.
                        """
                    )
                },
                {
                    "role": "user", 
                    "content": prompt
                },
            ],
            temperature=1,
            top_p=1
        )
        openai_classification, next_scan = user_msg_input_class.choices[0].message.content.strip().split('\n')
        classifications['OpenAI'] = openai_classification
        classifications['Next Scan'] = next_scan
        print(f"OpenAI classification: {openai_classification}, Next scan suggestion: {next_scan}")
    except Exception as e:
        print(f"Error with OpenAI API: {e}")
        classifications['OpenAI'] = "Error with OpenAI"
        classifications['Next Scan'] = ""

    # Fallback to Gemini if OpenAI fails
    try:
        gemini_classification, next_scan = classify_with_gemini(results)
        classifications['Gemini'] = gemini_classification
        classifications['Next Scan'] = next_scan
        print(f"Gemini classification: {gemini_classification}, Next scan suggestion: {next_scan}")
    except Exception as e:
        print(f"Error with Gemini API: {e}")
        classifications['Gemini'] = "Error with Gemini"
        classifications['Next Scan'] = ""

    # Fallback to Ollama if both OpenAI and Gemini fail
    try:
        ollama_classification, next_scan = classify_with_ollama(results)
        classifications['Ollama'] = ollama_classification
        classifications['Next Scan'] = next_scan
        print(f"Ollama classification: {ollama_classification}, Next scan suggestion: {next_scan}")
    except Exception as e:
        print(f"Error with Ollama locally: {e}")
        classifications['Ollama'] = "Error with Ollama"
        classifications['Next Scan'] = ""

    # If no classification can be determined, set to "Incomplete"
    if classifications.get('Next Scan'):
        return classifications['Next Scan']
    else:
        return "Error determining next scan"

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

def scan_with_fallback(target):
    # Step 1: Run initial scan with aggressive options
    print("Running initial aggressive scan...")
    results = run_nmap_scan(target, '-A -T3 -v')
    save_results_to_csv(results, "initial_scan_results.csv")

    # Step 2: Classify the scan results and get next scan recommendation
    scan_results_text = "\n".join([
        f"{result['IP']} {result['Port']} {result['State']}"
        for result in results
    ])
    next_scan = classify_scan(scan_results_text)

    # Step 3: Run the next scan based on LLM recommendation
    print(f"Next scan type suggested by LLM: {next_scan}")
    if next_scan:
        # Run the next scan as suggested by the LLM
        results_next_scan = run_nmap_scan(target, next_scan)
        save_results_to_csv(results_next_scan, "next_scan_results.csv")

    return results

def generate_final_report():
    # Combine results from initial and follow-up scans
    df_initial = pd.read_csv("initial_scan_results.csv")
    try:
        df_next_scan = pd.read_csv("next_scan_results.csv")
        df_combined = pd.concat([df_initial, df_next_scan]).drop_duplicates()
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
