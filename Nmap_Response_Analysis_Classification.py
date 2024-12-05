import nmap
import csv
import pandas as pd
from dotenv import load_dotenv
import os
import requests  # For Gemini API integration
import google.generativeai as genai  # For Gemini API integration
import ollama  # For Ollama integration
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
        # Ensure your Google API key is set in environment variables
        google_api_key = os.environ.get("GOOGLE_API_KEY")
        if not google_api_key:
            raise ValueError("Google API key is missing.")

        # Initialize the Gemini 1.5 model using Google's GenAI SDK
        model = genai.GenerativeModel('models/gemini-1.5-pro')  # Ensure the correct model name is used

        # Prepare the context and question (scan results)
        prompt = f"Classify the following scan results as Completed, Incomplete, or False Positive Rich:\n\n{results}"

        # Safety settings (optional but good practice to ensure no harmful outputs)
        safety_settings = [
            {"category": "HARM_CATEGORY_DANGEROUS", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]

        # Call the Gemini model for classification
        response = model.generate_content([prompt], safety_settings=safety_settings)
        classification = response.text.strip()  # Clean any unwanted leading/trailing spaces
        print(f"Gemini classification: {classification}")
        return classification
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        return "Error with Gemini"

# Function to classify using Ollama (Local Model Inference)
def classify_with_ollama(results):
    try:
        # Prepare the context (scan results)
        prompt = f"Classify the following scan results as Completed, Incomplete, or False Positive Rich:\n\n{results}"

        # Use Ollama's local model for classification (llama2 or another model you have available)
        response: ChatResponse = chat(model="llama2", messages=[{"role": "user", "content": prompt}])

        # Print the response to inspect its structure (for debugging purposes)
        print("Ollama response:", response)

        # Correctly extract classification from the response object
        classification = response.message.content.strip()  # Direct access to content
        print(f"Ollama classification: {classification}")
        return classification
    except Exception as e:
        print(f"Error calling Ollama locally: {e}")
        return "Error with Ollama"

# Function to classify scan results using OpenAI, Gemini, and Ollama
def classify_scan(results):
    classifications = {}

    # Format the scan results as a string for the prompt
    prompt = f"Classify the following scan results as Completed, Incomplete, or False Positive Rich:\n\n{results}"

    # Try OpenAI first
    try:
        user_msg_input_class = client.chat.completions.create(
            model="gpt-4",
            messages=[{
                "role": "system", "content": "You are a system that classifies scan results as 'Completed', 'Incomplete', or 'False Positive Rich' based on the scan data provided."},
                {"role": "user", "content": prompt},
            ],
            temperature=1,
            top_p=1
        )
        openai_classification = user_msg_input_class.choices[0].message.content.strip()
        classifications['OpenAI'] = openai_classification
        print(f"OpenAI classification: {openai_classification}")
    except Exception as e:
        print(f"Error with OpenAI API: {e}")
        classifications['OpenAI'] = "Error with OpenAI"

    # Fallback to Gemini if OpenAI fails
    try:
        gemini_classification = classify_with_gemini(results)
        classifications['Gemini'] = gemini_classification
        print(f"Gemini classification: {gemini_classification}")
    except Exception as e:
        print(f"Error with Gemini API: {e}")
        classifications['Gemini'] = "Error with Gemini"

    # Fallback to Ollama if both OpenAI and Gemini fail
    try:
        ollama_classification = classify_with_ollama(results)
        classifications['Ollama'] = ollama_classification
        print(f"Ollama classification: {ollama_classification}")
    except Exception as e:
        print(f"Error with Ollama locally: {e}")
        classifications['Ollama'] = "Error with Ollama"

    # If no classification can be determined, set to "Incomplete"
    if "Incomplete" in [classifications['OpenAI'], classifications['Gemini'], classifications['Ollama']]:
        classifications['Final Classification'] = "Incomplete"
    else:
        classifications['Final Classification'] = "Completed"

    return classifications

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
    # Step 1: Run initial aggressive scan
    print("Running initial aggressive scan...")
    results = run_nmap_scan(target, '-A -T3 -v')
    save_results_to_csv(results, "initial_scan_results.csv")

    # Step 2: Classify scan results with OpenAI, Gemini, and Ollama
    for result in results:
        classifications = classify_scan(result)
        
        # Add the classifications to each result
        result['OpenAI Classification'] = classifications.get('OpenAI', "Error")
        result['Gemini Classification'] = classifications.get('Gemini', "Error")
        result['Ollama Classification'] = classifications.get('Ollama', "Error")
        result['Final Classification'] = classifications.get('Final Classification', "Error")

    # Step 3: Save the results with the classifications
    save_results_to_csv(results, "scan_results_with_classifications.csv")

    # Step 4: If classification is incomplete, run a lighter scan
    if "Incomplete" in [result['Final Classification'] for result in results]:
        print("Running lighter scan due to incomplete results...")
        light_results = run_nmap_scan(target, '-sS -T2')
        save_results_to_csv(light_results, "light_scan_results.csv")
    
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




# import nmap
# import csv
# import pandas as pd
# from dotenv import load_dotenv
# import os
# import requests  # For Gemini API integration
# load_dotenv()

# import google.generativeai as genai
# from openai import OpenAI

# client = OpenAI(
#     api_key=os.environ.get("OPENAI_API_KEY"),
# )
# genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

# # Function to call the Gemini API (assumed to be a REST API)
# def classify_with_gemini(results):
#     # Ensure your Google API key is set in environment variables
#     google_api_key = os.environ.get("GOOGLE_API_KEY")
#     if not google_api_key:
#         raise ValueError("Google API key is missing.")

#     # Initialize the Gemini 1.5 model using Google's GenAI SDK
#     model = genai.GenerativeModel('models/gemini-1.5-pro')  # Ensure the correct model name is used

#     # Prepare the context and question (scan results)
#     prompt = f"Classify the following scan results as Completed, Incomplete, or False Positive Rich:\n\n{results}"
    
#     # Safety settings (optional but good practice to ensure no harmful outputs)
#     safety_settings = [
#         {"category": "HARM_CATEGORY_DANGEROUS", "threshold": "BLOCK_NONE"},
#         {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
#         {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
#         {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
#         {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
#     ]
    
#     # Call the Gemini model for classification
#     try:
#         response = model.generate_content([prompt], safety_settings=safety_settings)
#         # The response should contain the classification in the 'text' field
#         classification = response.text.strip()  # Clean any unwanted leading/trailing spaces
#         print(f"Gemini classification: {classification}")
#         return classification
#     except Exception as e:
#         print(f"Error calling Gemini API: {e}")
#         return "Error with Gemini"

# def run_nmap_scan(target, scan_arguments):
#     scanner = nmap.PortScanner()
#     scanner.scan(hosts=target, arguments=scan_arguments)
#     results = []

#     for host in scanner.all_hosts():
#         for proto in scanner[host].all_protocols():
#             for port in scanner[host][proto]:
#                 service_info = scanner[host][proto][port]
#                 results.append({
#                     'IP': host,
#                     'Protocol': proto,
#                     'Port': port,
#                     'State': service_info['state'],
#                     'Name': service_info.get('name', ''),
#                     'Product': service_info.get('product', ''),
#                     'Version': service_info.get('version', '')
#                 })
#     return results

# def save_results_to_csv(results, filename="scan_results.csv"):
#     if results:
#         keys = results[0].keys()
#         with open(filename, 'w', newline='') as output_file:
#             dict_writer = csv.DictWriter(output_file, fieldnames=keys)
#             dict_writer.writeheader()
#             dict_writer.writerows(results)
#     else:
#         print(f"No results to save in {filename}.")

# def classify_scan(results):
#     # Format the scan results as a string for the prompt
#     prompt = f"Classify the following scan results as Completed, Incomplete, or False Positive Rich:\n\n{results}"

#     # Try OpenAI first
#     try:
#         user_msg_input_class = client.chat.completions.create(
#             model="gpt-4",
#             messages=[
#                 {"role": "system", "content": "You are a system that classifies scan results as 'Completed', 'Incomplete', or 'False Positive Rich' based on the scan data provided."},
#                 {"role": "user", "content": prompt},
#             ],
#             temperature=1,
#             top_p=1
#         )
#         classification = user_msg_input_class.choices[0].message.content.strip()
#         print(f"OpenAI classification: {classification}")
#     except Exception as e:
#         print(f"Error with OpenAI API: {e}")
#         classification = "Error with OpenAI"

#     # Fallback to Gemini if OpenAI fails
#     if classification == "Error with OpenAI":
#         print("Attempting classification with Gemini API...")
#         classification = classify_with_gemini(results)
#         print(f"Gemini classification: {classification}")
    
#     return classification

# def scan_with_fallback(target):
#     # Step 1: Run initial aggressive scan
#     print("Running initial aggressive scan...")
#     results = run_nmap_scan(target, '-A -T3 -v')
#     save_results_to_csv(results, "initial_scan_results.csv")

#     # Step 2: Classify scan results with both OpenAI and Gemini
#     openai_classification = classify_scan(results)  # Classification from OpenAI
#     gemini_classification = classify_with_gemini(results)  # Classification from Gemini

#     # Step 3: Add the classifications to the results
#     for result in results:
#         result['OpenAI Classification'] = openai_classification
#         result['Gemini Classification'] = gemini_classification

#     # Step 4: Save the results with both classifications
#     save_results_to_csv(results, "scan_results_with_classifications.csv")
    
#     return results

# def generate_final_report():
#     # Combine results from initial and any follow-up scans
#     df_initial = pd.read_csv("initial_scan_results.csv")
#     try:
#         df_light = pd.read_csv("light_scan_results.csv")
#         df_combined = pd.concat([df_initial, df_light]).drop_duplicates()
#     except FileNotFoundError:
#         df_combined = df_initial  # No follow-up scan file

#     df_combined.to_csv("final_scan_report.csv", index=False)
#     print("Final report saved as final_scan_report.csv")

# def main():
#     target = "www.megacorpone.com"
#     results = scan_with_fallback(target)
#     generate_final_report()

# if __name__ == "__main__":
#     main()
