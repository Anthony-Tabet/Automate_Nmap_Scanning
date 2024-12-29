import streamlit as st
import requests

def main():
    # Define the model flavors dictionary
    model_flavors = {
        "gpt": ["gpt-4", "gpt-4o", "gpt-4o-mini", "o1", "o1-mini"],
        "gemini": [
            "models/gemini-1.5-pro", "models/gemini-1.5-flash",
            "models/gemini-1.5-flash-8b", "models/gemini-1.0-pro"
        ],
        "ollama": [
            "llama3.3", "llama3.2", "llama3.1", "llama3", 
            "llama2", "gemma2", "gemma",
            "jimscard/whiterabbit-neo", "ALIENTELLIGENCE/cybersecuritythreatanalysis"
        ]
    }

    # Streamlit app
    st.title("Nmap Scan Automator")

    # Step 1: Choose interpretor
    interpretor = st.selectbox("Choose an interpretor", ["gpt", "gemini", "ollama"])

    # Step 2: Choose model flavor
    model_flavor = st.selectbox("Choose a model flavor", model_flavors[interpretor])

    # Step 3: Provide target IP or URL
    target = st.text_input("Enter the IP or URL of the target machine")

    # Step 4: Input nmap arguments
    nmap_args = st.text_input("Enter nmap arguments (comma separated)", "-A,-T3,-v")

    # Step 5: Choose runner
    runner = st.selectbox("Choose a runner", ["normal", "restricted", "suggest"])

    # Step 6: Submit form
    if st.button("Run Scan"):
        # Prepare the JSON payload
        payload = {
            "scanner": {
                "nmap_args": nmap_args.split(","),
                "save_dir": "./results",
                "target": target
            },
            "interpretor": {
                "interpretor_type": interpretor,
                "model_flavor": model_flavor,
                "interpret_runner": runner
            }
        }

        # Send the request to the server
        response = requests.post("http://127.0.0.1:5000/scan", json=payload)

        # Step 7: Display the result
        if response.status_code == 200:
            result = response.json()
            print(result)
            st.json(result)

            if "next_scan" in result:
                next_scan = result["next_scan"].split()
                new_nmap_args = " ".join(next_scan[1:-1])
                new_target = next_scan[-1]
                
                if st.button("Rerun Scan with New Target and Arguments"):
                    payload["scanner"]["nmap_args"] = new_nmap_args.split()
                    payload["scanner"]["target"] = new_target
                    
                    response = requests.post("http://127.0.0.1:5000/scan", json=payload)
                    
                    if response.status_code == 200:
                        result = response.json()
                        st.json(result)
                    else:
                        st.error(f"Error: {response.status_code} - {response.text}")
        else:
            st.error(f"Error: {response.status_code} - {response.text}")    

if __name__ == "__main__":
    main()