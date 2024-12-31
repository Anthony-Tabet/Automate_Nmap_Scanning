import streamlit as st
import requests
import pandas as pd
import automator_client.constants as const


def post_request(endpoint: str, payload):
    """Send the scan request and handle the response."""
    try:
        response = requests.post(endpoint, json=payload)
        if response.status_code == 200:
            return response.json(), None
        else:
            return None, f"Error: {response.status_code} - {response.text}"
    except requests.RequestException as e:
        return None, f"API request failed: {e}"


def render_scan_results(scan_results, scan_file_path, scan_dir_path):
    """Display scan results in a table."""
    st.success("Nmap scan completed. Results displayed below.")
    # Flatten and display results
    flattened_results = [
        {**entry, "Subdomain": subdomain_entry["target"]}
        for subdomain_entry in scan_results
        for entry in subdomain_entry["results"]
    ]
    df = pd.DataFrame(flattened_results)
    st.dataframe(df)
    st.session_state["scan_file_path"] = scan_file_path
    st.session_state["scan_dir_path"] = scan_dir_path
    st.session_state["scan_results"] = flattened_results


def render_analysis_results(result):
    """Display analysis results from the LLM."""
    if result:
        st.subheader("LLM Analysis Results")
        st.write(f"**Analysis Description:** {result['analysis_description']}")
        st.write(f"**Classification:** {result['result']}")
        if result.get("next_arguments"):
            st.subheader("Suggested Next Arguments")
            st.write(f"`{' '.join(result['next_arguments'])}`")
        else:
            st.write("No suggestions provided.")


def main():
    st.title("Nmap Scan Automator")

    # Step 1: Retrieve Subdomains
    st.header("Retrieve Subdomains")
    domain = st.text_input("Enter the domain to enumerate subdomains:", value="megacorpone.com")

    if st.button("Retrieve Subdomains"):
        response, error = post_request(const.ENUMERATE_SUBDOMAINS_ENDPOINT, payload={"domain": domain})
        if response:
            subdomains = response.get("subdomains", [])
            if subdomains:
                st.success(f"Found {len(subdomains)} subdomains.")
                st.session_state["subdomains"] = subdomains
            else:
                st.warning("No subdomains found.")
        else:
            st.error(f"Error retrieving subdomains: {error}")

    subdomains = st.session_state.get("subdomains", [])
    if subdomains:
        # Step 2: Select Subdomains
        st.header("Step 2: Select Subdomains for Nmap Scan")
        selected_subdomains = st.multiselect("Select subdomains to scan:", subdomains)

        # Step 3: Configure Nmap Scan
        st.header("Step 3: Configure Nmap Scan")
        nmap_args = st.text_input("Enter Nmap arguments (comma-separated):", value="-A,-T3,-v")

        if st.button("Run Nmap Scan"):
            if not selected_subdomains:
                st.warning("Please select at least one subdomain to scan.")
            else:
                payload = {
                    "scanner": {
                        "nmap_args": nmap_args.split(","),
                        "save_dir": "./results",
                        "target": selected_subdomains
                    }
                }
                result, error = post_request(endpoint=const.NMAP_ENDPOINT, payload=payload)
                if error:
                    st.error(f"Error scanning: {error}")
                elif result:
                    render_scan_results(
                        scan_results=result["data"],
                        scan_file_path=result["scan_file_path"],
                        scan_dir_path=result["scan_dir_path"]
                    )

    # Step 4: Analyze Logs with LLM
    scan_file_path = st.session_state.get("scan_file_path", None)
    scan_dir_path = st.session_state.get("scan_dir_path", None)
    if scan_file_path:
        st.header("Step 4: Analyze Nmap Logs")
        interpreter_type = st.selectbox("Choose an interpreter", ["gpt", "gemini", "ollama"])
        model_flavor = st.selectbox("Choose a model flavor", const.MODEL_FLAVORS[interpreter_type])
        runner_mode = st.selectbox("Select Runner Mode", const.RUNNER_MODES)

        if st.button("Analyze Logs"):
            payload = {
                "interpretor": {
                    "interpretor_type": interpreter_type,
                    "model_flavor": model_flavor,
                    "interpret_runner": runner_mode
                },
                "scan_file_path": scan_file_path,
                "scan_dir_path": scan_dir_path
            }
            result, error = post_request(endpoint=const.LLM_INTERPRETATION_ENDPOINT, payload=payload)
            if error:
                st.error(f"Error analyzing logs: {error}")
            elif result:
                render_analysis_results(result["interpreted_results"])


if __name__ == "__main__":
    if "subdomains" not in st.session_state:
        st.session_state["subdomains"] = []
    main()
