MODEL_FLAVORS = {
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

API_URL = "http://127.0.0.1:5000"
SCAN_ENDPOINT = f"{API_URL}/scan"
NMAP_ENDPOINT = f"{API_URL}/nmap_scan"
LLM_INTERPRETATION_ENDPOINT = f"{API_URL}/llm_interpret"
ENUMERATE_SUBDOMAINS_ENDPOINT = f"{API_URL}/enumerate_subdomains"