PROMPTS = {
    "default": (
        "Classify the following nmap scan results as Completed, Incomplete, or False Positive Rich:\n\n{scan_results}"
    ),
    "restricted": (
        "Classify the following nmap scan results into one of the following categories:\n"
        "'Completed', 'Incomplete', or 'False Positive Rich'.\n"
        "Do not provide any details, only return the category name.\n\n{scan_results}"
    ),
    "with_suggestions": (
        "Classify the following nmap scan results as Completed, Incomplete, or False Positive Rich.\n"
        "Provide a JSON response with the following fields:\n"
        "1. 'classification': The classification result.\n"
        "2. 'analysis_description': A detailed explanation of the classification decision.\n"
        "3. 'next_arguments': An array of recommended nmap arguments for the next nmap scan.\n\n{scan_results}"
    ),
}