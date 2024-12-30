from .base_interpretor import BaseInterpretor
import os
import io
from ollama import chat
import json

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
        "3. 'next_arguments': An array of recommended arguments for the next scan.\n\n{scan_results}"
    ),
}

class OllamaInterpretor(BaseInterpretor):
    def __init__(
        self,
        name: str,
        model_flavor: str = "gemma2",
        api_key: str = None
    ):
        self.__client = None
        super().__init__(name, model_flavor, api_key)

    def configure(self):
        super().configure()

    def save_results(self, results: dict, save_dir: str) -> None:
        # Save the results to a file
        with io.open(os.path.join(save_dir, f"{self.name}_results.json"), "w") as f:
            f.write(json.dumps(results, indent=4))

    def _interpret(self, scan_results: str, save_dir: str, prompt_key: str) -> dict:
        classifications = {
            "error": None,
            "result": None,
            "analysis_description": None,
            "next_arguments": None,
        }

        if not self.is_configured:
            classifications["error"] = "Interpretor not configured."
        else:
            try:
                prompt = PROMPTS[prompt_key].format(scan_results=scan_results)
                response = chat(
                    model=self.model_flavor,
                    messages=[{"role": "user", "content": prompt}]
                )
                output = response.message.content.strip()

                if prompt_key == "with_suggestions":
                    # Attempt to parse JSON response
                    json_start = output.find('{')  # Find the first '{' character
                    json_end = output.rfind('}')  # Find the last '}' character

                    if json_start != -1 and json_end != -1:
                        sanitized_output = output[json_start:json_end + 1]  # Extract JSON part
                        parsed_output = json.loads(sanitized_output)
                        classifications["result"] = parsed_output.get("classification", None)
                        classifications["analysis_description"] = parsed_output.get("analysis_description", None)
                        classifications["next_arguments"] = parsed_output.get("next_arguments", [])
                    else:
                        classifications["error"] = "No valid JSON found in Ollama response."
                else:
                    classifications["result"] = output

            except json.JSONDecodeError:
                classifications["error"] = "Failed to parse JSON response from Ollama."
            except Exception as e:
                classifications["error"] = f"Error with Ollama API: {e}"

        self.save_results(classifications, save_dir)
        return classifications

    def interpret(self, scan_results: str, save_dir: str) -> dict:
        return self._interpret(scan_results, save_dir, "default")

    def interpret_restricted(self, scan_results: str, save_dir: str) -> dict:
        return self._interpret(scan_results, save_dir, "restricted")

    def interpret_with_suggestions(self, scan_results: str, save_dir: str) -> dict:
        return self._interpret(scan_results, save_dir, "with_suggestions")
